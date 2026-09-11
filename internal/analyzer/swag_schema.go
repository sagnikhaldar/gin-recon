package analyzer

import (
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/parser"
	"go/types"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/sagnikhaldar/gin-recon/internal/model"
	"golang.org/x/tools/go/packages"
)

// swagSchemaResolver converts only statically available go/types data. It
// never imports a package, executes target code, or turns a missing name into
// an empty object. Package qualifiers are matched by package name; duplicate
// names are reported as ambiguous rather than guessed.
type swagSchemaResolver struct {
	packages   map[string][]*types.Package
	owner      *types.Package
	components map[string]model.SchemaEvidence
	building   map[string]bool
	depth      int
}

func newSwagSchemaResolver(owner *types.Package, pkgs []*packages.Package) *swagSchemaResolver {
	r := &swagSchemaResolver{owner: owner, packages: map[string][]*types.Package{}, components: map[string]model.SchemaEvidence{}, building: map[string]bool{}}
	seen := map[*types.Package]bool{}
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		if p.Types != nil && !seen[p.Types] {
			seen[p.Types] = true
			r.packages[p.Types.Name()] = append(r.packages[p.Types.Name()], p.Types)
		}
	})
	for _, ps := range r.packages {
		sort.Slice(ps, func(i, j int) bool { return ps[i].Path() < ps[j].Path() })
	}
	return r
}

func (r *swagSchemaResolver) resolveInfo(info *model.SwagInfo) {
	for i := range info.Parameters {
		r.resolveSchema(info.Parameters[i].Schema)
	}
	for i := range info.Responses {
		r.resolveSchema(info.Responses[i].Schema)
		for j := range info.Responses[i].Headers {
			r.resolveSchema(info.Responses[i].Headers[j].Schema)
		}
	}
	if len(r.components) > 0 {
		info.Components = r.components
	}
}

func (r *swagSchemaResolver) resolveSchema(s *model.SchemaEvidence) {
	if s == nil {
		return
	}
	if s.Items != nil {
		r.resolveSchema(s.Items)
	}
	if s.AdditionalProperties != nil {
		r.resolveSchema(s.AdditionalProperties)
	}
	if s.Evidence.Status != "unresolved" || s.GoType == "" {
		return
	}
	t, status := r.lookup(s.GoType)
	if t == nil {
		s.Evidence.Status = status
		return
	}
	resolved := r.schemaFor(t)
	attrs, goType := *s, s.GoType
	*s = resolved
	s.GoType = goType
	// Annotation-level constraints refine the resolved type without changing
	// field requiredness or pointer nullability.
	if attrs.Format != "" {
		s.Format = attrs.Format
	}
	if attrs.Default != nil {
		s.Default = attrs.Default
	}
	if attrs.Example != nil {
		s.Example = attrs.Example
	}
	if len(attrs.Enum) > 0 {
		s.Enum = attrs.Enum
	}
	if attrs.Minimum != nil {
		s.Minimum = attrs.Minimum
	}
	if attrs.Maximum != nil {
		s.Maximum = attrs.Maximum
	}
	if attrs.MinLength != nil {
		s.MinLength = attrs.MinLength
	}
	if attrs.MaxLength != nil {
		s.MaxLength = attrs.MaxLength
	}
	if attrs.Pattern != "" {
		s.Pattern = attrs.Pattern
	}
}

func (r *swagSchemaResolver) lookup(raw string) (types.Type, string) {
	expr, err := parser.ParseExpr(strings.TrimSpace(raw))
	if err != nil {
		return nil, "unsupported"
	}
	return r.lookupExpr(expr)
}

func (r *swagSchemaResolver) lookupExpr(expr ast.Expr) (types.Type, string) {
	switch x := expr.(type) {
	case *ast.StarExpr:
		t, status := r.lookupExpr(x.X)
		if t == nil {
			return nil, status
		}
		return types.NewPointer(t), status
	case *ast.ArrayType:
		t, status := r.lookupExpr(x.Elt)
		if t == nil {
			return nil, status
		}
		if x.Len == nil {
			return types.NewSlice(t), status
		}
		return types.NewArray(t, 0), "partial"
	case *ast.MapType:
		key, ks := r.lookupExpr(x.Key)
		value, vs := r.lookupExpr(x.Value)
		if key == nil {
			return nil, ks
		}
		if value == nil {
			return nil, vs
		}
		return types.NewMap(key, value), "resolved"
	case *ast.IndexExpr:
		base, status := r.lookupExpr(x.X)
		if base == nil {
			return nil, status
		}
		arg, as := r.lookupExpr(x.Index)
		if arg == nil {
			return nil, as
		}
		instantiated, err := types.Instantiate(nil, base, []types.Type{arg}, true)
		if err != nil {
			return nil, "unsupported"
		}
		return instantiated, "resolved"
	case *ast.IndexListExpr:
		base, status := r.lookupExpr(x.X)
		if base == nil {
			return nil, status
		}
		args := make([]types.Type, 0, len(x.Indices))
		for _, index := range x.Indices {
			arg, as := r.lookupExpr(index)
			if arg == nil {
				return nil, as
			}
			args = append(args, arg)
		}
		instantiated, err := types.Instantiate(nil, base, args, true)
		if err != nil {
			return nil, "unsupported"
		}
		return instantiated, "resolved"
	case *ast.Ident:
		return r.lookupNamed(r.owner, x.Name)
	case *ast.SelectorExpr:
		pkgID, ok := x.X.(*ast.Ident)
		if !ok {
			return nil, "unsupported"
		}
		candidates := r.packages[pkgID.Name]
		if len(candidates) > 1 {
			return nil, "ambiguous"
		}
		if len(candidates) == 0 {
			return nil, "unresolved"
		}
		return r.lookupNamed(candidates[0], x.Sel.Name)
	default:
		return nil, "unsupported"
	}
}

func (r *swagSchemaResolver) lookupNamed(pkg *types.Package, name string) (types.Type, string) {
	if basic := types.Universe.Lookup(name); basic != nil {
		if tn, ok := basic.(*types.TypeName); ok {
			return tn.Type(), "resolved"
		}
	}
	if pkg == nil {
		return nil, "unresolved"
	}
	obj := pkg.Scope().Lookup(name)
	if obj == nil {
		return nil, "unresolved"
	}
	tn, ok := obj.(*types.TypeName)
	if !ok {
		return nil, "unresolved"
	}
	return tn.Type(), "resolved"
}

func (r *swagSchemaResolver) schemaFor(t types.Type) model.SchemaEvidence {
	if r.depth >= 64 {
		return model.SchemaEvidence{GoType: types.TypeString(t, qualifier), Evidence: model.DocumentationEvidence{Source: "swag", Status: "unsupported", Conflicts: []string{"schema recursion depth limit reached"}}}
	}
	r.depth++
	defer func() { r.depth-- }()
	e := model.DocumentationEvidence{Source: "swag", Status: "resolved"}
	switch x := t.(type) {
	case *types.Pointer:
		s := r.schemaFor(x.Elem())
		s.Nullable = true
		return s
	case *types.Slice, *types.Array:
		var elem types.Type
		if v, ok := x.(*types.Slice); ok {
			elem = v.Elem()
		} else {
			elem = x.(*types.Array).Elem()
		}
		item := r.schemaFor(elem)
		return model.SchemaEvidence{Type: "array", Items: &item, Evidence: e}
	case *types.Map:
		value := r.schemaFor(x.Elem())
		return model.SchemaEvidence{Type: "object", AdditionalProperties: &value, Evidence: e}
	case *types.Basic:
		return basicSchema(x, e)
	case *types.Alias:
		return r.schemaFor(types.Unalias(x))
	case *types.Named:
		return r.namedSchema(x)
	case *types.Interface:
		return model.SchemaEvidence{Type: "object", GoType: types.TypeString(t, qualifier), Evidence: model.DocumentationEvidence{Source: "swag", Status: "partial"}}
	default:
		return model.SchemaEvidence{GoType: types.TypeString(t, qualifier), Evidence: model.DocumentationEvidence{Source: "swag", Status: "unsupported"}}
	}
}

func basicSchema(b *types.Basic, e model.DocumentationEvidence) model.SchemaEvidence {
	s := model.SchemaEvidence{Evidence: e}
	switch {
	case b.Info()&types.IsBoolean != 0:
		s.Type = "boolean"
	case b.Info()&types.IsInteger != 0:
		s.Type = "integer"
		if b.Kind() == types.Int64 || b.Kind() == types.Uint64 {
			s.Format = "int64"
		} else {
			s.Format = "int32"
		}
	case b.Info()&types.IsFloat != 0:
		s.Type = "number"
		if b.Kind() == types.Float32 {
			s.Format = "float"
		} else {
			s.Format = "double"
		}
	case b.Info()&types.IsString != 0:
		s.Type = "string"
	default:
		s.Type = "object"
		s.Evidence.Status = "partial"
	}
	return s
}

func (r *swagSchemaResolver) namedSchema(n *types.Named) model.SchemaEvidence {
	identity := types.TypeString(n, qualifier)
	id := componentID(n.Obj().Name(), identity)
	if _, ok := r.components[id]; ok || r.building[id] {
		return model.SchemaEvidence{Ref: id, GoType: identity, Evidence: model.DocumentationEvidence{Source: "swag", Status: "resolved"}}
	}
	r.building[id] = true
	base := r.schemaFor(n.Underlying())
	base.GoType = identity
	if st, ok := n.Underlying().(*types.Struct); ok {
		base = r.structSchema(st)
		base.GoType = identity
	}
	if hasSerializationMethod(n, "MarshalJSON") || hasSerializationMethod(n, "MarshalText") {
		base.CustomSerialization = true
		base.Evidence.Status = "partial"
	}
	r.components[id] = base
	delete(r.building, id)
	return model.SchemaEvidence{Ref: id, GoType: identity, Evidence: model.DocumentationEvidence{Source: "swag", Status: base.Evidence.Status}}
}

func (r *swagSchemaResolver) structSchema(st *types.Struct) model.SchemaEvidence {
	s := model.SchemaEvidence{Type: "object", Properties: map[string]model.SchemaEvidence{}, Evidence: model.DocumentationEvidence{Source: "swag", Status: "resolved"}}
	for i := 0; i < st.NumFields(); i++ {
		field, tag := st.Field(i), st.Tag(i)
		if reflect.StructTag(tag).Get("swaggerignore") == "true" {
			continue
		}
		name, omit, skip := jsonField(field.Name(), tag)
		if skip || !field.Exported() {
			continue
		}
		fs := r.schemaFor(field.Type())
		if override := reflect.StructTag(tag).Get("swaggertype"); override != "" {
			fs = swaggerTypeOverride(override)
			fs.GoType = types.TypeString(field.Type(), qualifier)
		}
		fs.OmitEmpty = omit
		applyStructSchemaTags(&fs, reflect.StructTag(tag))
		if field.Anonymous() && name == field.Name() { // no explicit JSON name: flatten statically known embedded objects
			component := fs
			if fs.Ref != "" {
				component = r.components[fs.Ref]
			}
			if component.Type == "object" {
				for k, v := range component.Properties {
					if _, exists := s.Properties[k]; !exists {
						s.Properties[k] = v
					}
				}
				s.Required = append(s.Required, component.Required...)
				continue
			}
		}
		s.Properties[name] = fs
		if tagHasRequired(reflect.StructTag(tag).Get("binding")) || tagHasRequired(reflect.StructTag(tag).Get("validate")) {
			s.Required = append(s.Required, name)
		}
	}
	sort.Strings(s.Required)
	return s
}

func jsonField(fallback, tag string) (string, bool, bool) {
	value := reflectStructTag(tag, "json")
	if value == "-" {
		return "", false, true
	}
	if value == "" {
		return fallback, false, false
	}
	parts := strings.Split(value, ",")
	name := parts[0]
	if name == "" {
		name = fallback
	}
	omit := false
	for _, p := range parts[1:] {
		if p == "omitempty" {
			omit = true
		}
	}
	return name, omit, false
}

// reflectStructTag avoids importing reflect solely to parse the already
// decoded go/types tag and tolerates malformed tags conservatively.
func reflectStructTag(tag, key string) string { return reflect.StructTag(tag).Get(key) }

func swaggerTypeOverride(raw string) model.SchemaEvidence {
	parts := strings.Split(raw, ",")
	kind := strings.TrimSpace(parts[0])
	value := "string"
	if len(parts) > 1 {
		value = strings.TrimSpace(parts[1])
	}
	base := model.SchemaEvidence{Evidence: model.DocumentationEvidence{Source: "swag", Status: "resolved"}}
	switch value {
	case "integer":
		base.Type = "integer"
	case "number":
		base.Type = "number"
	case "boolean":
		base.Type = "boolean"
	case "object":
		base.Type = "object"
	default:
		base.Type = "string"
	}
	if kind == "array" {
		item := base
		return model.SchemaEvidence{Type: "array", Items: &item, Evidence: base.Evidence}
	}
	return base
}
func tagHasRequired(raw string) bool {
	for _, part := range strings.Split(raw, ",") {
		if strings.TrimSpace(part) == "required" {
			return true
		}
	}
	return false
}
func applyStructSchemaTags(schema *model.SchemaEvidence, tag reflect.StructTag) {
	if raw := tag.Get("example"); raw != "" {
		schema.Example = parseTagLiteral(raw)
	}
	if raw := tag.Get("default"); raw != "" {
		schema.Default = parseTagLiteral(raw)
	}
	if raw := tag.Get("enums"); raw != "" {
		for _, v := range strings.Split(raw, ",") {
			schema.Enum = append(schema.Enum, parseTagLiteral(strings.TrimSpace(v)))
		}
	}
}
func parseTagLiteral(raw string) any {
	if b, err := strconv.ParseBool(raw); err == nil {
		return b
	}
	if n, err := strconv.ParseFloat(raw, 64); err == nil {
		return n
	}
	return raw
}

func hasSerializationMethod(n *types.Named, name string) bool {
	for i := 0; i < n.NumMethods(); i++ {
		if n.Method(i).Name() == name {
			return true
		}
	}
	p := types.NewPointer(n)
	ms := types.NewMethodSet(p)
	for i := 0; i < ms.Len(); i++ {
		if ms.At(i).Obj().Name() == name {
			return true
		}
	}
	return false
}
func qualifier(p *types.Package) string {
	if p == nil {
		return ""
	}
	return p.Path()
}
func componentID(name, identity string) string {
	sum := sha256.Sum256([]byte(identity))
	var b strings.Builder
	for _, r := range name {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		b.WriteString("Schema")
	}
	return fmt.Sprintf("%s_%x", b.String(), sum[:5])
}
