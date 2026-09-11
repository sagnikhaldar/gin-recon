package gin

// This file implements the bounded swaggo/swag dialect documented in ADR
// 0012. Parsing is offline and non-executing: annotations are documentary
// evidence, while route and authentication identity remain analyzer-owned.

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"strconv"
	"strings"
	"unicode"

	"github.com/sagnikhaldar/gin-recon/internal/model"
)

var swagMIMETypes = map[string]string{
	"json": "application/json", "xml": "application/xml", "plain": "text/plain",
	"html": "text/html", "mpfd": "multipart/form-data", "x-www-form-urlencoded": "application/x-www-form-urlencoded",
	"json-api": "application/vnd.api+json", "octet-stream": "application/octet-stream", "png": "image/png", "jpeg": "image/jpeg",
}

func declaredEvidence() model.DocumentationEvidence {
	return model.DocumentationEvidence{Source: "swag", Status: "declared"}
}

// ParseSwagAnnotations recognizes the versioned compatibility matrix in ADR
// 0012. Unknown directives remain unsupported and are ignored; malformed
// recognized directives are retained as Issues.
func ParseSwagAnnotations(doc *ast.CommentGroup) *model.SwagInfo {
	if doc == nil {
		return nil
	}
	var info model.SwagInfo
	var desc []string
	found := false
	responseByStatus := map[string]int{}
	for _, line := range swagCommentLines(doc) {
		if !strings.HasPrefix(line, "@") {
			continue
		}
		directive, rest := splitDirective(line)
		lower := strings.ToLower(directive)
		switch lower {
		case "@summary":
			info.Summary = strings.TrimSpace(rest)
			found = true
		case "@description":
			if v := strings.TrimSpace(rest); v != "" {
				desc = append(desc, v)
			}
			found = true
		case "@tags":
			info.Tags = appendCSVUnique(info.Tags, rest)
			found = true
		case "@id":
			info.ID = strings.TrimSpace(rest)
			found = true
		case "@accept":
			info.Accept = appendMIMEs(info.Accept, rest)
			found = true
		case "@produce":
			info.Produce = appendMIMEs(info.Produce, rest)
			found = true
		case "@router", "@deprecatedrouter":
			path, method, ok := parseRouterDirective(rest)
			if !ok {
				info.Issues = append(info.Issues, model.SwagIssue{Directive: directive, Message: "expected @Router <path> [<method>]"})
				found = true
				continue
			}
			info.Routers = append(info.Routers, model.SwagRouter{Path: path, Method: method, Deprecated: lower == "@deprecatedrouter", Evidence: declaredEvidence()})
			if info.RouterPath == "" {
				info.RouterPath, info.RouterMethod = path, method
			}
			found = true
		case "@deprecated":
			info.Deprecated = true
			found = true
		case "@param":
			p, issue := parseParam(rest)
			if issue != "" {
				info.Issues = append(info.Issues, model.SwagIssue{Directive: directive, Message: issue})
			} else {
				info.Parameters = append(info.Parameters, p)
			}
			found = true
		case "@success", "@failure", "@response":
			r, issue := parseResponse(rest)
			if issue != "" {
				info.Issues = append(info.Issues, model.SwagIssue{Directive: directive, Message: issue})
			} else {
				responseByStatus[r.Status] = len(info.Responses)
				info.Responses = append(info.Responses, r)
			}
			found = true
		case "@header":
			statuses, h, issue := parseHeader(rest)
			if issue != "" {
				info.Issues = append(info.Issues, model.SwagIssue{Directive: directive, Message: issue})
			} else {
				for _, status := range statuses {
					if i, ok := responseByStatus[status]; ok {
						info.Responses[i].Headers = append(info.Responses[i].Headers, h)
					} else {
						info.Issues = append(info.Issues, model.SwagIssue{Directive: directive, Message: "header references response status " + status + " before it is declared"})
					}
				}
			}
			found = true
		case "@security":
			if s, ok := parseSecurity(rest); ok {
				info.Security = append(info.Security, s)
			} else {
				info.Issues = append(info.Issues, model.SwagIssue{Directive: directive, Message: "missing security scheme name"})
			}
			found = true
		default:
			if strings.HasPrefix(lower, "@x-") {
				if info.Extensions == nil {
					info.Extensions = map[string]any{}
				}
				info.Extensions[strings.TrimPrefix(lower, "@")] = parseLiteral(strings.TrimSpace(rest))
				found = true
			}
		}
	}
	if !found {
		return nil
	}
	info.Description = strings.Join(desc, " ")
	info.Fields = swagFieldEvidence(info)
	return &info
}

func swagFieldEvidence(info model.SwagInfo) map[string]model.DocumentationEvidence {
	fields := map[string]model.DocumentationEvidence{}
	add := func(name string, present bool) {
		if present {
			fields[name] = declaredEvidence()
		}
	}
	add("summary", info.Summary != "")
	add("description", info.Description != "")
	add("tags", len(info.Tags) > 0)
	add("id", info.ID != "")
	add("accept", len(info.Accept) > 0)
	add("produce", len(info.Produce) > 0)
	add("deprecated", info.Deprecated)
	add("routers", len(info.Routers) > 0)
	add("parameters", len(info.Parameters) > 0)
	add("responses", len(info.Responses) > 0)
	add("security", len(info.Security) > 0)
	add("extensions", len(info.Extensions) > 0)
	add("issues", len(info.Issues) > 0)
	if len(fields) == 0 {
		return nil
	}
	return fields
}

// ParseSwagGlobalAnnotations parses the maintained general-API subset used by
// swaggo/swag v1.8-v1.16. Contextual @name/@in/@scope directives apply only
// to the immediately preceding security definition or tag in the same
// comment group; malformed context is recorded, never guessed.
func ParseSwagGlobalAnnotations(doc *ast.CommentGroup) *model.APIDocumentation {
	if doc == nil {
		return nil
	}
	lines := swagCommentLines(doc)
	globalAnchor := false
	for _, line := range lines {
		d, _ := splitDirective(line)
		lower := strings.ToLower(d)
		if lower == "@title" || lower == "@version" || lower == "@host" || lower == "@basepath" || lower == "@schemes" || lower == "@tag.name" || strings.HasPrefix(lower, "@securitydefinitions.") {
			globalAnchor = true
			break
		}
	}
	if !globalAnchor {
		return nil
	}
	api := &model.APIDocumentation{Evidence: declaredEvidence()}
	found := false
	currentSecurity, currentTag := "", -1
	for _, line := range lines {
		if !strings.HasPrefix(line, "@") {
			continue
		}
		directive, rest := splitDirective(line)
		lower := strings.ToLower(directive)
		rest = strings.TrimSpace(rest)
		switch lower {
		case "@title":
			api.Title = rest
			found = true
		case "@version":
			api.Version = rest
			found = true
		case "@description":
			if api.Description != "" {
				api.Description += " "
			}
			api.Description += rest
			found = true
		case "@termsofservice":
			api.TermsOfService = rest
			found = true
		case "@contact.name":
			api.ContactName = rest
			found = true
		case "@contact.url":
			api.ContactURL = rest
			found = true
		case "@contact.email":
			api.ContactEmail = rest
			found = true
		case "@license.name":
			api.LicenseName = rest
			found = true
		case "@license.url":
			api.LicenseURL = rest
			found = true
		case "@host":
			api.Host = rest
			found = true
		case "@basepath":
			api.BasePath = rest
			found = true
		case "@schemes":
			api.Schemes = appendCSVUnique(api.Schemes, strings.ReplaceAll(rest, " ", ","))
			found = true
		case "@tag.name":
			api.Tags = append(api.Tags, model.APITagDocumentation{Name: rest, Evidence: declaredEvidence()})
			currentTag = len(api.Tags) - 1
			currentSecurity = ""
			found = true
		case "@tag.description":
			if currentTag >= 0 {
				api.Tags[currentTag].Description = rest
			} else {
				api.Issues = append(api.Issues, model.SwagIssue{Directive: directive, Message: "tag description has no preceding @tag.name"})
			}
			found = true
		case "@security":
			if s, ok := parseSecurity(rest); ok {
				api.Security = append(api.Security, s)
			} else {
				api.Issues = append(api.Issues, model.SwagIssue{Directive: directive, Message: "missing security scheme name"})
			}
			found = true
		case "@securitydefinitions.basic", "@securitydefinitions.apikey", "@securitydefinitions.oauth2.application", "@securitydefinitions.oauth2.implicit", "@securitydefinitions.oauth2.password", "@securitydefinitions.oauth2.accesscode":
			if rest == "" {
				api.Issues = append(api.Issues, model.SwagIssue{Directive: directive, Message: "missing security definition name"})
				found = true
				continue
			}
			if api.SecurityDefinitions == nil {
				api.SecurityDefinitions = map[string]model.DocumentedSecurityScheme{}
			}
			typ := strings.TrimPrefix(lower, "@securitydefinitions.")
			scheme := model.DocumentedSecurityScheme{Type: typ, Evidence: declaredEvidence(), Scopes: map[string]string{}}
			if typ == "basic" {
				scheme.Type = "http"
				scheme.Scheme = "basic"
			} else if typ == "apikey" {
				scheme.Type = "apiKey"
			} else {
				scheme.Type = "oauth2"
			}
			api.SecurityDefinitions[rest] = scheme
			currentSecurity, currentTag = rest, -1
			found = true
		case "@name", "@in", "@tokenurl", "@authorizationurl":
			if currentSecurity == "" {
				api.Issues = append(api.Issues, model.SwagIssue{Directive: directive, Message: "security attribute has no preceding security definition"})
				found = true
				continue
			}
			scheme := api.SecurityDefinitions[currentSecurity]
			switch lower {
			case "@name":
				scheme.Name = rest
			case "@in":
				scheme.In = rest
			case "@tokenurl":
				scheme.TokenURL = rest
			case "@authorizationurl":
				scheme.AuthorizationURL = rest
			}
			api.SecurityDefinitions[currentSecurity] = scheme
			found = true
		default:
			if strings.HasPrefix(lower, "@scope.") && currentSecurity != "" {
				scheme := api.SecurityDefinitions[currentSecurity]
				if scheme.Scopes == nil {
					scheme.Scopes = map[string]string{}
				}
				scheme.Scopes[strings.TrimPrefix(directive, "@scope.")] = rest
				api.SecurityDefinitions[currentSecurity] = scheme
				found = true
			}
			if strings.HasPrefix(lower, "@x-") {
				if api.Extensions == nil {
					api.Extensions = map[string]any{}
				}
				api.Extensions[strings.TrimPrefix(lower, "@")] = parseLiteral(rest)
				found = true
			}
		}
	}
	if !found {
		return nil
	}
	api.Fields = apiGlobalFieldEvidence(api)
	return api
}

func apiGlobalFieldEvidence(api *model.APIDocumentation) map[string]model.DocumentationEvidence {
	fields := map[string]model.DocumentationEvidence{}
	add := func(name string, present bool) {
		if present {
			fields[name] = declaredEvidence()
		}
	}
	add("title", api.Title != "")
	add("version", api.Version != "")
	add("description", api.Description != "")
	add("termsOfService", api.TermsOfService != "")
	add("contact", api.ContactName != "" || api.ContactURL != "" || api.ContactEmail != "")
	add("license", api.LicenseName != "" || api.LicenseURL != "")
	add("server", api.Host != "" || api.BasePath != "" || len(api.Schemes) > 0)
	add("tags", len(api.Tags) > 0)
	add("securityDefinitions", len(api.SecurityDefinitions) > 0)
	add("security", len(api.Security) > 0)
	add("extensions", len(api.Extensions) > 0)
	add("issues", len(api.Issues) > 0)
	return fields
}

func swagCommentLines(doc *ast.CommentGroup) []string {
	var lines []string
	for _, c := range doc.List {
		text := strings.TrimSuffix(strings.TrimPrefix(c.Text, "/*"), "*/")
		for _, sub := range strings.Split(text, "\n") {
			sub = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(sub), "//"))
			sub = strings.TrimSpace(strings.TrimPrefix(sub, "*"))
			if sub != "" {
				lines = append(lines, sub)
			}
		}
	}
	return lines
}

func splitDirective(line string) (string, string) {
	i := strings.IndexFunc(line, unicode.IsSpace)
	if i < 0 {
		return line, ""
	}
	return line[:i], strings.TrimSpace(line[i:])
}

// annotationFields is a small lexer, not strings.Fields: quoted descriptions,
// tabs, and parenthesized attributes may contain whitespace.
func annotationFields(s string) ([]string, error) {
	var fields []string
	var b strings.Builder
	var quote rune
	escaped, depth := false, 0
	flush := func() {
		if b.Len() > 0 {
			fields = append(fields, b.String())
			b.Reset()
		}
	}
	for _, r := range strings.TrimSpace(s) {
		if escaped {
			b.WriteRune(r)
			escaped = false
			continue
		}
		if quote != 0 {
			if r == '\\' {
				escaped = true
			} else if r == quote {
				quote = 0
			} else {
				b.WriteRune(r)
			}
			continue
		}
		switch r {
		case '\'', '"', '`':
			quote = r
		case '(', '[', '{':
			depth++
			b.WriteRune(r)
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
			b.WriteRune(r)
		default:
			if unicode.IsSpace(r) && depth == 0 {
				flush()
			} else {
				b.WriteRune(r)
			}
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated quoted value")
	}
	flush()
	return fields, nil
}

func parseRouterDirective(rest string) (string, string, bool) {
	f, err := annotationFields(rest)
	if err != nil || len(f) == 0 || f[0] == "" {
		return "", "", false
	}
	method := ""
	if len(f) > 1 && strings.HasPrefix(f[1], "[") && strings.HasSuffix(f[1], "]") {
		method = strings.ToUpper(strings.TrimSpace(f[1][1 : len(f[1])-1]))
	}
	return f[0], method, true
}

func parseParam(rest string) (model.SwagParameter, string) {
	f, err := annotationFields(rest)
	if err != nil {
		return model.SwagParameter{}, err.Error()
	}
	if len(f) < 5 {
		return model.SwagParameter{}, "expected name, location, type, required flag, and description"
	}
	in := strings.ToLower(f[1])
	if in == "formdata" {
		in = "formData"
	}
	switch in {
	case "path", "query", "header", "body", "formData":
	default:
		return model.SwagParameter{}, "unsupported parameter location " + f[1]
	}
	required, err := strconv.ParseBool(strings.ToLower(f[3]))
	if err != nil {
		return model.SwagParameter{}, "required flag must be true or false"
	}
	if in == "path" {
		required = true
	}
	schema := schemaFromAnnotationType(f[2])
	for _, attr := range f[5:] {
		applySchemaAttribute(schema, attr)
	}
	return model.SwagParameter{Name: f[0], In: in, Required: required, Description: f[4], Schema: schema, Evidence: declaredEvidence()}, ""
}

func parseResponse(rest string) (model.SwagResponse, string) {
	f, err := annotationFields(rest)
	if err != nil {
		return model.SwagResponse{}, err.Error()
	}
	if len(f) < 1 {
		return model.SwagResponse{}, "missing response status"
	}
	r := model.SwagResponse{Status: f[0], Description: "Response", Evidence: declaredEvidence()}
	if !validResponseStatus(r.Status) {
		return model.SwagResponse{}, "status must be default, 100-599, or a 1XX-5XX range"
	}
	if len(f) >= 2 && strings.HasPrefix(f[1], "{") && strings.HasSuffix(f[1], "}") {
		kind := strings.ToLower(strings.Trim(f[1], "{}"))
		switch kind {
		case "object", "array", "string", "integer", "number", "boolean":
		default:
			return model.SwagResponse{}, "unsupported response schema kind " + kind
		}
		if len(f) < 3 {
			return model.SwagResponse{}, "response schema kind requires a type"
		}
		r.Schema = schemaFromAnnotationType(f[2])
		if kind == "array" {
			r.Schema = &model.SchemaEvidence{Type: "array", Items: r.Schema, Evidence: declaredEvidence()}
		}
		if len(f) > 3 {
			r.Description = f[3]
		}
	} else if len(f) > 1 {
		r.Description = f[1]
	}
	return r, ""
}

func validResponseStatus(status string) bool {
	if status == "default" {
		return true
	}
	if len(status) != 3 {
		return false
	}
	if status[1:] == "XX" {
		return status[0] >= '1' && status[0] <= '5'
	}
	n, err := strconv.Atoi(status)
	return err == nil && n >= 100 && n <= 599
}

func parseHeader(rest string) ([]string, model.SwagHeader, string) {
	f, err := annotationFields(rest)
	if err != nil {
		return nil, model.SwagHeader{}, err.Error()
	}
	if len(f) < 3 {
		return nil, model.SwagHeader{}, "expected status, type, and header name"
	}
	h := model.SwagHeader{Name: f[2], Schema: schemaFromAnnotationType(strings.Trim(f[1], "{}")), Evidence: declaredEvidence()}
	if len(f) > 3 {
		h.Description = f[3]
	}
	return strings.Split(f[0], ","), h, ""
}

func parseSecurity(rest string) (model.SwagSecurity, bool) {
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return model.SwagSecurity{}, false
	}
	s := model.SwagSecurity{Evidence: declaredEvidence()}
	if i := strings.Index(rest, "["); i >= 0 && strings.HasSuffix(rest, "]") {
		s.Name = strings.TrimSpace(rest[:i])
		s.Scopes = appendCSVUnique(nil, rest[i+1:len(rest)-1])
	} else {
		s.Name = rest
	}
	return s, s.Name != ""
}

func schemaFromAnnotationType(raw string) *model.SchemaEvidence {
	raw = strings.TrimSpace(raw)
	s := &model.SchemaEvidence{GoType: raw, Evidence: declaredEvidence()}
	if strings.HasPrefix(raw, "[]") {
		s.Type = "array"
		s.Items = schemaFromAnnotationType(raw[2:])
		return s
	}
	if strings.HasPrefix(raw, "map[") {
		if end := strings.Index(raw, "]"); end >= 0 {
			s.Type = "object"
			s.AdditionalProperties = schemaFromAnnotationType(raw[end+1:])
			return s
		}
	}
	switch strings.ToLower(raw) {
	case "string":
		s.Type = "string"
	case "bool", "boolean":
		s.Type = "boolean"
	case "int", "int8", "int16", "int32", "uint", "uint8", "uint16", "uint32":
		s.Type = "integer"
		s.Format = "int32"
	case "int64", "uint64":
		s.Type = "integer"
		s.Format = "int64"
	case "float32":
		s.Type = "number"
		s.Format = "float"
	case "float64", "number":
		s.Type = "number"
		s.Format = "double"
	case "file":
		s.Type = "string"
		s.Format = "binary"
	case "interface{}", "any", "object":
		s.Type = "object"
	default:
		s.Evidence.Status = "unresolved"
	}
	return s
}

func applySchemaAttribute(s *model.SchemaEvidence, attr string) {
	i := strings.Index(attr, "(")
	if i < 1 || !strings.HasSuffix(attr, ")") {
		s.Evidence.Status = "partial"
		s.Evidence.Conflicts = append(s.Evidence.Conflicts, "unsupported or malformed schema attribute "+attr)
		return
	}
	name, raw := strings.ToLower(attr[:i]), attr[i+1:len(attr)-1]
	switch name {
	case "default":
		s.Default = parseLiteral(raw)
	case "example":
		s.Example = parseLiteral(raw)
	case "enums", "enum":
		for _, v := range strings.Split(raw, ",") {
			s.Enum = append(s.Enum, parseLiteral(strings.TrimSpace(v)))
		}
	case "minimum", "min":
		if v, err := strconv.ParseFloat(raw, 64); err == nil {
			s.Minimum = &v
		} else {
			s.Evidence.Status = "partial"
			s.Evidence.Conflicts = append(s.Evidence.Conflicts, "invalid numeric attribute "+attr)
		}
	case "maximum", "max":
		if v, err := strconv.ParseFloat(raw, 64); err == nil {
			s.Maximum = &v
		} else {
			s.Evidence.Status = "partial"
			s.Evidence.Conflicts = append(s.Evidence.Conflicts, "invalid numeric attribute "+attr)
		}
	case "minlength":
		if v, err := strconv.Atoi(raw); err == nil && v >= 0 {
			s.MinLength = &v
		} else {
			s.Evidence.Status = "partial"
			s.Evidence.Conflicts = append(s.Evidence.Conflicts, "invalid integer attribute "+attr)
		}
	case "maxlength":
		if v, err := strconv.Atoi(raw); err == nil && v >= 0 {
			s.MaxLength = &v
		} else {
			s.Evidence.Status = "partial"
			s.Evidence.Conflicts = append(s.Evidence.Conflicts, "invalid integer attribute "+attr)
		}
	case "format":
		s.Format = raw
	case "pattern":
		s.Pattern = raw
	default:
		s.Evidence.Status = "partial"
		s.Evidence.Conflicts = append(s.Evidence.Conflicts, "unsupported schema attribute "+attr)
	}
}

func parseLiteral(raw string) any {
	raw = strings.TrimSpace(raw)
	var v any
	if json.Unmarshal([]byte(raw), &v) == nil {
		return v
	}
	if b, err := strconv.ParseBool(raw); err == nil {
		return b
	}
	if n, err := strconv.ParseFloat(raw, 64); err == nil {
		return n
	}
	return raw
}
func appendCSVUnique(dst []string, raw string) []string {
	seen := map[string]bool{}
	for _, v := range dst {
		seen[v] = true
	}
	for _, v := range strings.Split(raw, ",") {
		v = strings.TrimSpace(v)
		if v != "" && !seen[v] {
			dst = append(dst, v)
			seen[v] = true
		}
	}
	return dst
}
func appendMIMEs(dst []string, raw string) []string {
	for _, v := range strings.Split(raw, ",") {
		v = strings.TrimSpace(v)
		if full := swagMIMETypes[strings.ToLower(v)]; full != "" {
			v = full
		}
		dst = appendCSVUnique(dst, v)
	}
	return dst
}

func ApplySwagFromDoc(route *model.Route, doc *ast.CommentGroup) *model.Diagnostic {
	info := ParseSwagAnnotations(doc)
	if info == nil {
		return nil
	}
	ApplySwagProvenance(info, route.Source)
	route.Swag = info
	return swagRouterMismatchDiagnostic(*route, *info)
}

// ApplySwagProvenance attaches the discovered handler location after parsing
// or schema resolution without exposing source text.
func ApplySwagProvenance(info *model.SwagInfo, source *model.Source) {
	if source == nil {
		return
	}
	copySource := func() *model.Source { x := *source; return &x }
	for key, evidence := range info.Fields {
		evidence.Provenance = copySource()
		info.Fields[key] = evidence
	}
	for i := range info.Routers {
		info.Routers[i].Evidence.Provenance = copySource()
	}
	for i := range info.Parameters {
		info.Parameters[i].Evidence.Provenance = copySource()
		applySchemaProvenance(info.Parameters[i].Schema, copySource)
	}
	for i := range info.Responses {
		info.Responses[i].Evidence.Provenance = copySource()
		applySchemaProvenance(info.Responses[i].Schema, copySource)
		for j := range info.Responses[i].Headers {
			info.Responses[i].Headers[j].Evidence.Provenance = copySource()
			applySchemaProvenance(info.Responses[i].Headers[j].Schema, copySource)
		}
	}
	for i := range info.Security {
		info.Security[i].Evidence.Provenance = copySource()
	}
	for key, component := range info.Components {
		applySchemaProvenance(&component, copySource)
		info.Components[key] = component
	}
}

func applySchemaProvenance(schema *model.SchemaEvidence, copySource func() *model.Source) {
	if schema == nil {
		return
	}
	schema.Evidence.Provenance = copySource()
	applySchemaProvenance(schema.Items, copySource)
	applySchemaProvenance(schema.AdditionalProperties, copySource)
	for key, value := range schema.Properties {
		applySchemaProvenance(&value, copySource)
		schema.Properties[key] = value
	}
}

func swagRouterMismatchDiagnostic(route model.Route, info model.SwagInfo) *model.Diagnostic {
	routers := info.Routers
	if len(routers) == 0 && (info.RouterPath != "" || info.RouterMethod != "") {
		routers = []model.SwagRouter{{Path: info.RouterPath, Method: info.RouterMethod}}
	}
	if len(routers) == 0 {
		return nil
	}
	for _, r := range routers {
		if (r.Path == "" || r.Path == swagPathForm(route.GinPath)) && (r.Method == "" || r.Method == route.Method) {
			return nil
		}
	}
	claims := make([]string, 0, len(routers))
	for _, r := range routers {
		claims = append(claims, fmt.Sprintf("%s %s", r.Method, r.Path))
	}
	return &model.Diagnostic{Code: "swag-router-mismatch", Severity: model.DiagnosticWarning, Message: fmt.Sprintf("@Router annotations %q do not include discovered route %s %s; analyzer evidence remains authoritative per ADR 0007/0012", strings.Join(claims, ", "), route.Method, route.GinPath), Source: route.Source}
}

func swagPathForm(ginPath string) string {
	parts := strings.Split(ginPath, "/")
	for i, p := range parts {
		if strings.HasPrefix(p, ":") || strings.HasPrefix(p, "*") {
			parts[i] = "{" + p[1:] + "}"
		}
	}
	return strings.Join(parts, "/")
}
