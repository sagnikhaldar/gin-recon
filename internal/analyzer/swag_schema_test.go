package analyzer

import (
	"go/token"
	"go/types"
	"testing"

	"github.com/sagnikhaldar/gin-recon/internal/model"
)

func TestSwagSchemaStructTagsEmbeddingPointersAndCycles(t *testing.T) {
	pkg := types.NewPackage("example.com/dto", "dto")
	node := types.NewNamed(types.NewTypeName(token.NoPos, pkg, "Node", nil), nil, nil)
	embedded := types.NewNamed(types.NewTypeName(token.NoPos, pkg, "Meta", nil), types.NewStruct([]*types.Var{types.NewField(token.NoPos, pkg, "TraceID", types.Typ[types.String], false)}, []string{"json:\"traceId\""}), nil)
	fields := []*types.Var{types.NewField(token.NoPos, pkg, "Name", types.Typ[types.String], false), types.NewField(token.NoPos, pkg, "Optional", types.NewPointer(types.Typ[types.String]), false), types.NewField(token.NoPos, pkg, "Ignored", types.Typ[types.String], false), types.NewField(token.NoPos, pkg, "Meta", embedded, true), types.NewField(token.NoPos, pkg, "Next", types.NewPointer(node), false), types.NewField(token.NoPos, pkg, "Opaque", types.Typ[types.Int], false)}
	node.SetUnderlying(types.NewStruct(fields, []string{"json:\"name\" binding:\"required\"", "json:\"optional,omitempty\"", "json:\"-\"", "", "json:\"next,omitempty\"", "json:\"opaque,omitempty\" swaggertype:\"primitive,string\" example:\"demo\""}))
	r := &swagSchemaResolver{packages: map[string][]*types.Package{}, owner: pkg, components: map[string]model.SchemaEvidence{}, building: map[string]bool{}}
	s := r.schemaFor(node)
	if s.Ref == "" || len(r.components) != 2 {
		t.Fatalf("schema=%+v components=%+v", s, r.components)
	}
	component := r.components[s.Ref]
	if _, ok := component.Properties["traceId"]; !ok {
		t.Fatal("embedded field not flattened")
	}
	if _, ok := component.Properties["Ignored"]; ok {
		t.Fatal("json:- field retained")
	}
	if component.Properties["optional"].Nullable != true {
		t.Fatal("pointer nullability lost")
	}
	if contains(component.Required, "optional") {
		t.Fatal("omitempty conflated with required")
	}
	if _, ok := component.Properties["next"]; !ok {
		t.Fatal("recursive field lost")
	}
	if !contains(component.Required, "name") {
		t.Fatal("binding required tag was not retained")
	}
	if !component.Properties["optional"].OmitEmpty {
		t.Fatal("omitempty provenance was not retained")
	}
	if component.Properties["opaque"].Type != "string" || component.Properties["opaque"].Example != "demo" {
		t.Fatalf("model override lost: %+v", component.Properties["opaque"])
	}
}

func TestSwagSchemaGenericInstanceAndAliasHaveDeterministicDistinctComponents(t *testing.T) {
	pkg := types.NewPackage("example.com/dto", "dto")
	constraint := types.NewInterfaceType(nil, nil)
	constraint.Complete()
	tp := types.NewTypeParam(types.NewTypeName(token.NoPos, pkg, "T", nil), constraint)
	box := types.NewNamed(types.NewTypeName(token.NoPos, pkg, "Box", nil), types.NewStruct([]*types.Var{types.NewField(token.NoPos, pkg, "Value", tp, false)}, []string{"json:\"value\""}), nil)
	box.SetTypeParams([]*types.TypeParam{tp})
	stringBox, err := types.Instantiate(nil, box, []types.Type{types.Typ[types.String]}, true)
	if err != nil {
		t.Fatal(err)
	}
	intBox, err := types.Instantiate(nil, box, []types.Type{types.Typ[types.Int]}, true)
	if err != nil {
		t.Fatal(err)
	}
	r := &swagSchemaResolver{packages: map[string][]*types.Package{}, owner: pkg, components: map[string]model.SchemaEvidence{}, building: map[string]bool{}}
	a, b := r.schemaFor(stringBox), r.schemaFor(intBox)
	if a.Ref == b.Ref || a.Ref == "" || b.Ref == "" {
		t.Fatalf("generic refs %q %q", a.Ref, b.Ref)
	}
	if r.schemaFor(types.NewAlias(types.NewTypeName(token.NoPos, pkg, "Alias", nil), stringBox)).Ref != a.Ref {
		t.Fatal("alias did not resolve to underlying generic instance")
	}
}

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}
