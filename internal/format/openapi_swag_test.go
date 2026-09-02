package format

import (
	"testing"

	"github.com/sagnikhaldar/gin-recon/internal/model"
)

// TestOpenAPIAppliesSwagEvidence exercises applySwagEvidence's precedence
// rule directly (docs/adr/0012-swag-annotation-evidence.md): a present swag
// field replaces this formatter's own generic default for
// summary/description/tags/deprecated; an absent field leaves the default
// completely untouched. See internal/analyzer's fixture-driven
// TestInventoryAndOpenAPIApplySwagAnnotations for the full discovery-through-
// OpenAPI path.
func TestOpenAPIAppliesSwagEvidence(t *testing.T) {
	route := routeAt("GET", "/users/:id")
	route.Swag = &model.SwagInfo{
		Summary:     "Get a user by ID",
		Description: "Returns the user record matching the given ID.",
		Tags:        []string{"users", "public"},
		Deprecated:  true,
	}
	rep := inventoryWithRoutes(route)

	data, diags, err := OpenAPI(rep, nil)
	if err != nil {
		t.Fatalf("OpenAPI: %v", err)
	}
	if len(diags) != 0 {
		t.Fatalf("unexpected diagnostics: %+v", diags)
	}
	doc := decodeDoc(t, data)
	op := doc.Paths["/users/{id}"].Get
	if op == nil {
		t.Fatal("expected GET /users/{id} operation")
	}
	if op.Summary != "Get a user by ID" {
		t.Errorf("Summary = %q, want swag-derived value", op.Summary)
	}
	if op.Description != "Returns the user record matching the given ID." {
		t.Errorf("Description = %q, want swag-derived value", op.Description)
	}
	if len(op.Tags) != 2 || op.Tags[0] != "users" || op.Tags[1] != "public" {
		t.Errorf("Tags = %+v, want [users public]", op.Tags)
	}
	if !op.Deprecated {
		t.Error("Deprecated = false, want true")
	}
}

// TestOpenAPIWithoutSwagKeepsGenericDefaults confirms the common case (no
// swag comment at all) is completely unaffected — the formatter's existing
// placeholder summary/tags remain exactly as before, and no description or
// deprecated flag is fabricated.
func TestOpenAPIWithoutSwagKeepsGenericDefaults(t *testing.T) {
	rep := inventoryWithRoutes(routeAt("GET", "/users/:id"))
	data, _, err := OpenAPI(rep, nil)
	if err != nil {
		t.Fatalf("OpenAPI: %v", err)
	}
	doc := decodeDoc(t, data)
	op := doc.Paths["/users/{id}"].Get
	if op == nil {
		t.Fatal("expected GET /users/{id} operation")
	}
	if op.Summary == "" {
		t.Error("Summary is empty, want the generic method/path/handler default")
	}
	if op.Description != "" {
		t.Errorf("Description = %q, want empty when no swag evidence is present", op.Description)
	}
	if op.Deprecated {
		t.Error("Deprecated = true, want false when no swag evidence is present")
	}
}
