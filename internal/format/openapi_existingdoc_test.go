package format

import (
	"strings"
	"testing"

	"github.com/sagnikhaldar/gin-recon/internal/model"
)

// TestOpenAPIAppliesExistingDocumentEvidence exercises
// applyExistingDocEvidence's precedence rule directly
// (docs/adr/0013-existing-openapi-document-reconciliation.md): a present
// existing-document field replaces this formatter's own generic default when
// no higher-precedence swag evidence already claimed it, and a matched path
// parameter's description is filled in.
func TestOpenAPIAppliesExistingDocumentEvidence(t *testing.T) {
	route := routeAt("GET", "/users/:id")
	route.ExistingDocument = &model.ExistingDocumentInfo{
		Summary:           "Fetch a user by ID from the existing document",
		Description:       "Existing-document description.",
		Tags:              []string{"users", "legacy-doc"},
		Deprecated:        true,
		ParamDescriptions: map[string]string{"id": "the user's ID, per the existing document"},
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
	if op.Summary != "Fetch a user by ID from the existing document" {
		t.Errorf("Summary = %q, want existing-document value", op.Summary)
	}
	if op.Description != "Existing-document description." {
		t.Errorf("Description = %q, want existing-document value", op.Description)
	}
	if len(op.Tags) != 2 || op.Tags[0] != "users" || op.Tags[1] != "legacy-doc" {
		t.Errorf("Tags = %+v, want [users legacy-doc]", op.Tags)
	}
	if !op.Deprecated {
		t.Error("Deprecated = false, want true")
	}
	if len(op.Parameters) != 1 || op.Parameters[0].Description != "the user's ID, per the existing document" {
		t.Errorf("Parameters = %+v, want id's description filled in", op.Parameters)
	}
}

// TestOpenAPIExistingDocumentNeverOverridesSwag confirms ADR 0013's
// precedence order: swag (ADR 0012) outranks the existing document, so a
// field already set by a swag annotation must survive untouched even when
// the existing document also carries a value for it.
func TestOpenAPIExistingDocumentNeverOverridesSwag(t *testing.T) {
	route := routeAt("GET", "/users/:id")
	route.Swag = &model.SwagInfo{Summary: "Swag summary wins", Description: "Swag description wins", Tags: []string{"from-swag"}}
	route.ExistingDocument = &model.ExistingDocumentInfo{
		Summary:     "Existing-doc summary should be ignored",
		Description: "Existing-doc description should be ignored",
		Tags:        []string{"from-doc"},
	}
	rep := inventoryWithRoutes(route)

	data, _, err := OpenAPI(rep, nil)
	if err != nil {
		t.Fatalf("OpenAPI: %v", err)
	}
	doc := decodeDoc(t, data)
	op := doc.Paths["/users/{id}"].Get
	if op.Summary != "Swag summary wins" {
		t.Errorf("Summary = %q, want swag value to win over the existing document", op.Summary)
	}
	if op.Description != "Swag description wins" {
		t.Errorf("Description = %q, want swag value to win over the existing document", op.Description)
	}
	if len(op.Tags) != 1 || op.Tags[0] != "from-swag" {
		t.Errorf("Tags = %+v, want swag's tags to win over the existing document", op.Tags)
	}
}

// TestOpenAPIExistingDocumentParamConflictMarksUnrefined confirms a
// structural parameter-name conflict is surfaced via the existing
// x-gin-recon.unrefined mechanism (already used for "unrefined: security")
// rather than silently applying or silently dropping the document's
// parameter content.
func TestOpenAPIExistingDocumentParamConflictMarksUnrefined(t *testing.T) {
	route := routeAt("GET", "/orders/:orderId")
	route.ExistingDocument = &model.ExistingDocumentInfo{
		Summary:       "Still applied despite the conflict",
		ParamConflict: true,
		// A conflicted ParamDescriptions should never occur from real
		// reconciliation, but even if present here it must not leak into the
		// generated parameter description.
		ParamDescriptions: map[string]string{"orderId": "should never appear"},
	}
	rep := inventoryWithRoutes(route)

	data, _, err := OpenAPI(rep, nil)
	if err != nil {
		t.Fatalf("OpenAPI: %v", err)
	}
	doc := decodeDoc(t, data)
	op := doc.Paths["/orders/{orderId}"].Get
	if op.Summary != "Still applied despite the conflict" {
		t.Errorf("Summary = %q, want the existing-document value: prose is never gated by the structural check", op.Summary)
	}
	if len(op.Parameters) != 1 || op.Parameters[0].Description != "" {
		t.Errorf("Parameters = %+v, want no description applied on conflict", op.Parameters)
	}
	if !strings.Contains(string(data), `"unrefined": [`) || !strings.Contains(string(data), `"parameters"`) {
		t.Errorf("expected the operation to be marked unrefined for \"parameters\"; got:\n%s", data)
	}
}

// TestOpenAPIWithoutExistingDocumentKeepsGenericDefaults confirms the common
// case (analysis.existingOpenAPIDocument unset, Route.ExistingDocument nil)
// is completely unaffected.
func TestOpenAPIWithoutExistingDocumentKeepsGenericDefaults(t *testing.T) {
	rep := inventoryWithRoutes(routeAt("GET", "/users/:id"))
	data, _, err := OpenAPI(rep, nil)
	if err != nil {
		t.Fatalf("OpenAPI: %v", err)
	}
	doc := decodeDoc(t, data)
	op := doc.Paths["/users/{id}"].Get
	if op.Description != "" {
		t.Errorf("Description = %q, want empty when no existing-document evidence is present", op.Description)
	}
	if op.Deprecated {
		t.Error("Deprecated = true, want false when no existing-document evidence is present")
	}
}
