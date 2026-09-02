package analyzer

import (
	"testing"

	"github.com/sagnikhaldar/gin-recon/internal/model"
)

// TestReconcileExistingDocumentSwagger2 is
// TestInventoryAndOpenAPIReconcilesExistingDocument's Swagger 2.0
// counterpart: testdata/fixtures/existing-swagger-document/swagger.yaml is a
// genuine Swagger 2.0 document (top-level "swagger: 2.0", not
// "openapi: 3.x"), which loadExistingDocument only recognizes via its
// BuildV2Model() fallback. This confirms that fallback produces identical
// outcomes to the v3 path: the document is recognized as valid (never
// openapi-spec-invalid), GetUser's operation matches and merges exactly like
// a v3 document's would, and GetOrder's deliberately-mismatched path
// parameter still produces openapi-spec-conflict.
func TestReconcileExistingDocumentSwagger2(t *testing.T) {
	result := loadAndInventory(t, "existing-swagger-document")

	specResult := ReconcileExistingDocument(result.Routes, fixtureDir(t, "existing-swagger-document"), "swagger.yaml")
	if specResult == nil {
		t.Fatal("ReconcileExistingDocument returned nil, want a populated result")
	}
	for _, d := range specResult.Diagnostics {
		if d.Code == "openapi-spec-invalid" {
			t.Fatalf("got openapi-spec-invalid diagnostic, want the Swagger 2.0 document recognized as valid: %+v", d)
		}
	}
	if specResult.Reconciled == nil {
		t.Fatal("Reconciled is nil, want populated (document parsed successfully via BuildV2Model fallback)")
	}

	routes := map[string]*model.Route{}
	for i := range result.Routes {
		r := &result.Routes[i]
		routes[r.Method+" "+r.NormalizedPath] = r
	}

	getUser, ok := routes["GET /users/:id"]
	if !ok {
		t.Fatalf("route GET /users/:id not found; routes: %+v", result.Routes)
	}
	if getUser.ExistingDocument == nil {
		t.Fatal("GetUser: ExistingDocument is nil, want populated")
	}
	if getUser.ExistingDocument.Summary != "Fetch a user by ID from the existing document" {
		t.Errorf("GetUser: Summary = %q", getUser.ExistingDocument.Summary)
	}
	if getUser.ExistingDocument.Description != "Existing-document description for GetUser." {
		t.Errorf("GetUser: Description = %q", getUser.ExistingDocument.Description)
	}
	if len(getUser.ExistingDocument.Tags) != 2 {
		t.Errorf("GetUser: Tags = %+v, want 2 entries", getUser.ExistingDocument.Tags)
	}
	if getUser.ExistingDocument.ParamConflict {
		t.Error("GetUser: ParamConflict = true, want false")
	}
	if getUser.ExistingDocument.ParamDescriptions["id"] != "The user's ID, per the existing document." {
		t.Errorf("GetUser: ParamDescriptions[id] = %q", getUser.ExistingDocument.ParamDescriptions["id"])
	}

	getOrder, ok := routes["GET /orders/:orderId"]
	if !ok {
		t.Fatalf("route GET /orders/:orderId not found; routes: %+v", result.Routes)
	}
	if getOrder.ExistingDocument == nil {
		t.Fatal("GetOrder: ExistingDocument is nil, want populated (summary has no structural conflict)")
	}
	if getOrder.ExistingDocument.Summary == "" {
		t.Error("GetOrder: Summary is empty, want the existing-document value despite the parameter conflict")
	}
	if !getOrder.ExistingDocument.ParamConflict {
		t.Error("GetOrder: ParamConflict = false, want true (\"orderId\" vs the document's \"id\")")
	}
	if len(getOrder.ExistingDocument.ParamDescriptions) != 0 {
		t.Errorf("GetOrder: ParamDescriptions = %+v, want empty on conflict", getOrder.ExistingDocument.ParamDescriptions)
	}

	plain, ok := routes["GET /plain"]
	if !ok {
		t.Fatalf("route GET /plain not found; routes: %+v", result.Routes)
	}
	if plain.ExistingDocument != nil {
		t.Errorf("PlainHandler: ExistingDocument = %+v, want nil (no matching document operation)", plain.ExistingDocument)
	}

	if len(specResult.Reconciled.OrphanedOperations) != 1 {
		t.Fatalf("OrphanedOperations = %+v, want exactly 1", specResult.Reconciled.OrphanedOperations)
	}
	orphan := specResult.Reconciled.OrphanedOperations[0]
	if orphan.Method != "DELETE" || orphan.Path != "/legacy/{id}" {
		t.Errorf("orphan = %+v, want DELETE /legacy/{id}", orphan)
	}
	if orphan.Summary != "Deprecated legacy delete operation no longer present in code" {
		t.Errorf("orphan.Summary = %q", orphan.Summary)
	}

	var conflicts, orphanDiags int
	for _, d := range specResult.Diagnostics {
		switch d.Code {
		case "openapi-spec-conflict":
			conflicts++
			if d.Severity != model.DiagnosticWarning {
				t.Errorf("openapi-spec-conflict severity = %q, want warning", d.Severity)
			}
		case "openapi-spec-orphan-operation":
			orphanDiags++
			if d.Severity != model.DiagnosticInfo {
				t.Errorf("openapi-spec-orphan-operation severity = %q, want info", d.Severity)
			}
		}
	}
	if conflicts != 1 {
		t.Errorf("got %d openapi-spec-conflict diagnostics, want 1: %+v", conflicts, specResult.Diagnostics)
	}
	if orphanDiags != 1 {
		t.Errorf("got %d openapi-spec-orphan-operation diagnostics, want 1: %+v", orphanDiags, specResult.Diagnostics)
	}
}
