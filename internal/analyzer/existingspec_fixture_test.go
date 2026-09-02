package analyzer

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sagnikhaldar/gin-recon/internal/format"
	"github.com/sagnikhaldar/gin-recon/internal/model"
	"github.com/sagnikhaldar/gin-recon/internal/report"
)

// TestInventoryAndOpenAPIReconcilesExistingDocument exercises the full
// discovery-through-OpenAPI path for
// docs/adr/0013-existing-openapi-document-reconciliation.md against
// testdata/fixtures/existing-openapi-document (see its manifest.json):
// GetUser's route fully agrees with the companion openapi.yaml, GetOrder's
// route disagrees with it on a path parameter name (a structural conflict),
// PlainHandler has no corresponding document operation, and the document's
// DELETE /legacy/{id} has no matching route (an orphan never synthesized
// into routes).
func TestInventoryAndOpenAPIReconcilesExistingDocument(t *testing.T) {
	result := loadAndInventory(t, "existing-openapi-document")

	specResult := ReconcileExistingDocument(result.Routes, fixtureDir(t, "existing-openapi-document"), "openapi.yaml")
	if specResult == nil {
		t.Fatal("ReconcileExistingDocument returned nil, want a populated result")
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

	if specResult.Reconciled == nil {
		t.Fatal("Reconciled is nil, want populated (document parsed successfully)")
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

	rep := report.NewInventoryReport(model.ProfileTyped, report.Target{Module: result.Module})
	rep.Routes = result.Routes
	rep.ScanCoverage = result.ScanCoverage
	rep.Diagnostics = append(rep.Diagnostics, specResult.Diagnostics...)
	rep.ExistingDocumentReconciliation = specResult.Reconciled

	data, diags, err := format.OpenAPI(rep, nil)
	if err != nil {
		t.Fatalf("OpenAPI: %v", err)
	}
	if len(diags) != 0 {
		t.Errorf("unexpected OpenAPI-format-time diagnostics: %+v", diags)
	}
	for _, want := range []string{
		`"summary": "Fetch a user by ID from the existing document"`,
		`"description": "The user's ID, per the existing document."`,
		`"parameters"`,
	} {
		if !strings.Contains(string(data), want) {
			t.Errorf("generated OpenAPI document missing %q:\n%s", want, data)
		}
	}
	// The orphaned DELETE /legacy/{id} document operation must never be
	// synthesized into the generated OpenAPI document's paths — it was never
	// discovered in code, only claimed by the document — but it IS expected
	// to appear in the document-level
	// "x-gin-recon-existing-document-reconciliation" extension, which exposes
	// the same already-computed orphan list one layer further than
	// routes.json/routes.md/results.sarif alone.
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal generated document: %v", err)
	}
	if strings.Contains(string(decoded["paths"]), `"/legacy/{id}"`) {
		t.Errorf("generated OpenAPI document's paths must not contain the orphaned operation's path:\n%s", decoded["paths"])
	}
	ext, ok := decoded["x-gin-recon-existing-document-reconciliation"]
	if !ok {
		t.Fatalf("expected x-gin-recon-existing-document-reconciliation extension, got none:\n%s", data)
	}
	for _, want := range []string{
		`"method": "DELETE"`,
		`"path": "/legacy/{id}"`,
		`"summary": "Deprecated legacy delete operation no longer present in code"`,
	} {
		if !strings.Contains(string(ext), want) {
			t.Errorf("x-gin-recon-existing-document-reconciliation missing %q:\n%s", want, ext)
		}
	}
}

// TestInventoryAndOpenAPIAutoDetectsExistingDocument is
// TestInventoryAndOpenAPIReconcilesExistingDocument's counterpart for
// docs/adr/0014-auto-detect-existing-openapi-document.md: the same fixture's
// openapi.yaml sits at its --src root, which is the first entry in
// ExistingDocumentCandidates, so calling ResolveAndReconcileExistingDocument
// with no explicit path at all (as cmd/gin-recon's
// applyExistingDocumentReconciliation now does whenever
// analysis.existingOpenAPIDocument is unset) must reconcile against it
// automatically and produce the identical outcome as the explicit-path test
// above.
func TestInventoryAndOpenAPIAutoDetectsExistingDocument(t *testing.T) {
	result := loadAndInventory(t, "existing-openapi-document")

	specResult := ResolveAndReconcileExistingDocument(result.Routes, fixtureDir(t, "existing-openapi-document"), "", false)
	if specResult == nil {
		t.Fatal("ResolveAndReconcileExistingDocument returned nil, want auto-detection to find the fixture's root openapi.yaml")
	}

	var getUser *model.Route
	for i := range result.Routes {
		if result.Routes[i].Method+" "+result.Routes[i].NormalizedPath == "GET /users/:id" {
			getUser = &result.Routes[i]
			break
		}
	}
	if getUser == nil {
		t.Fatalf("route GET /users/:id not found; routes: %+v", result.Routes)
	}
	if getUser.ExistingDocument == nil {
		t.Fatal("GetUser: ExistingDocument is nil, want populated by auto-detection")
	}
	if getUser.ExistingDocument.Summary != "Fetch a user by ID from the existing document" {
		t.Errorf("GetUser: Summary = %q", getUser.ExistingDocument.Summary)
	}
}
