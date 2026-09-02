package format

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sagnikhaldar/gin-recon/internal/report"
)

// TestOpenAPIDocumentLevelExtensionPresentWithOrphans confirms
// rep.ExistingDocumentReconciliation's already-computed orphan list (per
// docs/adr/0013-existing-openapi-document-reconciliation.md, threaded into
// rep by cmd/gin-recon's applyExistingDocumentReconciliation before any
// format.* call) is exposed one layer further as the document-root
// "x-gin-recon-existing-document-reconciliation" extension, so a reader of
// openapi.json/api.html alone sees the same orphan evidence
// routes.json/routes.md/results.sarif already carry.
func TestOpenAPIDocumentLevelExtensionPresentWithOrphans(t *testing.T) {
	rep := inventoryWithRoutes(routeAt("GET", "/users/:id"))
	rep.ExistingDocumentReconciliation = &report.ExistingDocumentReconciliation{
		OrphanedOperations: []report.OrphanedOperation{
			{Method: "DELETE", Path: "/legacy/{id}", Summary: "Deprecated legacy delete operation"},
		},
	}

	data, _, err := OpenAPI(rep, nil)
	if err != nil {
		t.Fatalf("OpenAPI: %v", err)
	}

	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal generated document: %v", err)
	}
	ext, ok := decoded["x-gin-recon-existing-document-reconciliation"]
	if !ok {
		t.Fatalf("expected x-gin-recon-existing-document-reconciliation key present; got:\n%s", data)
	}
	for _, want := range []string{
		`"method": "DELETE"`,
		`"path": "/legacy/{id}"`,
		`"summary": "Deprecated legacy delete operation"`,
	} {
		if !strings.Contains(string(ext), want) {
			t.Errorf("extension missing %q:\n%s", want, ext)
		}
	}
}

// TestOpenAPIDocumentLevelExtensionAbsentWhenReconciliationNil confirms the
// common, pre-ADR-0013 case (analysis.existingOpenAPIDocument never
// configured, rep.ExistingDocumentReconciliation nil) never gains the new
// extension key at all — absence, not an empty object, per
// report.ExistingDocumentReconciliation's own "present only when configured"
// discipline.
func TestOpenAPIDocumentLevelExtensionAbsentWhenReconciliationNil(t *testing.T) {
	rep := inventoryWithRoutes(routeAt("GET", "/users/:id"))

	data, _, err := OpenAPI(rep, nil)
	if err != nil {
		t.Fatalf("OpenAPI: %v", err)
	}
	if strings.Contains(string(data), "x-gin-recon-existing-document-reconciliation") {
		t.Errorf("expected no x-gin-recon-existing-document-reconciliation key when reconciliation never ran; got:\n%s", data)
	}
}

// TestOpenAPIDocumentLevelExtensionAbsentWhenNoOrphans confirms a
// reconciliation that ran but found zero orphans (every document operation
// matched a discovered route) still omits the key entirely rather than
// emitting an empty orphanedOperations array — matching
// ExistingDocumentReconciliation.MarshalJSON's own defaulting behavior for
// the report-level field, but the document-level extension's stricter rule
// (never present at all) is enforced in format.OpenAPI itself.
func TestOpenAPIDocumentLevelExtensionAbsentWhenNoOrphans(t *testing.T) {
	rep := inventoryWithRoutes(routeAt("GET", "/users/:id"))
	rep.ExistingDocumentReconciliation = &report.ExistingDocumentReconciliation{
		OrphanedOperations: []report.OrphanedOperation{},
	}

	data, _, err := OpenAPI(rep, nil)
	if err != nil {
		t.Fatalf("OpenAPI: %v", err)
	}
	if strings.Contains(string(data), "x-gin-recon-existing-document-reconciliation") {
		t.Errorf("expected no x-gin-recon-existing-document-reconciliation key when reconciliation found zero orphans; got:\n%s", data)
	}
}
