package format

import (
	"strings"
	"testing"

	"github.com/sagnikhaldar/gin-recon/internal/model"
)

// TestOpenAPIEvidenceSourceMarksSwagWhenSwagWins confirms
// x-gin-recon.evidenceSource records "swag" whenever a swag annotation
// actually replaced this formatter's own generic placeholder for
// Summary/Description/Tags/Deprecated, per ginReconExt.EvidenceSource's doc
// comment — so a reader of the generated document (or api.html) can tell
// this prose came from a developer's own doc comment, not gin-recon's static
// analysis.
func TestOpenAPIEvidenceSourceMarksSwagWhenSwagWins(t *testing.T) {
	route := routeAt("GET", "/users/:id")
	route.Swag = &model.SwagInfo{Summary: "Get a user by ID"}
	rep := inventoryWithRoutes(route)

	data, _, err := OpenAPI(rep, nil)
	if err != nil {
		t.Fatalf("OpenAPI: %v", err)
	}
	if !strings.Contains(string(data), `"evidenceSource": "swag"`) {
		t.Errorf("expected evidenceSource=swag when a swag annotation supplied the summary; got:\n%s", data)
	}
}

// TestOpenAPIEvidenceSourceMarksExistingDocumentWhenItWins confirms the
// counterpart marker for docs/adr/0013-existing-openapi-document-reconciliation.md's
// evidence, when no swag annotation is present to outrank it.
func TestOpenAPIEvidenceSourceMarksExistingDocumentWhenItWins(t *testing.T) {
	route := routeAt("GET", "/users/:id")
	route.ExistingDocument = &model.ExistingDocumentInfo{Summary: "Fetch a user by ID from the existing document"}
	rep := inventoryWithRoutes(route)

	data, _, err := OpenAPI(rep, nil)
	if err != nil {
		t.Fatalf("OpenAPI: %v", err)
	}
	if !strings.Contains(string(data), `"evidenceSource": "existingDocument"`) {
		t.Errorf("expected evidenceSource=existingDocument when the existing document supplied the summary; got:\n%s", data)
	}
}

// TestOpenAPIEvidenceSourceAbsentWithSwagPresentButNoWinningField confirms
// the marker is never set merely because Route.Swag is non-nil — only when
// it actually replaced a prose field. A swag annotation with no recognized
// prose directive (all four fields empty/false) cannot occur from real
// parsing (docs/adr/0012 says a doc comment with nothing recognized yields a
// nil *SwagInfo), but this pins the defensive behavior regardless.
func TestOpenAPIEvidenceSourceAbsentWithSwagPresentButNoWinningField(t *testing.T) {
	route := routeAt("GET", "/users/:id")
	route.Swag = &model.SwagInfo{}
	rep := inventoryWithRoutes(route)

	data, _, err := OpenAPI(rep, nil)
	if err != nil {
		t.Fatalf("OpenAPI: %v", err)
	}
	if strings.Contains(string(data), "evidenceSource") {
		t.Errorf("expected no evidenceSource marker when swag supplied nothing; got:\n%s", data)
	}
}

// TestOpenAPIEvidenceSourceAbsentWhenNeitherSourcePresent is the common-case
// regression: no swag, no existing document, gin-recon's own generic
// placeholder — the marker must never appear at all, not merely be false or
// empty-stringed in.
func TestOpenAPIEvidenceSourceAbsentWhenNeitherSourcePresent(t *testing.T) {
	rep := inventoryWithRoutes(routeAt("GET", "/users/:id"))

	data, _, err := OpenAPI(rep, nil)
	if err != nil {
		t.Fatalf("OpenAPI: %v", err)
	}
	if strings.Contains(string(data), "evidenceSource") {
		t.Errorf("expected no evidenceSource marker when neither swag nor an existing document is present; got:\n%s", data)
	}
}

// TestOpenAPIEvidenceSourceSwagOutranksExistingDocument confirms the marker
// itself follows ADR 0013's precedence (swag > existing document): when both
// are present and swag wins the prose fields, the marker says "swag", never
// "existingDocument", matching TestOpenAPIExistingDocumentNeverOverridesSwag's
// existing coverage of the underlying field precedence.
func TestOpenAPIEvidenceSourceSwagOutranksExistingDocument(t *testing.T) {
	route := routeAt("GET", "/users/:id")
	route.Swag = &model.SwagInfo{Summary: "Swag summary wins"}
	route.ExistingDocument = &model.ExistingDocumentInfo{Summary: "Existing-doc summary should be ignored"}
	rep := inventoryWithRoutes(route)

	data, _, err := OpenAPI(rep, nil)
	if err != nil {
		t.Fatalf("OpenAPI: %v", err)
	}
	if !strings.Contains(string(data), `"evidenceSource": "swag"`) {
		t.Errorf("expected evidenceSource=swag, not existingDocument, when both are present and swag wins; got:\n%s", data)
	}
	if strings.Contains(string(data), `"evidenceSource": "existingDocument"`) {
		t.Errorf("existingDocument must never claim evidenceSource when swag already won; got:\n%s", data)
	}
}
