package format

import (
	"strings"
	"testing"
)

// TestHTMLRendersEvidenceBadgeFunction confirms the generated page's JS
// carries a badge-rendering function keyed off x-gin-recon.evidenceSource
// (openapi.go's ginReconExt.EvidenceSource), following this codebase's
// established pattern of asserting on the embedded JS source text since no
// headless browser is available in this test suite (see
// TestHTMLSecurityFieldReflectsAuthStatusNotHardcodedPublic for the
// precedent).
func TestHTMLRendersEvidenceBadgeFunction(t *testing.T) {
	rep := inventoryWithRoutes(routeAt("GET", "/x"))
	data, _, err := HTML(rep, nil)
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := string(data)

	for _, want := range []string{
		"function evidenceBadge(",
		"ext.evidenceSource",
		`"badge evidence"`,
		"evidenceBadge(ext)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q — viewer must render a provenance badge from x-gin-recon.evidenceSource; got:\n%s", want, out)
		}
	}
}

// TestHTMLRendersExistingDocumentSectionFunction confirms the generated
// page's JS carries a function that renders the document-level
// "x-gin-recon-existing-document-reconciliation" extension, and that render()
// actually calls it — mirroring TestHTMLRendersSummaryDescriptionAndSchemaTreesWhenPresent's
// established pattern for asserting a rendering function exists AND is
// wired into the page's top-level assembly, not merely defined and unused.
func TestHTMLRendersExistingDocumentSectionFunction(t *testing.T) {
	rep := inventoryWithRoutes(routeAt("GET", "/x"))
	data, _, err := HTML(rep, nil)
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := string(data)

	for _, want := range []string{
		"function existingDocumentSection(",
		`spec["x-gin-recon-existing-document-reconciliation"]`,
		"existingDocumentSection(spec[",
		`class: "existing-doc-section"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q — viewer must render the existing-document orphan section and call it from render(); got:\n%s", want, out)
		}
	}
}

// TestHTMLGracefullyDegradesWithNoEvidenceOrExistingDocument confirms a
// report with no swag/existing-document evidence at all — the overwhelming
// common case — produces a well-formed page with no stray empty section:
// the existing-document section's own guard ("if (!ext ... return null")
// must still be present in the source (so it always CAN degrade), and the
// rendered JSON spec itself must carry no evidenceSource key or
// x-gin-recon-existing-document-reconciliation extension for this fixture,
// matching format.OpenAPI's own "absent means off" behavior verified in
// openapi_provenance_test.go/openapi_docext_test.go.
func TestHTMLGracefullyDegradesWithNoEvidenceOrExistingDocument(t *testing.T) {
	rep := inventoryWithRoutes(routeAt("GET", "/x"), routeAt("POST", "/y"))
	data, diags, err := HTML(rep, nil)
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}
	if len(diags) != 0 {
		t.Fatalf("unexpected diagnostics: %+v", diags)
	}
	out := string(data)

	if !strings.Contains(out, "if (!ext || !ext.orphanedOperations || !ext.orphanedOperations.length) return null;") {
		t.Errorf("existingDocumentSection must guard against an absent/empty extension so nothing renders when unconfigured; got:\n%s", out)
	}
	if strings.Contains(out, "evidenceSource") == false {
		// evidenceSource is only referenced by the badge-rendering JS itself
		// (ext.evidenceSource), never as literal spec content for this
		// fixture — this branch would only fail if the badge function was
		// removed entirely, which the earlier test already covers; this test
		// instead confirms the embedded spec JSON has no such key for a route
		// with no swag/existing-document evidence.
		t.Fatalf("evidenceBadge wiring appears to have been removed; got:\n%s", out)
	}
	if strings.Contains(out, `"evidenceSource":`) {
		t.Errorf("embedded spec must not carry an evidenceSource value for a route with no swag/existing-document evidence; got:\n%s", out)
	}
	if strings.Contains(out, "x-gin-recon-existing-document-reconciliation\": {") {
		t.Errorf("embedded spec must not carry the existing-document extension key at all when reconciliation never ran; got:\n%s", out)
	}
}
