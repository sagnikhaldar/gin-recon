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

// TestHTMLGracefullyDegradesWithNoEvidence confirms a report with no swag
// evidence at all — the overwhelming common case — produces a well-formed
// page, and the rendered JSON spec itself carries no evidenceSource key for
// this fixture, matching format.OpenAPI's own "absent means off" behavior
// verified in openapi_provenance_test.go.
func TestHTMLGracefullyDegradesWithNoEvidence(t *testing.T) {
	rep := inventoryWithRoutes(routeAt("GET", "/x"), routeAt("POST", "/y"))
	data, diags, err := HTML(rep, nil)
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}
	if len(diags) != 0 {
		t.Fatalf("unexpected diagnostics: %+v", diags)
	}
	out := string(data)

	if strings.Contains(out, "evidenceSource") == false {
		// evidenceSource is only referenced by the badge-rendering JS itself
		// (ext.evidenceSource), never as literal spec content for this
		// fixture — this branch would only fail if the badge function was
		// removed entirely, which the earlier test already covers; this test
		// instead confirms the embedded spec JSON has no such key for a route
		// with no swag evidence.
		t.Fatalf("evidenceBadge wiring appears to have been removed; got:\n%s", out)
	}
	if strings.Contains(out, `"evidenceSource":`) {
		t.Errorf("embedded spec must not carry an evidenceSource value for a route with no swag evidence; got:\n%s", out)
	}
}
