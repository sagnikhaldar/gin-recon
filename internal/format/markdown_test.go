package format

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sagnikhaldar/gin-recon/internal/model"
	"github.com/sagnikhaldar/gin-recon/internal/report"
)

func TestMarkdownInventoryDoesNotErrorAndOmitsAuditSections(t *testing.T) {
	rep := report.NewInventoryReport(model.ProfileTyped, testTarget())
	rep.Routes = []model.Route{sampleRoute()}
	rep.ScanCoverage = model.ScanCoverage{AnalyzedPackages: 1, AnalyzedFiles: 1, Complete: true}

	var buf bytes.Buffer
	if err := Markdown(&buf, rep); err != nil {
		t.Fatalf("Markdown: %v", err)
	}
	out := buf.String()

	for _, want := range []string{"# gin-recon inventory", "example.com/demo", "## Routes (1)", "GET", "/admin/users", "RequireUser", "ListUsers", "router.go:42"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q; got:\n%s", want, out)
		}
	}
	for _, unwanted := range []string{"## Summary", "## Findings", "## Policies evaluated"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("inventory output must not contain %q (audit-only section); got:\n%s", unwanted, out)
		}
	}
}

func TestMarkdownAuditIncludesSummaryAndFindings(t *testing.T) {
	route := sampleRoute()
	status := model.AuthUnknown
	enforcement := model.EnforcementContradicted
	route.Auth = &model.AuthClassification{AuthStatus: status, EnforcementAnalysis: &enforcement, Confidence: model.ConfidenceMedium}

	findingRoute := "GET /admin/users"
	rec := "Fix the guard."
	rep := report.NewAuditReport(
		model.ProfileTyped, testTarget(),
		report.Summary{TotalRoutes: 1, Unknown: 1, FindingsBySeverity: map[report.Severity]int{report.SeverityHigh: 1}},
		[]report.Finding{{
			ID: "f1", RuleID: report.RuleMatchedButUnenforced, Fingerprint: "f1",
			Severity: report.SeverityHigh, Confidence: model.ConfidenceHigh,
			Route: &findingRoute, Detail: "guard never aborts", Recommendation: &rec,
		}},
		report.PolicyEvaluation{EvaluatedPolicies: []string{"admin-requires-auth"}},
		nil,
	)
	rep.Routes = []model.Route{route}
	rep.ScanCoverage = model.ScanCoverage{AnalyzedPackages: 1, AnalyzedFiles: 1, Complete: false}

	var buf bytes.Buffer
	if err := Markdown(&buf, rep); err != nil {
		t.Fatalf("Markdown: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		"# gin-recon audit",
		"**INCOMPLETE**",
		"## Summary",
		"unknown: **1**",
		"unknown/contradicted",
		"## Findings (1)",
		"matched-but-unenforced",
		"guard never aborts",
		"Fix the guard.",
		"## Policies evaluated",
		"admin-requires-auth",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q; got:\n%s", want, out)
		}
	}
}

func TestMarkdownHandlesEmptyRoutesAndFindings(t *testing.T) {
	rep := report.NewInventoryReport(model.ProfileTyped, testTarget())
	var buf bytes.Buffer
	if err := Markdown(&buf, rep); err != nil {
		t.Fatalf("Markdown: %v", err)
	}
	if !strings.Contains(buf.String(), "## Routes (0)") {
		t.Errorf("expected Routes (0) header for an empty report; got:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "_None._") {
		t.Errorf("expected an explicit empty-state marker; got:\n%s", buf.String())
	}
}

func TestMdEscapeNeutralizesTableAndHTMLBreakingCharacters(t *testing.T) {
	cases := []struct {
		in       string
		mustNot  []string
		mustHave []string
	}{
		{in: "a|b", mustNot: []string{"a|b"}, mustHave: []string{`a\|b`}},
		{in: "a\\b", mustHave: []string{`a\\b`}},
		{in: "a`b", mustNot: []string{"a`b"}},
		{in: "line1\nline2", mustNot: []string{"\n"}, mustHave: []string{"line1 line2"}},
		{in: "<script>alert(1)</script>", mustNot: []string{"<script>"}, mustHave: []string{"&lt;script&gt;"}},
	}
	for _, c := range cases {
		got := mdEscape(c.in)
		for _, bad := range c.mustNot {
			if strings.Contains(got, bad) {
				t.Errorf("mdEscape(%q) = %q, must not contain %q", c.in, got, bad)
			}
		}
		for _, want := range c.mustHave {
			if !strings.Contains(got, want) {
				t.Errorf("mdEscape(%q) = %q, want it to contain %q", c.in, got, want)
			}
		}
	}
}

// TestMarkdownRouteWithHostileFieldsCannotBreakTableStructure is the
// docs/threat-model.md regression: a scanned repository is untrusted input,
// so a route whose method/path came from an attacker-controlled string
// literal (Handle("GET|evil", ...)) must not be able to inject an extra
// table column, break out into raw HTML, or otherwise corrupt the rendered
// document structure.
func TestMarkdownRouteWithHostileFieldsCannotBreakTableStructure(t *testing.T) {
	line := 1
	route := model.Route{
		Method:             "GET\n| INJECTED | <img onerror=alert(1)> |",
		NormalizedPath:     "/a|b`c<script>",
		SurfaceKind:        model.SurfaceRoute,
		FinalHandler:       model.Middleware{DisplayName: "h", CallableKind: model.CallableIdentifier, ResolutionStatus: model.Resolved},
		Source:             &model.Source{File: "r.go", Line: &line},
		PathConfidence:     model.ConfidenceHigh,
		AnalysisConfidence: model.ConfidenceHigh,
	}
	rep := report.NewInventoryReport(model.ProfileTyped, testTarget())
	rep.Routes = []model.Route{route}
	rep.ScanCoverage = model.ScanCoverage{AnalyzedPackages: 1, AnalyzedFiles: 1, Complete: true}

	var buf bytes.Buffer
	if err := Markdown(&buf, rep); err != nil {
		t.Fatalf("Markdown: %v", err)
	}
	out := buf.String()

	if strings.Contains(out, "<script>") || strings.Contains(out, "<img") {
		t.Errorf("raw HTML tag survived escaping; got:\n%s", out)
	}
	// Every route line the formatter emitted must still be a well-formed
	// table row (leading and trailing "|", same as the header/divider),
	// proving the embedded "\n" and "|" in Method/NormalizedPath did not
	// split or extend the row.
	inTable := false
	rowCount := 0
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "| Method") {
			inTable = true
			continue
		}
		if !inTable || l == "" {
			continue
		}
		if strings.HasPrefix(l, "##") {
			break
		}
		if !strings.HasPrefix(l, "| GET") && !strings.HasPrefix(l, "| ---") {
			t.Errorf("unexpected table line (possible injection): %q", l)
		}
		if strings.HasPrefix(l, "| GET") {
			rowCount++
		}
	}
	if rowCount != 1 {
		t.Errorf("expected exactly 1 route row, got %d — embedded newline may have split the row", rowCount)
	}
}
