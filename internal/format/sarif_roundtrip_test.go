package format

// Round-trip validation against a real, independent SARIF parser, mirroring
// the OpenAPI formatter's use of pb33f/libopenapi (see
// openapi_roundtrip_test.go) — docs/accuracy-strategy.md requires "Schema,
// SARIF, and OpenAPI validation must pass", and parsing the emitted document
// with a parser wholly independent of this package's own encoding/json-based
// formatter catches a bug that produces syntactically-valid-but-
// semantically-wrong SARIF (a ruleIndex out of range, a malformed location)
// that a same-package unmarshal-and-inspect test could miss if it shared a
// mistaken assumption with the formatter itself. go-sarif is confined to
// this file, a test-only dependency edge exactly like libopenapi's.

import (
	"testing"

	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/sagnikhaldar/gin-recon/internal/model"
	"github.com/sagnikhaldar/gin-recon/internal/report"
)

func parseWithGoSarif(t *testing.T, data []byte) *sarif.Report {
	t.Helper()
	parsed, err := sarif.FromBytes(data)
	if err != nil {
		t.Fatalf("sarif.FromBytes: %v\n%s", err, data)
	}
	if parsed.Version != "2.1.0" {
		t.Fatalf("parsed version = %q, want 2.1.0", parsed.Version)
	}
	if len(parsed.Runs) != 1 {
		t.Fatalf("expected exactly 1 run, got %d", len(parsed.Runs))
	}
	return parsed
}

func TestSARIFRoundTripEmptyDocument(t *testing.T) {
	rep := report.NewAuditReport(model.ProfileTyped, testTarget(), report.Summary{}, nil, report.PolicyEvaluation{}, nil)
	rep.ScanCoverage = model.ScanCoverage{AnalyzedPackages: 1, AnalyzedFiles: 1, Complete: true}

	data, err := SARIF(rep)
	if err != nil {
		t.Fatalf("SARIF: %v", err)
	}
	parsed := parseWithGoSarif(t, data)
	if len(parsed.Runs[0].Results) != 0 {
		t.Errorf("expected no results, got %d", len(parsed.Runs[0].Results))
	}
}

func TestSARIFRoundTripRichDocument(t *testing.T) {
	line1, line2 := 10, 20
	route1 := "GET /admin/users"
	route2 := "POST /webhook"
	rec := "fix the guard"

	findings := []report.Finding{
		{
			ID: "f1", RuleID: report.RuleMatchedButUnenforced, Fingerprint: "fp1",
			Severity: report.SeverityHigh, Confidence: model.ConfidenceHigh,
			Route: &route1, Source: &model.Source{File: "internal/auth/guard.go", Line: &line1},
			Detail: "configured guard never enforces a deny path", Recommendation: &rec,
		},
		{
			ID: "f2", RuleID: report.RulePublicRoute, Fingerprint: "fp2",
			Severity: report.SeverityMedium, Confidence: model.ConfidenceHigh,
			Route: &route2, Source: &model.Source{File: "router.go", Line: &line2},
			Detail: "no configured authentication guard matched this route's middleware chain",
		},
		{
			ID: "f3", RuleID: report.RuleStaleBaseline, Fingerprint: "fp3",
			Severity: report.SeverityLow, Confidence: model.ConfidenceHigh,
			Detail: "acceptedPublic entry does not match any discovered route",
		},
	}

	rep := report.NewAuditReport(model.ProfileTyped, testTarget(), report.Summary{}, findings, report.PolicyEvaluation{EvaluatedPolicies: []string{"admin-requires-auth"}}, nil)
	rep.Diagnostics = []model.Diagnostic{
		{Code: "gin-unresolved-path", Severity: model.DiagnosticWarning, Message: "path could not be resolved", Source: &model.Source{File: "router.go", Line: &line2}},
	}
	rep.ScanCoverage = model.ScanCoverage{AnalyzedPackages: 2, AnalyzedFiles: 5, Complete: false}

	data, err := SARIF(rep)
	if err != nil {
		t.Fatalf("SARIF: %v", err)
	}
	parsed := parseWithGoSarif(t, data)
	run := parsed.Runs[0]
	if len(run.Results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(run.Results))
	}
	for _, r := range run.Results {
		if r.RuleID == nil || *r.RuleID == "" {
			t.Errorf("result missing ruleId: %+v", r)
		}
		if r.RuleIndex == nil || int(*r.RuleIndex) >= len(run.Tool.Driver.Rules) {
			t.Errorf("result ruleIndex out of range: %+v", r)
		}
	}
	if len(run.Invocations) != 1 {
		t.Fatalf("expected 1 invocation, got %d", len(run.Invocations))
	}
	// Incomplete coverage must add its own notification on top of the
	// explicit diagnostic, per sarifInvocationFor.
	if len(run.Invocations[0].ToolExecutionNotifications) != 2 {
		t.Errorf("expected 2 tool execution notifications (1 diagnostic + 1 incomplete-coverage), got %d", len(run.Invocations[0].ToolExecutionNotifications))
	}
}

func TestSARIFRoundTripHostileFindingContent(t *testing.T) {
	fp := "fp-hostile"
	f := report.Finding{
		ID: fp, RuleID: report.RulePublicRoute, Fingerprint: fp,
		Severity: report.SeverityMedium, Confidence: model.ConfidenceHigh,
		Detail: "route \"/a|b\" <script>alert(1)</script>\nsecond line",
	}
	rep := report.NewAuditReport(model.ProfileTyped, testTarget(), report.Summary{}, []report.Finding{f}, report.PolicyEvaluation{}, nil)
	rep.ScanCoverage = model.ScanCoverage{Complete: true}

	data, err := SARIF(rep)
	if err != nil {
		t.Fatalf("SARIF: %v", err)
	}
	parsed := parseWithGoSarif(t, data)
	if len(parsed.Runs[0].Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(parsed.Runs[0].Results))
	}
}
