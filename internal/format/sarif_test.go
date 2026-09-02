package format

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sagnikhaldar/gin-recon/internal/model"
	"github.com/sagnikhaldar/gin-recon/internal/report"
)

func decodeSarif(t *testing.T, data []byte) sarifLog {
	t.Helper()
	var log sarifLog
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatalf("unmarshal generated SARIF: %v\n%s", err, data)
	}
	return log
}

func findingAt(ruleID report.RuleID, severity report.Severity, file string, line int) report.Finding {
	l := line
	routeIdentity := "GET /x"
	rec := "fix it"
	return report.Finding{
		ID: string(ruleID), RuleID: ruleID, Fingerprint: "fp-" + string(ruleID),
		Severity: severity, Confidence: model.ConfidenceHigh,
		Route: &routeIdentity, Source: &model.Source{File: file, Line: &l},
		Detail: "detail for " + string(ruleID), Recommendation: &rec,
	}
}

func TestSARIFTopLevelShape(t *testing.T) {
	rep := report.NewAuditReport(model.ProfileTyped, testTarget(), report.Summary{}, nil, report.PolicyEvaluation{}, nil)
	rep.ScanCoverage = model.ScanCoverage{AnalyzedPackages: 1, AnalyzedFiles: 1, Complete: true}

	data, err := SARIF(rep)
	if err != nil {
		t.Fatalf("SARIF: %v", err)
	}
	log := decodeSarif(t, data)
	if log.Version != "2.1.0" {
		t.Errorf("version = %q, want 2.1.0", log.Version)
	}
	if log.Schema != sarifSchemaURI {
		t.Errorf("schema = %q, want %q", log.Schema, sarifSchemaURI)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("expected exactly 1 run, got %d", len(log.Runs))
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "gin-recon" {
		t.Errorf("driver name = %q, want gin-recon", run.Tool.Driver.Name)
	}
	if len(run.Tool.Driver.Rules) != len(sarifRuleOrder) {
		t.Errorf("driver.rules length = %d, want %d (the full closed rule set, regardless of what fired)", len(run.Tool.Driver.Rules), len(sarifRuleOrder))
	}
	if len(run.Results) != 0 {
		t.Errorf("expected 0 results for an empty finding set, got %d", len(run.Results))
	}
}

func TestSARIFRuleIndexMatchesDriverRulesPosition(t *testing.T) {
	f := findingAt(report.RulePolicyViolation, report.SeverityHigh, "r.go", 10)
	rep := report.NewAuditReport(model.ProfileTyped, testTarget(), report.Summary{}, []report.Finding{f}, report.PolicyEvaluation{}, nil)
	rep.ScanCoverage = model.ScanCoverage{Complete: true}

	data, err := SARIF(rep)
	if err != nil {
		t.Fatalf("SARIF: %v", err)
	}
	log := decodeSarif(t, data)
	run := log.Runs[0]
	if len(run.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(run.Results))
	}
	result := run.Results[0]
	if result.RuleID != string(report.RulePolicyViolation) {
		t.Fatalf("ruleId = %q, want %q", result.RuleID, report.RulePolicyViolation)
	}
	if result.RuleIndex < 0 || result.RuleIndex >= len(run.Tool.Driver.Rules) {
		t.Fatalf("ruleIndex %d out of bounds for %d rules", result.RuleIndex, len(run.Tool.Driver.Rules))
	}
	if run.Tool.Driver.Rules[result.RuleIndex].ID != result.RuleID {
		t.Errorf("driver.rules[ruleIndex].id = %q, want it to match result.ruleId %q", run.Tool.Driver.Rules[result.RuleIndex].ID, result.RuleID)
	}
}

func TestSARIFSeverityMapsToLevel(t *testing.T) {
	cases := []struct {
		sev   report.Severity
		level string
	}{
		{report.SeverityCritical, "error"},
		{report.SeverityHigh, "error"},
		{report.SeverityMedium, "warning"},
		{report.SeverityLow, "note"},
		{report.SeverityInfo, "note"},
	}
	for _, c := range cases {
		f := findingAt(report.RulePublicRoute, c.sev, "r.go", 1)
		rep := report.NewAuditReport(model.ProfileTyped, testTarget(), report.Summary{}, []report.Finding{f}, report.PolicyEvaluation{}, nil)
		rep.ScanCoverage = model.ScanCoverage{Complete: true}

		data, err := SARIF(rep)
		if err != nil {
			t.Fatalf("SARIF: %v", err)
		}
		log := decodeSarif(t, data)
		got := log.Runs[0].Results[0].Level
		if got != c.level {
			t.Errorf("severity %q -> level %q, want %q", c.sev, got, c.level)
		}
	}
}

func TestSARIFResultCarriesLocationAndFingerprint(t *testing.T) {
	f := findingAt(report.RuleMatchedButUnenforced, report.SeverityHigh, "internal/auth/guard.go", 42)
	rep := report.NewAuditReport(model.ProfileTyped, testTarget(), report.Summary{}, []report.Finding{f}, report.PolicyEvaluation{}, nil)
	rep.ScanCoverage = model.ScanCoverage{Complete: true}

	data, err := SARIF(rep)
	if err != nil {
		t.Fatalf("SARIF: %v", err)
	}
	log := decodeSarif(t, data)
	result := log.Runs[0].Results[0]

	if len(result.Locations) != 1 {
		t.Fatalf("expected 1 location, got %d", len(result.Locations))
	}
	loc := result.Locations[0].PhysicalLocation
	if loc.ArtifactLocation.URI != "internal/auth/guard.go" {
		t.Errorf("uri = %q, want internal/auth/guard.go", loc.ArtifactLocation.URI)
	}
	if loc.Region == nil || loc.Region.StartLine != 42 {
		t.Errorf("region = %+v, want startLine 42", loc.Region)
	}
	if result.PartialFingerprints["ginReconFingerprint/v1"] != f.Fingerprint {
		t.Errorf("partialFingerprints = %+v, want ginReconFingerprint/v1 = %q", result.PartialFingerprints, f.Fingerprint)
	}
}

func TestSARIFFindingWithNoSourceOmitsLocations(t *testing.T) {
	fp := "fp-no-source"
	f := report.Finding{
		ID: fp, RuleID: report.RuleStaleAuthConfig, Fingerprint: fp,
		Severity: report.SeverityMedium, Confidence: model.ConfidenceHigh,
		Detail: "configured authMiddleware symbol was never matched",
	}
	rep := report.NewAuditReport(model.ProfileTyped, testTarget(), report.Summary{}, []report.Finding{f}, report.PolicyEvaluation{}, nil)
	rep.ScanCoverage = model.ScanCoverage{Complete: true}

	data, err := SARIF(rep)
	if err != nil {
		t.Fatalf("SARIF: %v", err)
	}
	log := decodeSarif(t, data)
	if len(log.Runs[0].Results[0].Locations) != 0 {
		t.Errorf("expected no locations for a source-less finding, got %+v", log.Runs[0].Results[0].Locations)
	}
}

func TestSARIFDiagnosticsBecomeToolExecutionNotifications(t *testing.T) {
	line := 5
	rep := report.NewAuditReport(model.ProfileTyped, testTarget(), report.Summary{}, nil, report.PolicyEvaluation{}, nil)
	rep.Diagnostics = []model.Diagnostic{
		{Code: "gin-unresolved-path", Severity: model.DiagnosticWarning, Message: "path could not be resolved", Source: &model.Source{File: "r.go", Line: &line}},
	}
	rep.ScanCoverage = model.ScanCoverage{Complete: true}

	data, err := SARIF(rep)
	if err != nil {
		t.Fatalf("SARIF: %v", err)
	}
	log := decodeSarif(t, data)
	inv := log.Runs[0].Invocations
	if len(inv) != 1 || !inv[0].ExecutionSuccessful {
		t.Fatalf("expected 1 successful invocation, got %+v", inv)
	}
	notes := inv[0].ToolExecutionNotifications
	if len(notes) != 1 {
		t.Fatalf("expected 1 notification, got %d", len(notes))
	}
	if notes[0].Descriptor.ID != "gin-unresolved-path" || notes[0].Level != "warning" {
		t.Errorf("notification = %+v, want descriptor gin-unresolved-path / level warning", notes[0])
	}
}

func TestSARIFIncompleteCoverageAddsNotification(t *testing.T) {
	rep := report.NewAuditReport(model.ProfileTyped, testTarget(), report.Summary{}, nil, report.PolicyEvaluation{}, nil)
	rep.ScanCoverage = model.ScanCoverage{Complete: false}

	data, err := SARIF(rep)
	if err != nil {
		t.Fatalf("SARIF: %v", err)
	}
	log := decodeSarif(t, data)
	notes := log.Runs[0].Invocations[0].ToolExecutionNotifications
	found := false
	for _, n := range notes {
		if n.Descriptor.ID == string(report.RuleIncompleteAnalysis) {
			found = true
		}
	}
	if !found {
		t.Errorf("expected an incomplete-analysis notification when ScanCoverage.Complete is false; got %+v", notes)
	}
}

func TestSARIFMessageTextIsEscaped(t *testing.T) {
	fp := "fp-hostile"
	f := report.Finding{
		ID: fp, RuleID: report.RulePublicRoute, Fingerprint: fp,
		Severity: report.SeverityMedium, Confidence: model.ConfidenceHigh,
		Detail: "route <script>alert(1)</script> | injected",
	}
	rep := report.NewAuditReport(model.ProfileTyped, testTarget(), report.Summary{}, []report.Finding{f}, report.PolicyEvaluation{}, nil)
	rep.ScanCoverage = model.ScanCoverage{Complete: true}

	data, err := SARIF(rep)
	if err != nil {
		t.Fatalf("SARIF: %v", err)
	}
	if strings.Contains(string(data), "<script>") {
		t.Errorf("raw <script> tag survived escaping in SARIF output:\n%s", data)
	}
}

func TestSARIFResultsSortedBySeverity(t *testing.T) {
	low := findingAt(report.RuleStaleBaseline, report.SeverityLow, "a.go", 1)
	high := findingAt(report.RuleMatchedButUnenforced, report.SeverityHigh, "b.go", 1)
	rep := report.NewAuditReport(model.ProfileTyped, testTarget(), report.Summary{}, []report.Finding{low, high}, report.PolicyEvaluation{}, nil)
	rep.ScanCoverage = model.ScanCoverage{Complete: true}

	data, err := SARIF(rep)
	if err != nil {
		t.Fatalf("SARIF: %v", err)
	}
	log := decodeSarif(t, data)
	results := log.Runs[0].Results
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if results[0].Level != "error" || results[1].Level != "note" {
		t.Errorf("expected high-severity result first, got levels %q then %q", results[0].Level, results[1].Level)
	}
}
