package format

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sagnikhaldar/gin-recon/internal/model"
	"github.com/sagnikhaldar/gin-recon/internal/report"
)

func testTarget() report.Target {
	return report.Target{
		Module: "example.com/demo",
		BuildContext: model.BuildContext{
			GOOS: "linux", GOARCH: "amd64", Profile: model.ProfileTyped,
			WorkspaceMode: model.WorkspaceOff, ModuleMode: model.ModuleReadonly,
		},
	}
}

func sampleRoute() model.Route {
	symbol := "example.com/demo/internal/auth.RequireUser"
	line := 42
	return model.Route{
		Method:         "GET",
		NormalizedPath: "/admin/users",
		SurfaceKind:    model.SurfaceRoute,
		Middleware: []model.Middleware{
			{DisplayName: "RequireUser", CanonicalSymbol: &symbol, CallableKind: model.CallableIdentifier, ResolutionStatus: model.Resolved},
		},
		FinalHandler:       model.Middleware{DisplayName: "ListUsers", CallableKind: model.CallableIdentifier, ResolutionStatus: model.Resolved},
		Source:             &model.Source{File: "router.go", Line: &line},
		PathConfidence:     model.ConfidenceHigh,
		AnalysisConfidence: model.ConfidenceHigh,
		BuildContext:       testTarget().BuildContext,
	}
}

func TestPrettyInventoryDoesNotErrorAndOmitsAuditSections(t *testing.T) {
	rep := report.NewInventoryReport(model.ProfileTyped, testTarget())
	rep.Routes = []model.Route{sampleRoute()}
	rep.ScanCoverage = model.ScanCoverage{AnalyzedPackages: 1, AnalyzedFiles: 1, Complete: true}

	var buf bytes.Buffer
	if err := Pretty(&buf, rep); err != nil {
		t.Fatalf("Pretty: %v", err)
	}
	out := buf.String()

	for _, want := range []string{"gin-recon inventory", "example.com/demo", "GET", "/admin/users", "RequireUser", "ListUsers", "router.go:42"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q; got:\n%s", want, out)
		}
	}
	for _, unwanted := range []string{"SUMMARY", "FINDINGS", "POLICIES EVALUATED"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("inventory output must not contain %q (audit-only section); got:\n%s", unwanted, out)
		}
	}
}

func TestPrettyAuditIncludesSummaryAndFindings(t *testing.T) {
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
	if err := Pretty(&buf, rep); err != nil {
		t.Fatalf("Pretty: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		"gin-recon audit",
		"INCOMPLETE",
		"SUMMARY",
		"1 unknown",
		"unknown/contradicted",
		"FINDINGS (1)",
		"matched-but-unenforced",
		"guard never aborts",
		"Fix the guard.",
		"POLICIES EVALUATED: admin-requires-auth",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q; got:\n%s", want, out)
		}
	}
}

func TestPrettyHandlesEmptyRoutesAndFindings(t *testing.T) {
	rep := report.NewInventoryReport(model.ProfileTyped, testTarget())
	var buf bytes.Buffer
	if err := Pretty(&buf, rep); err != nil {
		t.Fatalf("Pretty: %v", err)
	}
	if !strings.Contains(buf.String(), "ROUTES (0)") {
		t.Errorf("expected ROUTES (0) for an empty report; got:\n%s", buf.String())
	}
}
