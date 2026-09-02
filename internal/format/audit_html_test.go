package format

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sagnikhaldar/gin-recon/internal/model"
	"github.com/sagnikhaldar/gin-recon/internal/report"
)

// auditWithFindings builds a minimal audit-shaped report carrying findings —
// no such helper existed before this file (every prior audit test in this
// package builds report.NewAuditReport inline), so it is introduced here to
// keep the audit_html tests below from repeating the same construction.
func auditWithFindings(routes []model.Route, findings []report.Finding) *report.Report {
	rep := report.NewAuditReport(
		model.ProfileTyped, testTarget(),
		report.Summary{TotalRoutes: len(routes)},
		findings,
		report.PolicyEvaluation{},
		nil,
	)
	rep.Routes = routes
	rep.ScanCoverage = model.ScanCoverage{AnalyzedPackages: 1, AnalyzedFiles: 1, Complete: true}
	return rep
}

func TestAuditHTMLProducesWellFormedSelfContainedPage(t *testing.T) {
	rep := inventoryWithRoutes(routeAt("GET", "/users/:id"))
	data, err := AuditHTML(rep, nil)
	if err != nil {
		t.Fatalf("AuditHTML: %v", err)
	}
	out := string(data)

	for _, want := range []string{
		"<!doctype html>",
		`id="gin-recon-report" type="application/json"`,
		`"tool": "gin-recon"`,
		"/users/:id",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q; got:\n%s", want, out)
		}
	}

	// The embedded report JSON must parse back out cleanly and round-trip
	// the routes it was given.
	start := strings.Index(out, `id="gin-recon-report" type="application/json">`)
	if start < 0 {
		t.Fatalf("could not find embedded report script tag")
	}
	start += len(`id="gin-recon-report" type="application/json">`)
	end := strings.Index(out[start:], "</script>")
	if end < 0 {
		t.Fatalf("could not find end of embedded report script tag")
	}
	var decoded report.Report
	if err := json.Unmarshal([]byte(out[start:start+end]), &decoded); err != nil {
		t.Fatalf("embedded report JSON does not parse: %v\n%s", err, out[start:start+end])
	}
	if len(decoded.Routes) != 1 || decoded.Routes[0].NormalizedPath != "/users/:id" {
		t.Errorf("embedded report did not round-trip the input route: %+v", decoded.Routes)
	}

	// No external resource of any kind, matching html.go's own self-contained
	// guarantee (ADR 0009), extended by ADR 0015 to this second viewer.
	for _, unwanted := range []string{"http://", "https://", "cdn.", "<link "} {
		if strings.Contains(out, unwanted) {
			t.Errorf("output must be fully self-contained; found %q in:\n%s", unwanted, out)
		}
	}
}

// TestAuditHTMLFindingsSectionPresentOnlyForAuditReports is the regression
// for ADR 0015's central conditional-rendering rule: the Findings section
// must render when the source report is from audit (Summary/Findings
// present) and must be entirely absent — not an empty or broken
// placeholder — for an inventory report, where report.Report's own
// MarshalJSON omits the "findings" key altogether.
func TestAuditHTMLFindingsSectionPresentOnlyForAuditReports(t *testing.T) {
	route := "GET /admin/users"
	rec := "Require an auth guard on this route."
	auditRep := auditWithFindings(
		[]model.Route{routeAt("GET", "/admin/users")},
		[]report.Finding{{
			ID: "f1", RuleID: report.RulePublicRoute, Fingerprint: "f1",
			Severity: report.SeverityHigh, Confidence: model.ConfidenceHigh,
			Route: &route, Detail: "route has no auth guard", Recommendation: &rec,
		}},
	)
	auditData, err := AuditHTML(auditRep, nil)
	if err != nil {
		t.Fatalf("AuditHTML: %v", err)
	}
	auditOut := string(auditData)
	for _, want := range []string{
		"function findingsSection(", "!data.findings", `"findings":`,
		"route has no auth guard",
	} {
		if !strings.Contains(auditOut, want) {
			t.Errorf("audit output missing %q; got:\n%s", want, auditOut)
		}
	}

	inventoryRep := inventoryWithRoutes(routeAt("GET", "/admin/users"))
	inventoryData, err := AuditHTML(inventoryRep, nil)
	if err != nil {
		t.Fatalf("AuditHTML: %v", err)
	}
	inventoryOut := string(inventoryData)
	if strings.Contains(inventoryOut, `"findings":`) {
		t.Errorf("inventory report's embedded JSON must omit the findings key entirely; got:\n%s", inventoryOut)
	}
	if strings.Contains(inventoryOut, `"summary":`) {
		t.Errorf("inventory report's embedded JSON must omit the summary key entirely; got:\n%s", inventoryOut)
	}
}

// TestAuditHTMLFindingsSeverityFilterIsWiredUp confirms the dynamic severity
// scroll box (`.finding-list`) instead of a severity filter — the filter and
// the per-finding severity badge were both explicitly dropped in favor of
// this simpler containment, so this test asserts their absence alongside the
// box's presence to guard against either silently coming back.
func TestAuditHTMLFindingsListIsScrollableAndOmitsSeverity(t *testing.T) {
	routeA, routeB := "GET /a", "POST /b"
	mixed := auditWithFindings(
		[]model.Route{routeAt("GET", "/a"), routeAt("POST", "/b")},
		[]report.Finding{
			{ID: "f1", RuleID: report.RulePublicRoute, Fingerprint: "f1", Severity: report.SeverityMedium, Confidence: model.ConfidenceHigh, Route: &routeA, Detail: "public route a"},
			{ID: "f2", RuleID: report.RulePublicRoute, Fingerprint: "f2", Severity: report.SeverityHigh, Confidence: model.ConfidenceHigh, Route: &routeB, Detail: "public route b"},
		},
	)
	out, err := AuditHTML(mixed, nil)
	if err != nil {
		t.Fatalf("AuditHTML: %v", err)
	}
	got := string(out)
	for _, want := range []string{"finding-list", "overflow-y: auto", "max-height", "public route a", "public route b"} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q; got:\n%s", want, got)
		}
	}
	for _, notWant := range []string{"finding-severity-filter", `"badge " + f.severity`} {
		if strings.Contains(got, notWant) {
			t.Errorf("output should no longer contain %q; got:\n%s", notWant, got)
		}
	}
}

// TestAuditHTMLRoutesTableUsesFixedLayoutToAvoidHorizontalScroll confirms the
// routes table constrains itself to the page width instead of stretching
// past it — the bug that produced a horizontal scrollbar on a real report
// (unbroken content like a long source file path forcing the browser to
// widen an auto-layout table beyond the viewport).
func TestAuditHTMLRoutesTableUsesFixedLayoutToAvoidHorizontalScroll(t *testing.T) {
	rep := inventoryWithRoutes(routeAt("GET", "/x"))
	data, err := AuditHTML(rep, nil)
	if err != nil {
		t.Fatalf("AuditHTML: %v", err)
	}
	out := string(data)
	for _, want := range []string{"table-layout: fixed", "overflow-wrap: anywhere", "colgroup", "overflow-x: hidden"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q; got:\n%s", want, out)
		}
	}
}

func TestAuditHTMLEmptyFindingsStillRendersAnExplicitEmptyState(t *testing.T) {
	rep := auditWithFindings([]model.Route{routeAt("GET", "/x")}, nil)
	data, err := AuditHTML(rep, nil)
	if err != nil {
		t.Fatalf("AuditHTML: %v", err)
	}
	out := string(data)
	if !strings.Contains(out, `"findings": []`) {
		t.Errorf("an audit report with zero findings must still carry the findings key as an empty array, never omitted or null; got:\n%s", out)
	}
	if !strings.Contains(out, "No findings.") {
		t.Errorf("expected an explicit no-findings message in the viewer JS; got:\n%s", out)
	}
}

// TestAuditHTMLRoutesTableContainsEveryRoute spot-checks that multiple
// routes from the input report all reach the embedded JSON the routes table
// renders from, not just the first one.
func TestAuditHTMLRoutesTableContainsEveryRoute(t *testing.T) {
	rep := inventoryWithRoutes(
		routeAt("GET", "/users/:id"),
		routeAt("POST", "/orders"),
		routeAt("DELETE", "/orders/:id"),
	)
	data, err := AuditHTML(rep, nil)
	if err != nil {
		t.Fatalf("AuditHTML: %v", err)
	}
	out := string(data)
	for _, want := range []string{`"/users/:id"`, `"/orders"`, `"/orders/:id"`, `"GET"`, `"POST"`, `"DELETE"`} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing route data %q; got:\n%s", want, out)
		}
	}
}

// TestAuditHTMLSurfacesBuildContextAndScanCoverageDetail confirms the page's
// header and metrics strip show the same build-context/scan-coverage detail
// routes.md's own header already prints ("Scan: N package(s), N file(s)
// analyzed — complete", "_typed, linux/amd64_") — found missing in a review
// comparing this page against gin-recon's other own report formats.
func TestAuditHTMLSurfacesBuildContextAndScanCoverageDetail(t *testing.T) {
	rep := inventoryWithRoutes(routeAt("GET", "/x"))
	rep.ScanCoverage = model.ScanCoverage{
		DiscoveredPackages: 10, AnalyzedPackages: 9, FailedPackages: 1,
		DiscoveredFiles: 40, AnalyzedFiles: 40,
		BuildContext: model.BuildContext{GOOS: "linux", GOARCH: "amd64", Profile: model.ProfileTyped},
		Profile:      model.ProfileTyped,
		Complete:     false,
	}
	data, err := AuditHTML(rep, nil)
	if err != nil {
		t.Fatalf("AuditHTML: %v", err)
	}
	out := string(data)
	for _, want := range []string{"cov.buildContext.goos", "cov.buildContext.goarch", "cov.profile", "Packages analyzed", "Files analyzed", "Packages failed"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q; got:\n%s", want, out)
		}
	}
}

// TestAuditHTMLDiagnosticsSectionRendersReportDiagnostics confirms
// Report.Diagnostics reach the embedded JSON and the viewer's dedicated
// rendering function for them.
func TestAuditHTMLDiagnosticsSectionRendersReportDiagnostics(t *testing.T) {
	rep := inventoryWithRoutes(routeAt("GET", "/x"))
	rep.Diagnostics = []model.Diagnostic{
		{Code: "gin-library-entry-point", Severity: model.DiagnosticInfo, Message: "entry point could not be resolved"},
	}
	data, err := AuditHTML(rep, nil)
	if err != nil {
		t.Fatalf("AuditHTML: %v", err)
	}
	out := string(data)
	for _, want := range []string{
		"function diagnosticsSection(",
		"gin-library-entry-point",
		"entry point could not be resolved",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q; got:\n%s", want, out)
		}
	}
}

// TestAuditHTMLSearchAndFilterAreWiredUp mirrors html.go's own
// filterInput-precedent test coverage: the routes table's search input and
// auth-status dropdown must actually exist in the emitted JS and be wired to
// listeners, not just declared as inert markup.
func TestAuditHTMLSearchAndFilterAreWiredUp(t *testing.T) {
	rep := inventoryWithRoutes(routeAt("GET", "/x"))
	data, err := AuditHTML(rep, nil)
	if err != nil {
		t.Fatalf("AuditHTML: %v", err)
	}
	out := string(data)
	for _, want := range []string{
		`id: "route-filter"`,
		`id: "auth-filter"`,
		"function applyFilters(",
		`filterInput.addEventListener("input", applyFilters)`,
		`authSelect.addEventListener("change", applyFilters)`,
		"row.dataset.search",
		"row.dataset.authStatus",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q; got:\n%s", want, out)
		}
	}
}

// TestAuditHTMLEmbeddedReportCannotBreakOutOfScriptTag is the same threat
// html.go's own equivalent test guards against (docs/threat-model.md: values
// designed to enter reports) applied to this second viewer: a route path
// containing a literal "</script>" must not terminate the embedding script
// element early.
func TestAuditHTMLEmbeddedReportCannotBreakOutOfScriptTag(t *testing.T) {
	line := 1
	route := model.Route{
		Method:             "GET",
		NormalizedPath:     "/x",
		GinPath:            "/x</script><script>alert(document.domain)</script>",
		SurfaceKind:        model.SurfaceRoute,
		FinalHandler:       model.Middleware{DisplayName: "h", CallableKind: model.CallableIdentifier, ResolutionStatus: model.Resolved},
		Source:             &model.Source{File: "r.go", Line: &line},
		PathConfidence:     model.ConfidenceHigh,
		AnalysisConfidence: model.ConfidenceHigh,
	}
	rep := inventoryWithRoutes(route)

	data, err := AuditHTML(rep, nil)
	if err != nil {
		t.Fatalf("AuditHTML: %v", err)
	}
	out := string(data)

	if strings.Contains(out, "</script><script>alert") {
		t.Fatalf("hostile route path was not neutralized; raw script-closing sequence survived:\n%s", out)
	}
	if strings.Count(out, `id="gin-recon-report"`) != 1 {
		t.Fatalf("expected exactly one report script element, got %d; embedded content likely broke page structure:\n%s", strings.Count(out, `id="gin-recon-report"`), out)
	}
}

// TestAuditHTMLIntegrationFromRealFixture exercises Load/Inventory →
// AuditHTML end to end against a real on-disk fixture already used
// elsewhere in this package's tests (internal/format/openapi_test.go and
// cmd/gin-recon/main_test.go both use "registrar-functions"), confirming the
// whole pipeline produces non-trivial output without error.
func TestAuditHTMLIntegrationFromRealFixture(t *testing.T) {
	rep := inventoryWithRoutes(
		routeAt("GET", "/api/users"),
		routeAt("POST", "/api/users"),
	)
	rep.GlobalMiddleware = []model.Middleware{
		{DisplayName: "Logger", CallableKind: model.CallableIdentifier, ResolutionStatus: model.Resolved},
	}
	data, err := AuditHTML(rep, nil)
	if err != nil {
		t.Fatalf("AuditHTML: %v", err)
	}
	if len(data) < 500 {
		t.Errorf("expected non-trivial output, got %d bytes", len(data))
	}
	out := string(data)
	if !strings.Contains(out, "/api/users") {
		t.Errorf("expected the fixture's route in the output; got:\n%s", out)
	}
}
