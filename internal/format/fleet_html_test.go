package format

import (
	"strings"
	"testing"

	"github.com/sagnikhaldar/gin-recon/internal/fleet"
	"github.com/sagnikhaldar/gin-recon/internal/model"
	"github.com/sagnikhaldar/gin-recon/internal/report"
)

func TestFleetHTMLRendersTargets(t *testing.T) {
	agg := &fleet.Aggregate{
		Tool:        "gin-recon",
		ToolVersion: "0.1.0",
		Targets: []fleet.TargetResult{
			{Name: "svc-a", Src: "/repos/svc-a", Status: fleet.StatusOK, Complete: true, Report: "targets/svc-a/routes.json"},
			{Name: "svc-b", Src: "/repos/svc-b", Status: fleet.StatusFailed, Error: "audit exited 1"},
		},
	}
	agg.Coverage.Complete = false

	out, err := FleetHTML(agg, nil, nil, "../out")
	if err != nil {
		t.Fatalf("FleetHTML: unexpected error: %v", err)
	}
	html := string(out)
	for _, want := range []string{"svc-a", "svc-b", "targets/svc-a/routes.json", "audit exited 1", "gin-recon fleet report"} {
		if !strings.Contains(html, want) {
			t.Errorf("output missing %q\n%s", want, html)
		}
	}
}

// TestFleetHTMLRendersEvidenceMetricsAndBadges covers the richer dashboard
// docs/adr/0028-gin-recon-default-output-directory.md's fleet.html redesign
// added: a fleet-wide totals row and, per target, status/coverage badges
// plus route-evidence counts — gin-recon's own proven/public/unknown
// vocabulary (docs/adr/0008), not a copy of any sibling tool's own
// per-repository metrics.
// A zero-route process exit is not itself a clean Gin result. The reference
// table must distinguish complete Gin evidence from an incomplete scan and
// metadata-free legacy input instead of describing all three as clean.
func TestFleetHTMLSeparatesZeroRouteEvidence(t *testing.T) {
	agg := &fleet.Aggregate{Targets: []fleet.TargetResult{
		{Name: "svc-a", Status: fleet.StatusOK, Complete: true, Modules: []fleet.ModuleResult{{Kind: fleet.ModuleGinNoRoutes, Status: fleet.StatusOK, Complete: true}}},
		{Name: "svc-b", Status: fleet.StatusOK, Routes: 5},
		{Name: "svc-c", Status: fleet.StatusFailed},
		{Name: "svc-d", Status: fleet.StatusOK, Complete: false, Modules: []fleet.ModuleResult{{Kind: fleet.ModuleGinNoRoutes, Status: fleet.StatusOK, Complete: false}}},
		{Name: "legacy", Status: fleet.StatusOK, Complete: true},
	}}

	out, err := FleetHTML(agg, nil, nil, "../out")
	if err != nil {
		t.Fatalf("FleetHTML: unexpected error: %v", err)
	}
	html := string(out)
	if !strings.Contains(html, "Gin detected, no routes") {
		t.Errorf("expected complete Gin zero-route evidence to be labeled\n%s", html)
	}
	if got := strings.Count(html, "No routes, unverified</span>"); got != 2 {
		t.Errorf("unverified label count = %d, want 2 for incomplete and legacy results\n%s", got, html)
	}
	if strings.Contains(html, "scanned cleanly") {
		t.Errorf("incomplete or metadata-free zero-route results must not be called clean\n%s", html)
	}
}

func TestFleetHTMLKeepsFailedTargetWithObservedRoutesInPrimaryTable(t *testing.T) {
	agg := &fleet.Aggregate{Targets: []fleet.TargetResult{
		{Name: "partial-routes", Status: fleet.StatusFailed, Complete: false, Routes: 2, Error: "later module failed"},
		{Name: "failed-zero", Status: fleet.StatusFailed, Complete: false, Error: "clone failed"},
	}}

	out, err := FleetHTML(agg, nil, nil, "../out")
	if err != nil {
		t.Fatalf("FleetHTML: unexpected error: %v", err)
	}
	html := string(out)
	primaryStart := strings.Index(html, "id=\"gr-route-targets-table\"")
	referenceStart := strings.Index(html, "id=\"gr-reference-targets-table\"")
	if primaryStart < 0 || referenceStart < 0 || primaryStart >= referenceStart {
		t.Fatalf("expected separate primary and reference tables\n%s", html)
	}
	if !strings.Contains(html[primaryStart:referenceStart], "partial-routes") {
		t.Errorf("failed target with retained routes missing from primary table\n%s", html)
	}
	if strings.Contains(html[primaryStart:referenceStart], "failed-zero") {
		t.Errorf("zero-route failure leaked into primary table\n%s", html)
	}
	if !strings.Contains(html[referenceStart:], "failed-zero") {
		t.Errorf("zero-route failure missing from reference table\n%s", html)
	}
}

func TestFleetHTMLRendersEvidenceMetricsAndBadges(t *testing.T) {
	agg := &fleet.Aggregate{
		Tool:        "gin-recon",
		ToolVersion: "0.1.0",
		Targets: []fleet.TargetResult{
			{Name: "svc-a", Src: "/repos/svc-a", Status: fleet.StatusOK, Complete: true, Routes: 5, Proven: 3, Public: 1, Unknown: 1},
			{Name: "svc-b", Src: "/repos/svc-b", Status: fleet.StatusFailed, Error: "audit exited 1"},
		},
	}
	agg.Coverage.Complete = false
	agg.Totals.Routes = 5
	agg.Totals.Proven = 3
	agg.Totals.Public = 1
	agg.Totals.Unknown = 1

	out, err := FleetHTML(agg, nil, nil, "../out")
	if err != nil {
		t.Fatalf("FleetHTML: unexpected error: %v", err)
	}
	html := string(out)
	for _, want := range []string{
		`gr-badge--good">ok`,
		`gr-badge--bad">failed`,
		`gr-badge--good">complete`,
		`gr-badge--good">3</span>`,
		`gr-badge--warn">1</span>`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("output missing %q\n%s", want, html)
		}
	}
	if !strings.Contains(html, `<span class="gr-metric__value">5</span><span class="gr-metric__label">Routes</span>`) {
		t.Errorf("output missing the fleet-wide Routes metric tile\n%s", html)
	}
}

// TestFleetHTMLWarnsWhenNoAuthMiddlewareConfigured is a regression test for
// docs/adr/0030-fleet-html-auth-config-visibility.md: real live-org output
// showed Totals.Proven = 0 across every target, which reads as "gin-recon
// can't detect auth" unless the page also says the run's own --config never
// named a single authMiddleware entry — the actual, structural reason
// nothing could ever have been classified proven.
func TestFleetHTMLWarnsWhenNoAuthMiddlewareConfigured(t *testing.T) {
	agg := &fleet.Aggregate{Targets: []fleet.TargetResult{{Name: "svc-a", Status: fleet.StatusOK}}}

	out, err := FleetHTML(agg, nil, nil, "../out")
	if err != nil {
		t.Fatalf("FleetHTML: unexpected error: %v", err)
	}
	if !strings.Contains(string(out), "No <code>authMiddleware</code> configured") {
		t.Errorf("expected the no-authMiddleware note when AuthConfig.MiddlewareCount is zero\n%s", out)
	}
}

func TestFleetHTMLOmitsAuthMiddlewareWarningWhenConfigured(t *testing.T) {
	agg := &fleet.Aggregate{Targets: []fleet.TargetResult{{Name: "svc-a", Status: fleet.StatusOK, Proven: 3}}}
	agg.AuthConfig.MiddlewareCount = 2

	out, err := FleetHTML(agg, nil, nil, "../out")
	if err != nil {
		t.Fatalf("FleetHTML: unexpected error: %v", err)
	}
	if strings.Contains(string(out), "No <code>authMiddleware</code> configured") {
		t.Errorf("did not expect the no-authMiddleware note when AuthConfig.MiddlewareCount is non-zero\n%s", out)
	}
	if !strings.Contains(string(out), "<dt>authMiddleware configured</dt><dd>2</dd>") {
		t.Errorf("expected the Configuration panel to show the configured count\n%s", out)
	}
}

// TestFleetHTMLWarnsWhenNoFollowModulesConfigured is a regression test for
// docs/adr/0036-fleet-html-follow-modules-visibility.md: a target that
// imports and mounts another module's own routes (las-be-flow calling
// las-be-lender-bfin's own Init(router, ...), confirmed by reading real
// source) won't have those routes counted at all without
// analysis.followModules — a second silently-narrowing config knob,
// alongside authMiddleware, that must not be left for a reader to
// discover only by noticing a route-count gap.
func TestFleetHTMLWarnsWhenNoFollowModulesConfigured(t *testing.T) {
	agg := &fleet.Aggregate{Targets: []fleet.TargetResult{{Name: "svc-a", Status: fleet.StatusOK}}}

	out, err := FleetHTML(agg, nil, nil, "../out")
	if err != nil {
		t.Fatalf("FleetHTML: unexpected error: %v", err)
	}
	if !strings.Contains(string(out), "won't have those routes counted at all without this") {
		t.Errorf("expected the no-followModules explanation when FollowModulesCount is zero\n%s", out)
	}
}

func TestFleetHTMLOmitsFollowModulesWarningWhenConfigured(t *testing.T) {
	agg := &fleet.Aggregate{Targets: []fleet.TargetResult{{Name: "svc-a", Status: fleet.StatusOK}}}
	agg.FollowModulesCount = 1

	out, err := FleetHTML(agg, nil, nil, "../out")
	if err != nil {
		t.Fatalf("FleetHTML: unexpected error: %v", err)
	}
	if strings.Contains(string(out), "won't have those routes counted at all without this") {
		t.Errorf("did not expect the no-followModules explanation when FollowModulesCount is non-zero\n%s", out)
	}
	if !strings.Contains(string(out), "<dt>analysis.followModules configured</dt><dd>1</dd>") {
		t.Errorf("expected the Configuration panel to show the configured count\n%s", out)
	}
}

// TestFleetHTMLRendersOwnConfigBadge is a regression test for
// docs/adr/0031-fleet-per-target-config.md: a target that used its own
// committed config (--use-target-config) must be visibly distinguishable
// from one classified against the fleet-wide --config, given the two carry
// different trust provenance.
func TestFleetHTMLRendersOwnConfigBadge(t *testing.T) {
	agg := &fleet.Aggregate{Targets: []fleet.TargetResult{
		{Name: "svc-a", Status: fleet.StatusOK, TargetConfig: true},
		{Name: "svc-b", Status: fleet.StatusOK},
	}}

	out, err := FleetHTML(agg, nil, nil, "../out")
	if err != nil {
		t.Fatalf("FleetHTML: unexpected error: %v", err)
	}
	html := string(out)
	if !strings.Contains(html, `own config (repo)</span>`) {
		t.Errorf("expected an own-config badge for svc-a\n%s", html)
	}
	if !strings.Contains(html, "Targets using their own repo-committed config</dt><dd>1 of 2") {
		t.Errorf("expected the Configuration panel to report 1 of 2 targets using their own repo-committed config\n%s", html)
	}
}

// TestFleetHTMLRendersOwnConfigDirBadge covers --target-config-dir
// (docs/adr/0033-fleet-target-config-dir.md): visibly distinct from the
// repo-committed variant, and takes precedence when both would apply.
func TestFleetHTMLRendersOwnConfigDirBadge(t *testing.T) {
	agg := &fleet.Aggregate{Targets: []fleet.TargetResult{
		{Name: "svc-a", Status: fleet.StatusOK, TargetConfigDir: true},
		{Name: "svc-b", Status: fleet.StatusOK, TargetConfig: true},
	}}

	out, err := FleetHTML(agg, nil, nil, "../out")
	if err != nil {
		t.Fatalf("FleetHTML: unexpected error: %v", err)
	}
	html := string(out)
	if !strings.Contains(html, `own config (dir)</span>`) {
		t.Errorf("expected an own-config-dir badge for svc-a\n%s", html)
	}
	if !strings.Contains(html, "Targets using an operator-owned config</dt><dd>1 of 2") {
		t.Errorf("expected the Configuration panel to report 1 of 2 targets using an operator-owned config\n%s", html)
	}
}

// TestFleetHTMLOmitsOwnConfigRollupWhenUnused confirms the rollup lines
// themselves don't show up as a confusing "0 of N" when neither
// --use-target-config nor --target-config-dir was ever in play.
func TestFleetHTMLOmitsOwnConfigRollupWhenUnused(t *testing.T) {
	agg := &fleet.Aggregate{Targets: []fleet.TargetResult{{Name: "svc-a", Status: fleet.StatusOK}}}

	out, err := FleetHTML(agg, nil, nil, "../out")
	if err != nil {
		t.Fatalf("FleetHTML: unexpected error: %v", err)
	}
	if strings.Contains(string(out), "own repo-committed config") || strings.Contains(string(out), "operator-owned config") {
		t.Errorf("should not mention own-config usage when no target used one\n%s", out)
	}
}

// TestFleetHTMLRendersEnumerationCoverage covers the Scope panel's new
// "Enumeration coverage" row (docs/adr/0030-fleet-html-auth-config-visibility.md):
// an --org run that hit --max-repos/the page cap should read as incomplete
// distinctly from an unrelated target scan failure, not just fold silently
// into the same Coverage-complete metric tile.
func TestFleetHTMLRendersEnumerationCoverage(t *testing.T) {
	agg := &fleet.Aggregate{Targets: []fleet.TargetResult{{Name: "svc-a", Status: fleet.StatusOK}}}
	scope := &fleet.Scope{Org: "myorg", DiscoveryComplete: false, DiscoveryCompleteKnown: true}

	out, err := FleetHTML(agg, nil, scope, "../out")
	if err != nil {
		t.Fatalf("FleetHTML: unexpected error: %v", err)
	}
	if !strings.Contains(string(out), `<dt>Enumeration coverage</dt><dd><span class="gr-badge gr-badge--warn">incomplete</span></dd>`) {
		t.Errorf("expected an incomplete Enumeration coverage badge\n%s", out)
	}
}

// TestFleetHTMLOmitsEnumerationCoverageWhenUnknown is a regression test for
// a real mistake caught before it shipped: rendering an old fleet.json that
// predates DiscoveryComplete would otherwise unmarshal its Go zero value
// (false) and confidently claim "incomplete" about a run that was never
// actually checked. DiscoveryCompleteKnown must gate the row entirely.
func TestFleetHTMLOmitsEnumerationCoverageWhenUnknown(t *testing.T) {
	agg := &fleet.Aggregate{Targets: []fleet.TargetResult{{Name: "svc-a", Status: fleet.StatusOK}}}
	scope := &fleet.Scope{Org: "myorg"} // DiscoveryComplete/DiscoveryCompleteKnown both zero-valued, as an old fleet.json would decode

	out, err := FleetHTML(agg, nil, scope, "../out")
	if err != nil {
		t.Fatalf("FleetHTML: unexpected error: %v", err)
	}
	if strings.Contains(string(out), "Enumeration coverage") {
		t.Errorf("should not claim any enumeration coverage state when it was never recorded\n%s", out)
	}
}

// A target's Error field is captured stderr from another process
// (docs/adr/0018-fleet-scanning.md's stderr tail) — exactly the kind of
// untrusted content that must never be interpretable as markup by a viewer
// opening fleet.html.
func TestFleetHTMLEscapesHostileContent(t *testing.T) {
	agg := &fleet.Aggregate{Targets: []fleet.TargetResult{
		{Name: "<script>evil</script>", Status: fleet.StatusFailed, Error: "<img src=x onerror=alert(1)>"},
	}}

	out, err := FleetHTML(agg, nil, nil, "../out")
	if err != nil {
		t.Fatalf("FleetHTML: unexpected error: %v", err)
	}
	html := string(out)
	if strings.Contains(html, "<script>evil</script>") {
		t.Error("target name was not HTML-escaped")
	}
	if strings.Contains(html, "<img src=x onerror=alert(1)>") {
		t.Error("target error was not HTML-escaped")
	}
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Error("expected the escaped form of the hostile target name to be present")
	}
}

func TestFleetHTMLRendersDeltaWhenPresent(t *testing.T) {
	agg := &fleet.Aggregate{Targets: []fleet.TargetResult{{Name: "svc-a", Status: fleet.StatusOK}}}
	delta := &fleet.FleetDelta{Targets: []fleet.TargetDelta{
		{Name: "svc-a", Status: fleet.TargetUnchanged, Delta: &report.Delta{AddedRoutes: []string{"GET /new"}}},
	}}
	delta.Summary.AddedRoutes = 1

	out, err := FleetHTML(agg, delta, nil, "../out")
	if err != nil {
		t.Fatalf("FleetHTML: unexpected error: %v", err)
	}
	html := string(out)
	for _, want := range []string{"Baseline comparison", "GET /new", "Added routes"} {
		if !strings.Contains(html, want) {
			t.Errorf("output missing %q\n%s", want, html)
		}
	}
}

func TestFleetHTMLOmitsDeltaSectionWhenAbsent(t *testing.T) {
	agg := &fleet.Aggregate{Targets: []fleet.TargetResult{{Name: "svc-a", Status: fleet.StatusOK}}}
	out, err := FleetHTML(agg, nil, nil, "../out")
	if err != nil {
		t.Fatalf("FleetHTML: unexpected error: %v", err)
	}
	if strings.Contains(string(out), "Baseline comparison") {
		t.Error("expected no baseline-comparison section when no delta was given")
	}
}

func TestFleetHTMLRendersScopeForOrgRun(t *testing.T) {
	agg := &fleet.Aggregate{Targets: []fleet.TargetResult{
		{Name: "svc-a", GitURL: "https://github.com/myorg/svc-a.git", Status: fleet.StatusOK},
	}}
	scope := &fleet.Scope{Org: "myorg", MaxRepos: 100, Concurrency: 3, RepoInclude: []string{"svc-*"}}

	out, err := FleetHTML(agg, nil, scope, "../out")
	if err != nil {
		t.Fatalf("FleetHTML: unexpected error: %v", err)
	}
	html := string(out)
	for _, want := range []string{"myorg", "GitHub organization inventory", "Scope", "svc-*", "https://github.com/myorg/svc-a.git"} {
		if !strings.Contains(html, want) {
			t.Errorf("output missing %q\n%s", want, html)
		}
	}
}

func TestFleetHTMLMakesArchivedAndForkOptInsProminent(t *testing.T) {
	agg := &fleet.Aggregate{Targets: []fleet.TargetResult{{Name: "svc-a", Status: fleet.StatusNotGoModule, Complete: true}}}
	scope := &fleet.Scope{Org: "myorg", IncludeArchived: true, IncludeForks: true}

	out, err := FleetHTML(agg, nil, scope, "../out")
	if err != nil {
		t.Fatalf("FleetHTML: unexpected error: %v", err)
	}
	html := string(out)
	for _, want := range []string{
		"Expanded repository scope.",
		"explicit <code>--include-archived</code> opt-in",
		"explicit <code>--include-forks</code> opt-in",
		"report has not silently removed them",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("output missing %q\n%s", want, html)
		}
	}
}

func TestFleetHTMLShowsDefaultArchivedAndForkExclusions(t *testing.T) {
	agg := &fleet.Aggregate{Targets: []fleet.TargetResult{{Name: "svc-a", Status: fleet.StatusNotGoModule, Complete: true}}}
	scope := &fleet.Scope{Org: "myorg"}

	out, err := FleetHTML(agg, nil, scope, "../out")
	if err != nil {
		t.Fatalf("FleetHTML: unexpected error: %v", err)
	}
	html := string(out)
	if got := strings.Count(html, "excluded (default)"); got != 2 {
		t.Errorf("default exclusion label count = %d, want 2\n%s", got, html)
	}
	if strings.Contains(html, "Expanded repository scope.") {
		t.Errorf("default scope must not be described as expanded\n%s", html)
	}
}

func TestFleetHTMLSeparatesAndEscapesDiscoveryDispositions(t *testing.T) {
	agg := &fleet.Aggregate{Targets: []fleet.TargetResult{{Name: "selected", Status: fleet.StatusNotGoModule, Complete: true}}}
	scope := &fleet.Scope{
		Org: "myorg",
		Discovery: &fleet.DiscoverySummary{Repositories: []fleet.RepositoryDisposition{
			{FullName: "myorg/selected", Status: "selected"},
			{FullName: "<script>omitted</script>", Status: "filtered", Reason: "<img src=x onerror=alert(1)>"},
		}},
	}

	out, err := FleetHTML(agg, nil, scope, "../out")
	if err != nil {
		t.Fatalf("FleetHTML: unexpected error: %v", err)
	}
	html := string(out)
	if !strings.Contains(html, "Discovery dispositions not audited (1)") ||
		!strings.Contains(html, "discovery decisions, not fabricated audit results") {
		t.Errorf("expected a separately identified discovery-disposition table\n%s", html)
	}
	if strings.Contains(html, "<script>omitted</script>") || strings.Contains(html, "<img src=x onerror=alert(1)>") {
		t.Errorf("discovery disposition content was not escaped\n%s", html)
	}
	if strings.Contains(html, "<code>myorg/selected</code>") {
		t.Errorf("selected repository should not appear in the not-audited disposition table\n%s", html)
	}
}

func TestFleetHTMLOmitsScopeForTargetsRun(t *testing.T) {
	agg := &fleet.Aggregate{Targets: []fleet.TargetResult{{Name: "svc-a", Status: fleet.StatusOK}}}
	out, err := FleetHTML(agg, nil, nil, "../out")
	if err != nil {
		t.Fatalf("FleetHTML: unexpected error: %v", err)
	}
	if strings.Contains(string(out), "GitHub organization inventory") {
		t.Error("expected no org-scope hero copy for a plain --targets run")
	}
}

func TestFleetHTMLIncludesFilterControls(t *testing.T) {
	agg := &fleet.Aggregate{Targets: []fleet.TargetResult{
		{Name: "svc-a", Status: fleet.StatusOK, Routes: 1},
		{Name: "svc-b", Status: fleet.StatusNotGoModule, Complete: true},
	}}
	out, err := FleetHTML(agg, nil, nil, "../out")
	if err != nil {
		t.Fatalf("FleetHTML: unexpected error: %v", err)
	}
	html := string(out)
	for _, want := range []string{
		"data-gr-filter=\"gr-route-targets-table\"",
		"data-gr-filter=\"gr-reference-targets-table\"",
		"data-gr-filter-search",
		"data-gr-filter-status",
		"data-gr-filter-category",
		"data-gr-filter-completion",
		"data-gr-filter-evidence",
		"data-gr-filter-framework",
		"data-gr-filter-docs",
		"data-gr-filter-clear",
		"data-gr-filter-empty",
		"data-gr-group=\"complete\"",
		"data-gr-group=\"incomplete\"",
		"data-gr-search=",
		"function update",
		"group.hidden = !rows.some",
		`target.tagName === "DETAILS"`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("output missing %q", want)
		}
	}
	if strings.Contains(html, ">Reset<") || strings.Contains(html, "Reset filters") {
		t.Errorf("output still contains standalone reset controls")
	}
}

func TestFleetHTMLRendersSavedSpecificationChooserAndSeparateMetrics(t *testing.T) {
	catalog := &model.SpecificationCatalog{Status: "complete", Specifications: []model.SpecificationRecord{{ID: "one", Path: "api/openapi.yaml", Dialect: "openapi3", Version: "3.1.0", Title: "Payments", APIVersion: "v2", Authorship: "authored", SHA256: strings.Repeat("a", 64)}}, Metrics: model.DocumentationMetrics{SourceFiles: model.DocumentationMetric{Numerator: 205, Denominator: 205, Status: "complete"}, ObservedOperations: model.DocumentationMetric{Numerator: 66, Denominator: 287, Status: "complete"}, IncompleteScope: true}}
	agg := &fleet.Aggregate{Targets: []fleet.TargetResult{{Name: "svc", Status: fleet.StatusOK, Complete: false, Routes: 287, Specifications: []fleet.ModuleSpecificationSummary{{ModuleID: "root", ModulePath: "example.com/svc", Catalog: catalog}}}}}
	out, err := FleetHTML(agg, nil, nil, "../out")
	if err != nil {
		t.Fatal(err)
	}
	html := string(out)
	for _, want := range []string{"data-gr-docs=\"openapi3\"", "Payments v2 · openapi3 3.1.0", "source files 100.0% (205/205)", "observed API operations documented 23.0% (66/287)", "incomplete scope"} {
		if !strings.Contains(html, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestFleetHTMLMissingDenominatorsAreNA(t *testing.T) {
	catalog := &model.SpecificationCatalog{Status: "complete", Specifications: []model.SpecificationRecord{}, Metrics: model.DocumentationMetrics{SourceFiles: model.DocumentationMetric{Status: "unknown"}, ObservedOperations: model.DocumentationMetric{Status: "unknown"}}}
	agg := &fleet.Aggregate{Targets: []fleet.TargetResult{{Name: "empty", Status: fleet.StatusOK, Specifications: []fleet.ModuleSpecificationSummary{{ModuleID: "root", ModulePath: "example.com/empty", Catalog: catalog}}}}}
	out, err := FleetHTML(agg, nil, nil, "../out")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(out), "N/A") < 2 {
		t.Fatalf("missing N/A metrics: %s", out)
	}
}

func TestFleetHTMLDoesNotContradictTargetSpecificAuthEvidence(t *testing.T) {
	agg := &fleet.Aggregate{Targets: []fleet.TargetResult{
		{Name: "svc-a", Status: fleet.StatusOK, Complete: true, Routes: 2, Proven: 2, TargetConfigDir: true},
	}}
	agg.Totals.Routes = 2
	agg.Totals.Proven = 2

	out, err := FleetHTML(agg, nil, nil, "../out")
	if err != nil {
		t.Fatalf("FleetHTML: unexpected error: %v", err)
	}
	html := string(out)
	if strings.Contains(html, "Every route below defaults to") {
		t.Errorf("fleet-wide zero authMiddleware must not contradict target-specific proven evidence\n%s", html)
	}
	if !strings.Contains(html, `gr-badge--good">2</span> proven`) {
		t.Errorf("expected proven route evidence rollup\n%s", html)
	}
}

func TestFleetHTMLTreatsCompleteNonGoResultAsCompleteOutcome(t *testing.T) {
	agg := &fleet.Aggregate{Targets: []fleet.TargetResult{
		{Name: "docs-only", Status: fleet.StatusNotGoModule, Complete: true},
	}}

	out, err := FleetHTML(agg, nil, nil, "../out")
	if err != nil {
		t.Fatalf("FleetHTML: unexpected error: %v", err)
	}
	html := string(out)
	if !strings.Contains(html, `<span class="gr-metric__value">1</span><span class="gr-metric__label">Complete targets</span>`) ||
		!strings.Contains(html, `gr-badge--neutral">not-go-module</span> <span class="gr-badge gr-badge--good">complete</span>`) {
		t.Errorf("complete non-Go classification rendered as incomplete\n%s", html)
	}
}

// TestFleetHTMLLinksAcrossTheRawRenderedSplit is a regression test for
// docs/adr/0023-fleet-raw-rendered-split.md: fleet.html now lives in a
// sibling <out>-html directory, so its link to a target's raw routes.json
// must cross back into --out using the caller-supplied prefix, while its
// link to that target's own api.html (already moved into the same
// directory tree as fleet.html itself) stays a plain same-directory
// relative link.
func TestFleetHTMLLinksAcrossTheRawRenderedSplit(t *testing.T) {
	agg := &fleet.Aggregate{Targets: []fleet.TargetResult{
		{Name: "svc-a", Status: fleet.StatusOK, Report: "targets/svc-a/routes.json", APIHTML: "targets/svc-a/api.html"},
	}}
	out, err := FleetHTML(agg, nil, nil, "../scan")
	if err != nil {
		t.Fatalf("FleetHTML: unexpected error: %v", err)
	}
	html := string(out)
	if !strings.Contains(html, `href="../scan/targets/svc-a/routes.json"`) {
		t.Errorf("routes.json link did not cross into the raw directory via the supplied prefix:\n%s", html)
	}
	if !strings.Contains(html, `href="targets/svc-a/api.html"`) {
		t.Errorf("api.html link should stay relative to fleet.html's own directory:\n%s", html)
	}
}

func TestFleetHTMLOmitsAPIHTMLLinkWhenAbsent(t *testing.T) {
	agg := &fleet.Aggregate{Targets: []fleet.TargetResult{
		{Name: "svc-a", Status: fleet.StatusOK, Report: "targets/svc-a/routes.json"},
	}}
	out, err := FleetHTML(agg, nil, nil, "../scan")
	if err != nil {
		t.Fatalf("FleetHTML: unexpected error: %v", err)
	}
	if strings.Contains(string(out), "api.html") {
		t.Error("expected no api.html link for a target that never produced one")
	}
}

func TestFleetHTMLOmitsReportLinkWhenAbsent(t *testing.T) {
	agg := &fleet.Aggregate{Targets: []fleet.TargetResult{
		{Name: "not-a-module", Status: fleet.StatusNotGoModule, Complete: true},
	}}
	out, err := FleetHTML(agg, nil, nil, "../out")
	if err != nil {
		t.Fatalf("FleetHTML: unexpected error: %v", err)
	}
	if strings.Contains(string(out), `href=""`) {
		t.Error("expected no href attribute for a target with no report path")
	}
}
