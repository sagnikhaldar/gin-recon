package format

import (
	"strings"
	"testing"

	"github.com/sagnikhaldar/gin-recon/internal/fleet"
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
// TestFleetHTMLExplainsZeroRouteOKTargets is a regression test for a real
// live finding: several "ok" targets in a real org scan showed 0 routes
// with no bug at all — they're shared libraries other services import and
// mount routes from (gin-recon scans one repository at a time), or use a
// different web framework entirely. Confirmed by inspecting real source
// (las-be-lender-bfin's webhook.Init(router *gin.RouterGroup, ...) only
// registers routes once imported and called by las-be-flow, which is
// where those exact routes are already counted). Rather than leave a
// reader to reverse-engineer that, the dashboard must say so directly.
func TestFleetHTMLExplainsZeroRouteOKTargets(t *testing.T) {
	agg := &fleet.Aggregate{Targets: []fleet.TargetResult{
		{Name: "svc-a", Status: fleet.StatusOK, Routes: 0},
		{Name: "svc-b", Status: fleet.StatusOK, Routes: 5},
		{Name: "svc-c", Status: fleet.StatusFailed},
		{Name: "svc-d", Status: fleet.StatusNotGoModule},
	}}

	out, err := FleetHTML(agg, nil, nil, "../out")
	if err != nil {
		t.Fatalf("FleetHTML: unexpected error: %v", err)
	}
	html := string(out)
	if !strings.Contains(html, "0*</span>") {
		t.Errorf("expected the 0* mark for svc-a\n%s", html)
	}
	if !strings.Contains(html, "1 target scanned cleanly but found no routes") {
		t.Errorf("expected the zero-route explainer note counting exactly 1\n%s", html)
	}
	if strings.Contains(html, ">5</span>") && strings.Contains(html, "5*") {
		t.Errorf("svc-b has real routes and must not get the 0* mark\n%s", html)
	}
}

// TestFleetHTMLOmitsZeroRouteNoteWhenNotApplicable confirms the note
// doesn't appear at all when nothing would need it.
func TestFleetHTMLOmitsZeroRouteNoteWhenNotApplicable(t *testing.T) {
	agg := &fleet.Aggregate{Targets: []fleet.TargetResult{{Name: "svc-a", Status: fleet.StatusOK, Routes: 5}}}

	out, err := FleetHTML(agg, nil, nil, "../out")
	if err != nil {
		t.Fatalf("FleetHTML: unexpected error: %v", err)
	}
	if strings.Contains(string(out), "found no routes of their own") {
		t.Errorf("should not show the zero-route note when no target needs it\n%s", out)
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
	agg := &fleet.Aggregate{Targets: []fleet.TargetResult{{Name: "svc-a", Status: fleet.StatusOK}}}
	out, err := FleetHTML(agg, nil, nil, "../out")
	if err != nil {
		t.Fatalf("FleetHTML: unexpected error: %v", err)
	}
	html := string(out)
	for _, want := range []string{"data-gr-filter-search", "data-gr-filter-status", "data-gr-search=", "function update"} {
		if !strings.Contains(html, want) {
			t.Errorf("output missing %q", want)
		}
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
