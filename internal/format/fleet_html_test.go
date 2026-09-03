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

	out, err := FleetHTML(agg, nil, nil)
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

// A target's Error field is captured stderr from another process
// (docs/adr/0018-fleet-scanning.md's stderr tail) — exactly the kind of
// untrusted content that must never be interpretable as markup by a viewer
// opening fleet.html.
func TestFleetHTMLEscapesHostileContent(t *testing.T) {
	agg := &fleet.Aggregate{Targets: []fleet.TargetResult{
		{Name: "<script>evil</script>", Status: fleet.StatusFailed, Error: "<img src=x onerror=alert(1)>"},
	}}

	out, err := FleetHTML(agg, nil, nil)
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

	out, err := FleetHTML(agg, delta, nil)
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
	out, err := FleetHTML(agg, nil, nil)
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
	scope := &FleetScope{Org: "myorg", MaxRepos: 100, Concurrency: 3, RepoInclude: []string{"svc-*"}}

	out, err := FleetHTML(agg, nil, scope)
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
	out, err := FleetHTML(agg, nil, nil)
	if err != nil {
		t.Fatalf("FleetHTML: unexpected error: %v", err)
	}
	if strings.Contains(string(out), "GitHub organization inventory") {
		t.Error("expected no org-scope hero copy for a plain --targets run")
	}
}

func TestFleetHTMLIncludesFilterControls(t *testing.T) {
	agg := &fleet.Aggregate{Targets: []fleet.TargetResult{{Name: "svc-a", Status: fleet.StatusOK}}}
	out, err := FleetHTML(agg, nil, nil)
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

func TestFleetHTMLOmitsReportLinkWhenAbsent(t *testing.T) {
	agg := &fleet.Aggregate{Targets: []fleet.TargetResult{
		{Name: "not-a-module", Status: fleet.StatusNotGoModule, Complete: true},
	}}
	out, err := FleetHTML(agg, nil, nil)
	if err != nil {
		t.Fatalf("FleetHTML: unexpected error: %v", err)
	}
	if strings.Contains(string(out), `href=""`) {
		t.Error("expected no href attribute for a target with no report path")
	}
}
