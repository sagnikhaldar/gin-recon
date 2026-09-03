package fleet

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/sagnikhaldar/gin-recon/internal/model"
	"github.com/sagnikhaldar/gin-recon/internal/report"
)

func writeTargetReport(t *testing.T, outDir, name string, rep *report.Report) {
	t.Helper()
	dir := filepath.Join(outDir, "targets", name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "routes.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func auditReportWithRoutes(routes ...model.Route) *report.Report {
	rep := report.NewAuditReport(
		model.ProfileTyped,
		report.Target{Module: "fixture", BuildContext: model.BuildContext{GOOS: "linux", GOARCH: "amd64"}},
		report.Summary{},
		nil,
		report.PolicyEvaluation{},
		nil,
	)
	rep.Routes = routes
	return rep
}

func provenRoute(method, path string) model.Route {
	return model.Route{
		Method:         method,
		NormalizedPath: path,
		Auth:           &model.AuthClassification{AuthStatus: model.AuthProven},
	}
}

func publicRoute(method, path string) model.Route {
	return model.Route{
		Method:         method,
		NormalizedPath: path,
		Auth:           &model.AuthClassification{AuthStatus: model.AuthPublic},
	}
}

func writeBaselineFleetJSON(t *testing.T, dir string, targets []TargetResult) string {
	t.Helper()
	agg := &Aggregate{Targets: targets}
	data, err := json.Marshal(agg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "fleet.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCompareBaselineDetectsAddedAndRemovedTargets(t *testing.T) {
	baselineDir := t.TempDir()
	writeTargetReport(t, baselineDir, "svc-a", auditReportWithRoutes(provenRoute("GET", "/a")))
	baselinePath := writeBaselineFleetJSON(t, baselineDir, []TargetResult{
		{Name: "svc-a", Status: StatusOK, Complete: true, Report: "targets/svc-a/routes.json"},
		{Name: "svc-removed", Status: StatusOK, Complete: true, Report: "targets/svc-removed/routes.json"},
	})
	baseline, err := LoadBaseline(baselinePath)
	if err != nil {
		t.Fatal(err)
	}

	currentDir := t.TempDir()
	writeTargetReport(t, currentDir, "svc-a", auditReportWithRoutes(provenRoute("GET", "/a")))
	writeTargetReport(t, currentDir, "svc-new", auditReportWithRoutes(provenRoute("GET", "/new")))
	current := []TargetResult{
		{Name: "svc-a", Status: StatusOK, Complete: true},
		{Name: "svc-new", Status: StatusOK, Complete: true},
	}

	fd, err := CompareBaseline(baseline, currentDir, current)
	if err != nil {
		t.Fatalf("CompareBaseline: %v", err)
	}
	if fd.Summary.AddedTargets != 1 || fd.Summary.RemovedTargets != 1 {
		t.Fatalf("Summary = %+v", fd.Summary)
	}
	if !fd.HasNew() {
		t.Error("HasNew() = false, want true: svc-new was added")
	}
}

func TestCompareBaselineDetectsRouteAndAuthChanges(t *testing.T) {
	baselineDir := t.TempDir()
	writeTargetReport(t, baselineDir, "svc-a", auditReportWithRoutes(
		provenRoute("GET", "/a"),
		provenRoute("GET", "/removed"),
	))
	baselinePath := writeBaselineFleetJSON(t, baselineDir, []TargetResult{
		{Name: "svc-a", Status: StatusOK, Complete: true},
	})
	baseline, err := LoadBaseline(baselinePath)
	if err != nil {
		t.Fatal(err)
	}

	currentDir := t.TempDir()
	writeTargetReport(t, currentDir, "svc-a", auditReportWithRoutes(
		publicRoute("GET", "/a"), // regression: proven -> public
		provenRoute("GET", "/added"),
	))
	current := []TargetResult{{Name: "svc-a", Status: StatusOK, Complete: true}}

	fd, err := CompareBaseline(baseline, currentDir, current)
	if err != nil {
		t.Fatalf("CompareBaseline: %v", err)
	}
	if fd.Summary.AddedRoutes != 1 || fd.Summary.RemovedRoutes != 1 || fd.Summary.AuthRegressions != 1 {
		t.Fatalf("Summary = %+v", fd.Summary)
	}
	if !fd.HasNew() {
		t.Error("HasNew() = false, want true: a route was added")
	}
	if !fd.HasRegression() {
		t.Error("HasRegression() = false, want true: GET /a went proven -> public")
	}
}

func TestCompareBaselineSkipsTargetsWithoutARealReport(t *testing.T) {
	baselineDir := t.TempDir()
	baselinePath := writeBaselineFleetJSON(t, baselineDir, []TargetResult{
		{Name: "not-go", Status: StatusNotGoModule, Complete: true},
	})
	baseline, err := LoadBaseline(baselinePath)
	if err != nil {
		t.Fatal(err)
	}

	current := []TargetResult{{Name: "not-go", Status: StatusNotGoModule, Complete: true}}
	fd, err := CompareBaseline(baseline, t.TempDir(), current)
	if err != nil {
		t.Fatalf("CompareBaseline: %v", err)
	}
	if len(fd.Targets) != 1 || fd.Targets[0].Status != TargetUnchanged || fd.Targets[0].Delta != nil {
		t.Fatalf("Targets = %+v, want one unchanged target with no delta", fd.Targets)
	}
	if fd.HasNew() || fd.HasRegression() {
		t.Error("expected no new/regression signal for a target with nothing to diff")
	}
}

// TestLoadBaselineSurvivesOverwriteOfSourcePath is a regression test caught
// by hand: --baseline pointing at a path inside the current run's own --out
// (a realistic setup with --force) must not silently compare the new run
// against itself once the current run overwrites that same path. Because
// LoadBaseline reads every target's report eagerly, before Run touches the
// filesystem, the in-memory Baseline must still reflect the original
// content even after the file on disk changes underneath it.
func TestLoadBaselineSurvivesOverwriteOfSourcePath(t *testing.T) {
	dir := t.TempDir()
	writeTargetReport(t, dir, "svc-a", auditReportWithRoutes(provenRoute("GET", "/a")))
	path := writeBaselineFleetJSON(t, dir, []TargetResult{
		{Name: "svc-a", Status: StatusOK, Complete: true},
	})

	baseline, err := LoadBaseline(path)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate the current run overwriting the exact same directory tree
	// after the baseline was loaded — this is what fleet.Run legitimately
	// does when --out and --baseline's directory coincide.
	writeTargetReport(t, dir, "svc-a", auditReportWithRoutes(
		provenRoute("GET", "/a"),
		provenRoute("GET", "/new-route"),
	))
	if err := os.WriteFile(path, []byte(`{"targets":[{"name":"svc-a","status":"ok","complete":true}]}`), 0o644); err != nil {
		t.Fatal(err)
	}

	current := []TargetResult{{Name: "svc-a", Status: StatusOK, Complete: true}}
	fd, err := CompareBaseline(baseline, dir, current)
	if err != nil {
		t.Fatalf("CompareBaseline: %v", err)
	}
	if fd.Summary.AddedRoutes != 1 {
		t.Fatalf("Summary = %+v, want AddedRoutes = 1 (the overwrite must not have erased the in-memory baseline)", fd.Summary)
	}
}

func TestCompareBaselineMarksIncompatibleReportsIncomparable(t *testing.T) {
	baselineDir := t.TempDir()
	baselineReport := auditReportWithRoutes(provenRoute("GET", "/a"))
	baselineReport.AnalysisProfile = model.ProfileSyntaxOnly
	writeTargetReport(t, baselineDir, "svc-a", baselineReport)
	baselinePath := writeBaselineFleetJSON(t, baselineDir, []TargetResult{
		{Name: "svc-a", Status: StatusOK, Complete: true},
	})
	baseline, err := LoadBaseline(baselinePath)
	if err != nil {
		t.Fatal(err)
	}

	currentDir := t.TempDir()
	writeTargetReport(t, currentDir, "svc-a", auditReportWithRoutes(provenRoute("GET", "/a"))) // typed profile
	current := []TargetResult{{Name: "svc-a", Status: StatusOK, Complete: true}}

	fd, err := CompareBaseline(baseline, currentDir, current)
	if err != nil {
		t.Fatalf("CompareBaseline: %v", err)
	}
	if len(fd.Targets) != 1 || fd.Targets[0].Status != TargetIncomparable || fd.Targets[0].Reason == "" {
		t.Fatalf("Targets = %+v, want one incomparable target with a reason", fd.Targets)
	}
	if fd.Summary.IncomparableTargets != 1 {
		t.Errorf("IncomparableTargets = %d, want 1", fd.Summary.IncomparableTargets)
	}
}
