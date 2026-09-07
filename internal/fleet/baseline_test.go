package fleet

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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

// TestLoadBaselineRejectsPathTraversalTargetName is a regression test for a
// real path-traversal read: --baseline is an arbitrary file, and before this
// fix a target's Name field was used to build the path to its routes.json
// with no validation — a crafted name like "../../../../etc/passwd" would
// have loadTargetReport attempt to read arbitrary files outside the
// baseline's own directory tree as if they were a target's report.
func TestLoadBaselineRejectsPathTraversalTargetName(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fleet.json")
	fleetJSON := `{"targets":[{"name":"../../../../etc/passwd","status":"ok"}]}`
	if err := os.WriteFile(path, []byte(fleetJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadBaseline(path); err == nil {
		t.Fatal("LoadBaseline succeeded with a path-traversal target name, want an error")
	} else if !strings.Contains(err.Error(), "must match") {
		t.Errorf("LoadBaseline error = %v, want it to reject the invalid target name", err)
	}
}

// TestLoadBaselineRejectsDuplicateTargetNames guards against two targets in
// one --baseline file sharing a name, which would otherwise let the second
// silently shadow the first in Baseline.Reports.
func TestLoadBaselineRejectsDuplicateTargetNames(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fleet.json")
	fleetJSON := `{"targets":[{"name":"svc-a","status":"ok"},{"name":"svc-a","status":"ok"}]}`
	if err := os.WriteFile(path, []byte(fleetJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadBaseline(path); err == nil {
		t.Fatal("LoadBaseline succeeded with duplicate target names, want an error")
	} else if !strings.Contains(err.Error(), "duplicate target name") {
		t.Errorf("LoadBaseline error = %v, want it to reject the duplicate target name", err)
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

func TestCompareBaselineRecordsStatusTransitionAsIncomparable(t *testing.T) {
	baselineDir := t.TempDir()
	baselinePath := writeBaselineFleetJSON(t, baselineDir, []TargetResult{{
		Name: "svc-a", Status: StatusFailed, Complete: false,
	}})
	baseline, err := LoadBaseline(baselinePath)
	if err != nil {
		t.Fatal(err)
	}
	fd, err := CompareBaseline(baseline, t.TempDir(), []TargetResult{{
		Name: "svc-a", Status: StatusNotGoModule, Complete: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(fd.Targets) != 1 || fd.Targets[0].Status != TargetStatusChanged {
		t.Fatalf("targets = %+v, want explicit status change", fd.Targets)
	}
	if fd.Targets[0].BeforeStatus != StatusFailed || fd.Targets[0].AfterStatus != StatusNotGoModule {
		t.Fatalf("status transition = %+v", fd.Targets[0])
	}
	if fd.Coverage.Complete || fd.Summary.IncomparableTargets != 1 || fd.Summary.StatusChanges != 1 {
		t.Fatalf("coverage/summary = %+v / %+v", fd.Coverage, fd.Summary)
	}
}

func TestCompareFleetBaselineRejectsScopeOrScanMismatch(t *testing.T) {
	baseline := &Baseline{Aggregate: &Aggregate{ScopeFingerprint: "org-a", ScanFingerprint: "scan-a"}, Reports: map[string]*report.Report{}}
	for _, current := range []*Aggregate{
		{ScopeFingerprint: "org-b", ScanFingerprint: "scan-a"},
		{ScopeFingerprint: "org-a", ScanFingerprint: "scan-b"},
	} {
		if _, err := CompareFleetBaseline(baseline, t.TempDir(), current); err == nil {
			t.Fatalf("comparison accepted mismatched fingerprints: %+v", current)
		}
	}
}

func TestCompareFleetBaselineKeepsModuleRouteIdentitiesSeparate(t *testing.T) {
	baselineDir := t.TempDir()
	currentDir := t.TempDir()
	beforeModules := []ModuleResult{
		{ID: "module-0123456789abcdef", Path: "apps/a", Status: StatusOK, Complete: true, Report: "targets/repo/modules/module-0123456789abcdef/routes.json"},
		{ID: "module-fedcba9876543210", Path: "apps/b", Status: StatusOK, Complete: true, Report: "targets/repo/modules/module-fedcba9876543210/routes.json"},
	}
	afterModules := append([]ModuleResult(nil), beforeModules...)
	for _, fixture := range []struct {
		root string
		path string
		rep  *report.Report
	}{
		{baselineDir, beforeModules[0].Report, auditReportWithRoutes(provenRoute("GET", "/same"))},
		{baselineDir, beforeModules[1].Report, auditReportWithRoutes(provenRoute("GET", "/same"))},
		{currentDir, afterModules[0].Report, auditReportWithRoutes(publicRoute("GET", "/same"))},
		{currentDir, afterModules[1].Report, auditReportWithRoutes(provenRoute("GET", "/same"))},
	} {
		path := filepath.Join(fixture.root, filepath.FromSlash(fixture.path))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(fixture.rep)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	baseAgg := &Aggregate{Targets: []TargetResult{{Name: "repo", Status: StatusOK, Complete: true, Modules: beforeModules}}}
	baseData, _ := json.Marshal(baseAgg)
	basePath := filepath.Join(baselineDir, "fleet.json")
	if err := os.WriteFile(basePath, baseData, 0o644); err != nil {
		t.Fatal(err)
	}
	baseline, err := LoadBaseline(basePath)
	if err != nil {
		t.Fatal(err)
	}
	current := &Aggregate{Targets: []TargetResult{{Name: "repo", Status: StatusOK, Complete: true, Modules: afterModules}}}
	fd, err := CompareFleetBaseline(baseline, currentDir, current)
	if err != nil {
		t.Fatal(err)
	}
	if fd.Summary.AuthRegressions != 1 || len(fd.Targets[0].Modules) != 2 {
		t.Fatalf("module-aware delta = %+v", fd)
	}
}

func TestCompareFleetBaselineTreatsZeroRouteModuleAdditionAsNew(t *testing.T) {
	baseline := &Baseline{
		Aggregate: &Aggregate{Targets: []TargetResult{{Name: "repo", Status: StatusOK, Complete: true}}},
		Reports:   map[string]*report.Report{},
	}
	current := &Aggregate{Targets: []TargetResult{{
		Name: "repo", Status: StatusOK, Complete: true,
		Modules: []ModuleResult{{ID: "module-0123456789abcdef", Path: "worker", Status: StatusOK, Complete: true}},
	}}}
	delta, err := CompareFleetBaseline(baseline, t.TempDir(), current)
	if err != nil {
		t.Fatal(err)
	}
	if delta.Summary.AddedModules != 1 || !delta.HasNew() {
		t.Fatalf("module addition was not classified as new: %+v", delta)
	}
}
