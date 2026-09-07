package fleet

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"

	"github.com/sagnikhaldar/gin-recon/internal/compare"
	"github.com/sagnikhaldar/gin-recon/internal/report"
)

// TargetDeltaStatus classifies one target's outcome in a fleet-level
// comparison (docs/adr/0022-fleet-baseline-delta.md).
type TargetDeltaStatus string

const (
	TargetUnchanged     TargetDeltaStatus = "unchanged"
	TargetAdded         TargetDeltaStatus = "added-target"
	TargetRemoved       TargetDeltaStatus = "removed-target"
	TargetStatusChanged TargetDeltaStatus = "status-changed"
	TargetIncomparable  TargetDeltaStatus = "incomparable"
)

type ModuleDelta struct {
	ID     string            `json:"id"`
	Path   string            `json:"path"`
	Status TargetDeltaStatus `json:"status"`
	Reason string            `json:"reason,omitempty"`
	Delta  *report.Delta     `json:"delta,omitempty"`
}

// TargetDelta is one target's contribution to a FleetDelta.
type TargetDelta struct {
	Name         string            `json:"name"`
	Status       TargetDeltaStatus `json:"status"`
	Reason       string            `json:"reason,omitempty"` // set only when Status is incomparable
	Delta        *report.Delta     `json:"delta,omitempty"`  // set only when Status is unchanged and both sides had a real report
	BeforeStatus Status            `json:"beforeStatus,omitempty"`
	AfterStatus  Status            `json:"afterStatus,omitempty"`
	Modules      []ModuleDelta     `json:"modules,omitempty"`
}

// FleetDelta is fleet-delta.json's shape: docs/adr/0022-fleet-baseline-delta.md's
// per-target breakdown plus a fleet-wide roll-up of the same counts
// report.Delta already tracks per repository.
type FleetDelta struct {
	SchemaVersion       string `json:"schemaVersion"`
	Kind                string `json:"kind"`
	BaselineFingerprint string `json:"baselineFingerprint,omitempty"`
	CurrentFingerprint  string `json:"currentFingerprint,omitempty"`
	Coverage            struct {
		Complete    bool     `json:"complete"`
		Diagnostics []string `json:"diagnostics,omitempty"`
	} `json:"coverage"`
	Targets []TargetDelta `json:"targets"`
	Summary struct {
		AddedTargets        int `json:"addedTargets"`
		RemovedTargets      int `json:"removedTargets"`
		IncomparableTargets int `json:"incomparableTargets"`
		StatusChanges       int `json:"statusChanges"`
		AddedModules        int `json:"addedModules"`
		RemovedModules      int `json:"removedModules"`
		AddedRoutes         int `json:"addedRoutes"`
		RemovedRoutes       int `json:"removedRoutes"`
		AuthRegressions     int `json:"authRegressions"`
		AuthImprovements    int `json:"authImprovements"`
		NewFindings         int `json:"newFindings"`
		ResolvedFindings    int `json:"resolvedFindings"`
	} `json:"summary"`
}

// HasNew reports whether the delta contains anything --fail-on new should
// match: an added target, an added route, or a new finding anywhere in the
// fleet (docs/adr/0022-fleet-baseline-delta.md).
func (d *FleetDelta) HasNew() bool {
	return d.Summary.AddedTargets > 0 || d.Summary.AddedModules > 0 || d.Summary.AddedRoutes > 0 || d.Summary.NewFindings > 0
}

// HasRegression reports whether --fail-on regression should match: any
// route anywhere in the fleet becoming less safely authenticated.
func (d *FleetDelta) HasRegression() bool {
	return d.Summary.AuthRegressions > 0
}

// Baseline is a previous fleet run's aggregate, fully loaded into memory —
// its own fleet.json plus every one of its targets' own routes.json content
// (for any target that had one). Loading everything eagerly, not just the
// top-level aggregate, matters because --baseline's directory can overlap
// or even equal the current run's own --out (a realistic setup with
// --force): reading a target's report lazily, after the current run has
// already re-scanned and overwritten that same path, would silently
// compare the new run against itself for that target instead of against
// the real baseline. Loading everything before Run touches the filesystem
// closes that regardless of how much the two directories overlap.
type Baseline struct {
	Aggregate *Aggregate
	Reports   map[string]*report.Report // by target/module identity; only present for targets with a real report
}

// LoadBaseline reads a previous fleet run's fleet.json and every one of its
// targets' own reports. Call this before writing any of the current run's
// own output — see Baseline's own doc comment for why.
func LoadBaseline(baselinePath string) (*Baseline, error) {
	data, err := ReadBoundedFile(baselinePath)
	if err != nil {
		return nil, fmt.Errorf("fleet: --baseline: %w", err)
	}
	agg, err := ParseAggregate(data, true)
	if err != nil {
		return nil, fmt.Errorf("fleet: --baseline: %s is not a valid fleet.json: %w", baselinePath, err)
	}

	// A target whose report can't be read (a baseline directory that was
	// partially cleaned up, or a target since removed along with its
	// output) is skipped here, not a fatal error for the whole baseline —
	// CompareBaseline only needs this map for a target that's actually
	// present on both sides, and reports that outcome as one incomparable
	// target with a clear reason, not by aborting --baseline entirely.
	baselineDir := filepath.Dir(baselinePath)
	reports := make(map[string]*report.Report)
	for _, t := range agg.Targets {
		if t.Status != StatusOK {
			continue
		}
		if len(t.Modules) == 0 {
			if rep, err := loadTargetReport(baselineDir, t); err == nil {
				reports[reportIdentity(t.Name, "")] = rep
			}
			continue
		}
		for _, module := range t.Modules {
			if rep, err := loadModuleReport(baselineDir, t.Name, module); err == nil {
				reports[reportIdentity(t.Name, module.ID)] = rep
			}
		}
	}
	return &Baseline{Aggregate: agg, Reports: reports}, nil
}

// CompareBaseline compares an already-loaded Baseline (see LoadBaseline)
// against the current run's own results, per
// docs/adr/0022-fleet-baseline-delta.md. currentOutDir is the current run's
// --out; current is the current run's own aggregate target list — only
// current targets' reports are read from disk here, since the baseline's
// own reports were already captured in memory by LoadBaseline.
func CompareBaseline(baseline *Baseline, currentOutDir string, current []TargetResult) (*FleetDelta, error) {
	return compareFleetBaseline(baseline, currentOutDir, &Aggregate{Targets: current})
}

// CompareFleetBaseline additionally verifies fleet-level scan and scope
// fingerprints before performing any route comparison.
func CompareFleetBaseline(baseline *Baseline, currentOutDir string, current *Aggregate) (*FleetDelta, error) {
	return compareFleetBaseline(baseline, currentOutDir, current)
}

func compareFleetBaseline(baseline *Baseline, currentOutDir string, currentAggregate *Aggregate) (*FleetDelta, error) {
	if err := compatibleFleetAggregates(baseline.Aggregate, currentAggregate); err != nil {
		return nil, err
	}
	current := currentAggregate.Targets
	baselineByName := make(map[string]TargetResult, len(baseline.Aggregate.Targets))
	for _, t := range baseline.Aggregate.Targets {
		baselineByName[t.Name] = t
	}
	currentByName := make(map[string]TargetResult, len(current))
	for _, t := range current {
		currentByName[t.Name] = t
	}

	names := make(map[string]bool, len(baselineByName)+len(currentByName))
	for name := range baselineByName {
		names[name] = true
	}
	for name := range currentByName {
		names[name] = true
	}
	sorted := make([]string, 0, len(names))
	for name := range names {
		sorted = append(sorted, name)
	}
	sort.Strings(sorted)

	fd := &FleetDelta{SchemaVersion: "1.0", Kind: "fleet-delta", BaselineFingerprint: baseline.Aggregate.ScanFingerprint, CurrentFingerprint: currentAggregate.ScanFingerprint}
	fd.Coverage.Complete = true
	for _, name := range sorted {
		before, inBaseline := baselineByName[name]
		after, inCurrent := currentByName[name]

		switch {
		case inBaseline && !inCurrent:
			fd.Targets = append(fd.Targets, TargetDelta{Name: name, Status: TargetRemoved})
			fd.Summary.RemovedTargets++
		case !inBaseline && inCurrent:
			fd.Targets = append(fd.Targets, TargetDelta{Name: name, Status: TargetAdded})
			fd.Summary.AddedTargets++
		case before.Status != after.Status:
			reason := fmt.Sprintf("target status changed from %s to %s; route evidence is not comparable", before.Status, after.Status)
			fd.Targets = append(fd.Targets, TargetDelta{Name: name, Status: TargetStatusChanged, BeforeStatus: before.Status, AfterStatus: after.Status, Reason: reason})
			fd.Summary.StatusChanges++
			fd.Summary.IncomparableTargets++
			fd.Coverage.Complete = false
			fd.Coverage.Diagnostics = append(fd.Coverage.Diagnostics, name+": "+reason)
		case before.Status != StatusOK:
			// Neither side has a real report to diff (e.g. not-go-module on
			// both sides, or a target that failed on one side) — the target
			// itself persists, so it's not added/removed, but there is no
			// route-level delta to compute.
			fd.Targets = append(fd.Targets, TargetDelta{Name: name, Status: TargetUnchanged, BeforeStatus: before.Status, AfterStatus: after.Status})
		case !before.Complete || !after.Complete:
			reason := "one or both target scans are incomplete"
			fd.Targets = append(fd.Targets, TargetDelta{Name: name, Status: TargetIncomparable, BeforeStatus: before.Status, AfterStatus: after.Status, Reason: reason})
			fd.Summary.IncomparableTargets++
			fd.Coverage.Complete = false
			fd.Coverage.Diagnostics = append(fd.Coverage.Diagnostics, name+": "+reason)
		default:
			targetDelta := compareTargetReports(fd, baseline, currentOutDir, before, after)
			fd.Targets = append(fd.Targets, targetDelta)
		}
	}
	return fd, nil
}

func compatibleFleetAggregates(baseline, current *Aggregate) error {
	for _, check := range []struct{ name, before, after string }{
		{"scope", baseline.ScopeFingerprint, current.ScopeFingerprint},
		{"scan", baseline.ScanFingerprint, current.ScanFingerprint},
	} {
		if check.before == "" && check.after == "" {
			continue // legacy in-memory/test aggregate
		}
		if check.before == "" || check.after == "" || check.before != check.after {
			return fmt.Errorf("fleet: --baseline: %s fingerprint does not match the current run", check.name)
		}
	}
	return nil
}

func compareTargetReports(fd *FleetDelta, baseline *Baseline, currentOutDir string, before, after TargetResult) TargetDelta {
	result := TargetDelta{Name: after.Name, Status: TargetUnchanged, BeforeStatus: before.Status, AfterStatus: after.Status}
	if len(before.Modules) == 0 && len(after.Modules) == 0 {
		delta, reason := compareReportPair(baseline.Reports[reportIdentity(before.Name, "")], func() (*report.Report, error) { return loadTargetReport(currentOutDir, after) })
		if reason != "" {
			markIncomparable(fd, &result, reason)
			return result
		}
		result.Delta = delta
		addDeltaSummary(fd, delta)
		return result
	}

	beforeModules := make(map[string]ModuleResult, len(before.Modules))
	afterModules := make(map[string]ModuleResult, len(after.Modules))
	for _, module := range before.Modules {
		beforeModules[module.ID] = module
	}
	for _, module := range after.Modules {
		afterModules[module.ID] = module
	}
	ids := make(map[string]bool, len(beforeModules)+len(afterModules))
	for id := range beforeModules {
		ids[id] = true
	}
	for id := range afterModules {
		ids[id] = true
	}
	ordered := make([]string, 0, len(ids))
	for id := range ids {
		ordered = append(ordered, id)
	}
	sort.Strings(ordered)
	for _, id := range ordered {
		bm, beforeOK := beforeModules[id]
		am, afterOK := afterModules[id]
		switch {
		case !beforeOK:
			result.Modules = append(result.Modules, ModuleDelta{ID: id, Path: am.Path, Status: TargetAdded})
			fd.Summary.AddedModules++
			fd.Summary.AddedRoutes += am.Routes
		case !afterOK:
			result.Modules = append(result.Modules, ModuleDelta{ID: id, Path: bm.Path, Status: TargetRemoved})
			fd.Summary.RemovedModules++
			fd.Summary.RemovedRoutes += bm.Routes
		case bm.Status != am.Status:
			reason := fmt.Sprintf("module status changed from %s to %s", bm.Status, am.Status)
			result.Modules = append(result.Modules, ModuleDelta{ID: id, Path: am.Path, Status: TargetStatusChanged, Reason: reason})
			fd.Summary.StatusChanges++
			markIncomparable(fd, &result, reason)
		case bm.Status != StatusOK || !bm.Complete || !am.Complete:
			reason := fmt.Sprintf("module status/coverage changed (%s/%t -> %s/%t)", bm.Status, bm.Complete, am.Status, am.Complete)
			result.Modules = append(result.Modules, ModuleDelta{ID: id, Path: am.Path, Status: TargetIncomparable, Reason: reason})
			markIncomparable(fd, &result, reason)
		default:
			delta, reason := compareReportPair(baseline.Reports[reportIdentity(before.Name, id)], func() (*report.Report, error) { return loadModuleReport(currentOutDir, after.Name, am) })
			moduleDelta := ModuleDelta{ID: id, Path: am.Path, Status: TargetUnchanged, Delta: delta, Reason: reason}
			if reason != "" {
				moduleDelta.Status = TargetIncomparable
				markIncomparable(fd, &result, reason)
			} else {
				addDeltaSummary(fd, delta)
			}
			result.Modules = append(result.Modules, moduleDelta)
		}
	}
	return result
}

func compareReportPair(before *report.Report, loadAfter func() (*report.Report, error)) (*report.Delta, string) {
	if before == nil {
		return nil, "baseline target has no captured report"
	}
	after, err := loadAfter()
	if err != nil {
		return nil, err.Error()
	}
	if err := compare.Compatible(before, after); err != nil {
		return nil, err.Error()
	}
	return compare.Compare(before, after), ""
}

func markIncomparable(fd *FleetDelta, target *TargetDelta, reason string) {
	if target.Status != TargetIncomparable {
		fd.Summary.IncomparableTargets++
	}
	target.Status = TargetIncomparable
	if target.Reason == "" {
		target.Reason = reason
	}
	fd.Coverage.Complete = false
	fd.Coverage.Diagnostics = append(fd.Coverage.Diagnostics, target.Name+": "+reason)
}

func addDeltaSummary(fd *FleetDelta, delta *report.Delta) {
	fd.Summary.AddedRoutes += len(delta.AddedRoutes)
	fd.Summary.RemovedRoutes += len(delta.RemovedRoutes)
	fd.Summary.AuthRegressions += len(delta.AuthRegressions)
	fd.Summary.AuthImprovements += len(delta.AuthImprovements)
	fd.Summary.NewFindings += len(delta.NewFindings)
	fd.Summary.ResolvedFindings += len(delta.ResolvedFindings)
}

func reportIdentity(target, module string) string { return target + "\x00" + module }

// loadTargetReport reads one target's own routes.json, resolved the same
// way runOneTarget wrote it: <outDir>/targets/<name>/routes.json.
func loadTargetReport(outDir string, t TargetResult) (*report.Report, error) {
	rel := t.Report
	if rel == "" {
		rel = filepath.Join("targets", t.Name, "routes.json")
	}
	return loadReportArtifact(outDir, t.Name, rel)
}

func loadModuleReport(outDir, targetName string, module ModuleResult) (*report.Report, error) {
	if module.Report == "" {
		return nil, fmt.Errorf("target %q module %q has no report path", targetName, module.Path)
	}
	return loadReportArtifact(outDir, targetName, module.Report)
}

func loadReportArtifact(outDir, targetName, relativePath string) (*report.Report, error) {
	path, err := safeRelativeArtifactPath(outDir, relativePath)
	if err != nil {
		return nil, fmt.Errorf("target %q: %w", targetName, err)
	}
	data, err := ReadBoundedFile(path)
	if err != nil {
		return nil, fmt.Errorf("target %q: reading %s: %w", targetName, path, err)
	}
	var rep report.Report
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, fmt.Errorf("target %q: decoding %s: %w", targetName, path, err)
	}
	return &rep, nil
}
