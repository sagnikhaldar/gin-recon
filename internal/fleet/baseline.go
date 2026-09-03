package fleet

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/sagnikhaldar/gin-recon/internal/compare"
	"github.com/sagnikhaldar/gin-recon/internal/report"
)

// TargetDeltaStatus classifies one target's outcome in a fleet-level
// comparison (docs/adr/0022-fleet-baseline-delta.md).
type TargetDeltaStatus string

const (
	TargetUnchanged    TargetDeltaStatus = "unchanged"
	TargetAdded        TargetDeltaStatus = "added-target"
	TargetRemoved      TargetDeltaStatus = "removed-target"
	TargetIncomparable TargetDeltaStatus = "incomparable"
)

// TargetDelta is one target's contribution to a FleetDelta.
type TargetDelta struct {
	Name   string            `json:"name"`
	Status TargetDeltaStatus `json:"status"`
	Reason string            `json:"reason,omitempty"` // set only when Status is incomparable
	Delta  *report.Delta     `json:"delta,omitempty"`  // set only when Status is unchanged and both sides had a real report
}

// FleetDelta is fleet-delta.json's shape: docs/adr/0022-fleet-baseline-delta.md's
// per-target breakdown plus a fleet-wide roll-up of the same counts
// report.Delta already tracks per repository.
type FleetDelta struct {
	Targets []TargetDelta `json:"targets"`
	Summary struct {
		AddedTargets        int `json:"addedTargets"`
		RemovedTargets      int `json:"removedTargets"`
		IncomparableTargets int `json:"incomparableTargets"`
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
	return d.Summary.AddedTargets > 0 || d.Summary.AddedRoutes > 0 || d.Summary.NewFindings > 0
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
	Reports   map[string]*report.Report // by target name; only present for targets with a real report
}

// LoadBaseline reads a previous fleet run's fleet.json and every one of its
// targets' own reports. Call this before writing any of the current run's
// own output — see Baseline's own doc comment for why.
func LoadBaseline(baselinePath string) (*Baseline, error) {
	data, err := os.ReadFile(baselinePath)
	if err != nil {
		return nil, fmt.Errorf("fleet: --baseline: %w", err)
	}
	var agg Aggregate
	if err := json.Unmarshal(data, &agg); err != nil {
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
		if rep, err := loadTargetReport(baselineDir, t); err == nil {
			reports[t.Name] = rep
		}
	}
	return &Baseline{Aggregate: &agg, Reports: reports}, nil
}

// CompareBaseline compares an already-loaded Baseline (see LoadBaseline)
// against the current run's own results, per
// docs/adr/0022-fleet-baseline-delta.md. currentOutDir is the current run's
// --out; current is the current run's own aggregate target list — only
// current targets' reports are read from disk here, since the baseline's
// own reports were already captured in memory by LoadBaseline.
func CompareBaseline(baseline *Baseline, currentOutDir string, current []TargetResult) (*FleetDelta, error) {
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

	fd := &FleetDelta{}
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
		case before.Status != StatusOK || after.Status != StatusOK:
			// Neither side has a real report to diff (e.g. not-go-module on
			// both sides, or a target that failed on one side) — the target
			// itself persists, so it's not added/removed, but there is no
			// route-level delta to compute.
			fd.Targets = append(fd.Targets, TargetDelta{Name: name, Status: TargetUnchanged})
		default:
			beforeReport, ok := baseline.Reports[before.Name]
			if !ok {
				fd.Targets = append(fd.Targets, TargetDelta{Name: name, Status: TargetIncomparable, Reason: "baseline target has no captured report"})
				fd.Summary.IncomparableTargets++
				continue
			}
			afterReport, err := loadTargetReport(currentOutDir, after)
			if err != nil {
				fd.Targets = append(fd.Targets, TargetDelta{Name: name, Status: TargetIncomparable, Reason: err.Error()})
				fd.Summary.IncomparableTargets++
				continue
			}
			if err := compare.Compatible(beforeReport, afterReport); err != nil {
				fd.Targets = append(fd.Targets, TargetDelta{Name: name, Status: TargetIncomparable, Reason: err.Error()})
				fd.Summary.IncomparableTargets++
				continue
			}
			delta := compare.Compare(beforeReport, afterReport)
			fd.Targets = append(fd.Targets, TargetDelta{Name: name, Status: TargetUnchanged, Delta: delta})
			fd.Summary.AddedRoutes += len(delta.AddedRoutes)
			fd.Summary.RemovedRoutes += len(delta.RemovedRoutes)
			fd.Summary.AuthRegressions += len(delta.AuthRegressions)
			fd.Summary.AuthImprovements += len(delta.AuthImprovements)
			fd.Summary.NewFindings += len(delta.NewFindings)
			fd.Summary.ResolvedFindings += len(delta.ResolvedFindings)
		}
	}
	return fd, nil
}

// loadTargetReport reads one target's own routes.json, resolved the same
// way runOneTarget wrote it: <outDir>/targets/<name>/routes.json.
func loadTargetReport(outDir string, t TargetResult) (*report.Report, error) {
	path := filepath.Join(outDir, "targets", t.Name, "routes.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("target %q: reading %s: %w", t.Name, path, err)
	}
	var rep report.Report
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, fmt.Errorf("target %q: decoding %s: %w", t.Name, path, err)
	}
	return &rep, nil
}
