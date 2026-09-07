package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"

	"github.com/sagnikhaldar/gin-recon/internal/cli"
)

// accuracyManifest is the subset of a fixture's manifest.json this harness
// reads — every other reviewed field (excludedRoutes, expectedDiagnostics,
// expectedFindings, ...) documents intent for the fixture's own dedicated
// analyzer/classify tests and is irrelevant to route recall/precision.
type accuracyManifest struct {
	ExpectedRoutes []accuracyRouteRef `json:"expectedRoutes"`
	// registrar-functions keeps its control-flow-following coverage in its
	// own array, separate from expectedRoutes, so a dedicated analyzer test
	// can assert on it in isolation (see that fixture's manifest.json). For
	// corpus-wide recall/precision both arrays are equally real routes this
	// fixture's source registers, so this harness merges them.
	ControlFlowExpectedRoutes []accuracyRouteRef `json:"controlFlowExpectedRoutes"`
}

type accuracyRouteRef struct {
	Method         string `json:"method"`
	NormalizedPath string `json:"normalizedPath"`
}

type accuracyRouteKey struct{ Method, Path string }

// TestAccuracyCorpusRouteRecallAndPrecision is gin-recon's first aggregate
// accuracy measurement (docs/accuracy-strategy.md's "Metrics and Release
// Gates"). The 12 fixture manifest.json files under testdata/fixtures
// existed only as human-reviewed ground truth that each fixture's own
// analyzer/classify test separately hardcoded its own assertions against —
// nothing parsed and aggregated them into the recall/precision percentages
// PLAN.md's release criteria actually require, so nobody could state gin-
// recon's real numbers.
//
// For every fixture with a non-empty expectedRoutes/controlFlowExpectedRoutes
// list, this runs a real `inventory` exactly as a user would and compares
// the emitted routes' (method, normalizedPath) identity — the canonical
// route identity per docs/reference.md — against that fixture's own
// manifest. Recall/precision are aggregated corpus-wide, matching the
// accuracy strategy's own framing, then asserted against PLAN.md's Alpha
// bar (>= 90% each) — this project's current release stage, not yet Beta's
// 98%/95%. A fixture with zero expectedRoutes (engine-security, which
// measures findings rather than routes) is skipped rather than counted as
// zero found.
//
// Known gap surfaced by the first real run of this harness, deliberately
// left unfixed here rather than papered over: untracked-factory's
// /resolved-factory and /via-logged-factory are not discovered.
// NewRouter() in that fixture never calls gin.New()/Default() itself — it
// only assigns local variables from calling other factory functions that
// do — so internal/analyzer/inventory.go's root-selection
// (gin.HasEngineConstruction, direct-call-only) never scans it, and
// gin.DetectLibraryEntryPoint doesn't cover it either since it takes no
// router-typed parameter to key off. A real, silent route-loss gap,
// structurally the mirror image of the parameter-based case
// DetectLibraryEntryPoint already handles — real analyzer/root-selection
// work, not a one-line fix, so it's measured honestly here rather than
// adjusted away by weakening the manifest to match the bug.
func TestAccuracyCorpusRouteRecallAndPrecision(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not determine repo-relative fixture path")
	}
	fixturesRoot := filepath.Join(filepath.Dir(thisFile), "..", "..", "testdata", "fixtures")

	entries, err := os.ReadDir(fixturesRoot)
	if err != nil {
		t.Fatalf("reading %s: %v", fixturesRoot, err)
	}

	var totalExpected, totalMatched, totalActual int
	var report []string

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		fixtureName := e.Name()
		fixtureDir := filepath.Join(fixturesRoot, fixtureName)
		data, err := os.ReadFile(filepath.Join(fixtureDir, "manifest.json"))
		if err != nil {
			continue // not every testdata/fixtures entry is a manifest-bearing corpus fixture
		}
		var manifest accuracyManifest
		if err := json.Unmarshal(data, &manifest); err != nil {
			t.Fatalf("%s: invalid manifest.json: %v", fixtureName, err)
		}
		expected := append(append([]accuracyRouteRef{}, manifest.ExpectedRoutes...), manifest.ControlFlowExpectedRoutes...)
		if len(expected) == 0 {
			continue // e.g. engine-security: measures findings, not route discovery
		}

		var stdout, stderr bytes.Buffer
		code := run([]string{"inventory", "--src", fixtureDir, "--format", "json", "--allow-downloads"}, &stdout, &stderr)
		if code != cli.ExitSuccess {
			t.Errorf("%s: inventory exited %d, want %d; stderr: %s", fixtureName, code, cli.ExitSuccess, stderr.String())
			continue
		}

		var result struct {
			Routes []accuracyRouteRef `json:"routes"`
		}
		if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
			t.Fatalf("%s: inventory produced invalid JSON: %v", fixtureName, err)
		}

		expectedSet := map[accuracyRouteKey]bool{}
		for _, r := range expected {
			expectedSet[accuracyRouteKey{r.Method, r.NormalizedPath}] = true
		}
		actualSet := map[accuracyRouteKey]bool{}
		for _, r := range result.Routes {
			actualSet[accuracyRouteKey{r.Method, r.NormalizedPath}] = true
		}

		matched := 0
		var missing, extra []string
		for k := range expectedSet {
			if actualSet[k] {
				matched++
			} else {
				missing = append(missing, k.Method+" "+k.Path)
			}
		}
		for k := range actualSet {
			if !expectedSet[k] {
				extra = append(extra, k.Method+" "+k.Path)
			}
		}
		sort.Strings(missing)
		sort.Strings(extra)

		totalExpected += len(expectedSet)
		totalMatched += matched
		totalActual += len(actualSet)

		line := fmt.Sprintf("%-26s expected=%-3d actual=%-3d matched=%-3d", fixtureName, len(expectedSet), len(actualSet), matched)
		if len(missing) > 0 {
			line += fmt.Sprintf(" MISSING=%v", missing)
		}
		if len(extra) > 0 {
			line += fmt.Sprintf(" EXTRA=%v", extra)
		}
		report = append(report, line)
	}

	sort.Strings(report)
	for _, line := range report {
		t.Log(line)
	}

	if totalExpected == 0 {
		t.Fatal("no fixture contributed any expectedRoutes — corpus discovery is broken")
	}

	recall := float64(totalMatched) / float64(totalExpected) * 100
	precision := 100.0
	if totalActual > 0 {
		precision = float64(totalMatched) / float64(totalActual) * 100
	}
	t.Logf("corpus-wide: %d/%d expected routes recalled (%.1f%%), %d/%d emitted routes correct (%.1f%%)",
		totalMatched, totalExpected, recall, totalMatched, totalActual, precision)

	// PLAN.md's Alpha bar (phases 1-5 complete): >= 90% recall and
	// precision. Beta's 98%/95% is not asserted here — this corpus isn't
	// there yet, per the known gap in this test's own doc comment.
	const alphaBar = 90.0
	if recall < alphaBar {
		t.Errorf("corpus-wide route recall = %.1f%%, want >= %.1f%% (PLAN.md Alpha bar)", recall, alphaBar)
	}
	if precision < alphaBar {
		t.Errorf("corpus-wide route precision = %.1f%%, want >= %.1f%% (PLAN.md Alpha bar)", precision, alphaBar)
	}
}
