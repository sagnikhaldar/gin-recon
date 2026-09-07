package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/sagnikhaldar/gin-recon/internal/cli"
	"github.com/sagnikhaldar/gin-recon/internal/fleet"
)

func writeFakeSuggestions(t *testing.T, path string, candidatesJSON string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	doc := `{"module":"m","totalRoutes":1,"candidates":[` + candidatesJSON + `],"opaqueMiddleware":0,"scanCoverage":{"complete":true}}`
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestAggregateFleetAuthSuggestionsMergesAcrossTargets is the core
// regression test for --suggest-auth's whole reason for existing: a
// canonical symbol shared across multiple repositories (a common internal
// auth package, the case most worth surfacing) must merge into one entry
// with a combined RepoCount/RouteCount and a labeled, deduplicated sample
// list — not silently collapse to whichever target's candidate happened to
// be read first, or appear as separate, harder-to-notice duplicate rows.
func TestAggregateFleetAuthSuggestionsMergesAcrossTargets(t *testing.T) {
	outDir := t.TempDir()
	writeFakeSuggestions(t, filepath.Join(outDir, "targets", "repo-a", "suggestions.json"),
		`{"canonicalSymbol":"github.com/acme/common-auth.RequireAuth","routeCount":3,"totalRoutes":5,"appliesToAllRoutes":false,"nameHint":true,"knownNonAuth":false,"sampleRoutes":["GET /a","POST /b"]}`)
	writeFakeSuggestions(t, filepath.Join(outDir, "targets", "repo-b", "suggestions.json"),
		`{"canonicalSymbol":"github.com/acme/common-auth.RequireAuth","routeCount":2,"totalRoutes":2,"appliesToAllRoutes":true,"nameHint":true,"knownNonAuth":false,"sampleRoutes":["GET /c"]}`)

	agg := &fleet.Aggregate{Targets: []fleet.TargetResult{
		{Name: "repo-a", Status: fleet.StatusOK, Complete: true, Report: filepath.Join("targets", "repo-a", "routes.json")},
		{Name: "repo-b", Status: fleet.StatusOK, Complete: true, Report: filepath.Join("targets", "repo-b", "routes.json")},
	}}

	got, err := aggregateFleetAuthSuggestions(agg, outDir)
	if err != nil {
		t.Fatalf("aggregateFleetAuthSuggestions: %v", err)
	}
	if got.TargetsScanned != 2 || got.TargetsContributed != 2 {
		t.Errorf("TargetsScanned=%d TargetsContributed=%d, want 2 and 2", got.TargetsScanned, got.TargetsContributed)
	}
	if len(got.Candidates) != 1 {
		t.Fatalf("Candidates = %+v, want exactly 1 merged entry", got.Candidates)
	}
	c := got.Candidates[0]
	if c.CanonicalSymbol != "github.com/acme/common-auth.RequireAuth" {
		t.Errorf("CanonicalSymbol = %q", c.CanonicalSymbol)
	}
	if c.RouteCount != 5 {
		t.Errorf("RouteCount = %d, want 3+2=5", c.RouteCount)
	}
	if c.RepoCount != 2 {
		t.Errorf("RepoCount = %d, want 2", c.RepoCount)
	}
	if len(c.Repos) != 2 || c.Repos[0] != "repo-a" || c.Repos[1] != "repo-b" {
		t.Errorf("Repos = %+v, want [repo-a repo-b]", c.Repos)
	}
	wantSamples := []string{"repo-a: GET /a", "repo-a: POST /b", "repo-b: GET /c"}
	if len(c.SampleRoutes) != len(wantSamples) {
		t.Fatalf("SampleRoutes = %+v, want %+v", c.SampleRoutes, wantSamples)
	}
	for i, want := range wantSamples {
		if c.SampleRoutes[i] != want {
			t.Errorf("SampleRoutes[%d] = %q, want %q", i, c.SampleRoutes[i], want)
		}
	}
	if !c.NameHint {
		t.Error("NameHint = false, want true")
	}
}

// TestAggregateFleetAuthSuggestionsSkipsTargetsWithoutSuggestions confirms a
// target whose own suggest-auth pass never produced a file (failed, or
// reused from --update/--resume rather than freshly scanned) is silently
// excluded, not an error for the whole aggregation.
func TestAggregateFleetAuthSuggestionsSkipsTargetsWithoutSuggestions(t *testing.T) {
	outDir := t.TempDir()
	agg := &fleet.Aggregate{Targets: []fleet.TargetResult{
		{Name: "no-suggestions", Status: fleet.StatusOK, Complete: true, Report: filepath.Join("targets", "no-suggestions", "routes.json")},
		{Name: "failed-target", Status: fleet.StatusFailed},
	}}
	got, err := aggregateFleetAuthSuggestions(agg, outDir)
	if err != nil {
		t.Fatalf("aggregateFleetAuthSuggestions: %v", err)
	}
	if got.TargetsScanned != 1 {
		t.Errorf("TargetsScanned = %d, want 1 (the failed target must not count)", got.TargetsScanned)
	}
	if got.TargetsContributed != 0 {
		t.Errorf("TargetsContributed = %d, want 0", got.TargetsContributed)
	}
	if len(got.Candidates) != 0 {
		t.Errorf("Candidates = %+v, want none", got.Candidates)
	}
}

// TestAggregateFleetAuthSuggestionsCapsReposAndSamples proves the size
// bounds actually apply — a symbol used across more repositories than
// fleetAuthRepoCap must not make the document scale with the whole
// organization.
func TestAggregateFleetAuthSuggestionsCapsReposAndSamples(t *testing.T) {
	outDir := t.TempDir()
	targets := make([]fleet.TargetResult, 0, fleetAuthRepoCap+3)
	for i := 0; i < fleetAuthRepoCap+3; i++ {
		name := "repo-" + string(rune('a'+i))
		writeFakeSuggestions(t, filepath.Join(outDir, "targets", name, "suggestions.json"),
			`{"canonicalSymbol":"github.com/acme/common-auth.RequireAuth","routeCount":1,"totalRoutes":1,"appliesToAllRoutes":true,"nameHint":true,"knownNonAuth":false,"sampleRoutes":["GET /x"]}`)
		targets = append(targets, fleet.TargetResult{Name: name, Status: fleet.StatusOK, Complete: true, Report: filepath.Join("targets", name, "routes.json")})
	}
	agg := &fleet.Aggregate{Targets: targets}

	got, err := aggregateFleetAuthSuggestions(agg, outDir)
	if err != nil {
		t.Fatalf("aggregateFleetAuthSuggestions: %v", err)
	}
	if len(got.Candidates) != 1 {
		t.Fatalf("Candidates = %+v, want exactly 1", got.Candidates)
	}
	c := got.Candidates[0]
	if c.RepoCount != fleetAuthRepoCap+3 {
		t.Errorf("RepoCount = %d, want the real total %d", c.RepoCount, fleetAuthRepoCap+3)
	}
	if len(c.Repos) != fleetAuthRepoCap {
		t.Errorf("len(Repos) = %d, want capped at %d", len(c.Repos), fleetAuthRepoCap)
	}
	if c.RepoCountTotal != fleetAuthRepoCap+3 {
		t.Errorf("RepoCountTotal = %d, want %d", c.RepoCountTotal, fleetAuthRepoCap+3)
	}
}

// TestRunFleetSuggestAuthWritesCandidates is the CLI-level end-to-end test:
// a real fleet run with --suggest-auth against a real fixture must produce
// fleet-auth-candidates.json with real, non-empty candidates.
func TestRunFleetSuggestAuthWritesCandidates(t *testing.T) {
	fleetBinaryPathForTests = buildRealGinReconBinary(t)
	defer func() { fleetBinaryPathForTests = "" }()

	root := t.TempDir()
	manifestPath := filepath.Join(root, "targets.json")
	manifest := `{"version":1,"targets":[{"name":"repo-a","src":` +
		jsonString(fixtureDir(t, "auth-wrappers")) + `}]}`
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(root, "out")

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"fleet", "--targets", manifestPath, "--out", outDir,
		"--allow-downloads", "--suggest-auth",
	}, &stdout, &stderr)
	if code != cli.ExitSuccess {
		t.Fatalf("exit code = %d, want %d; stderr: %s", code, cli.ExitSuccess, stderr.String())
	}

	data, err := os.ReadFile(filepath.Join(outDir, fleetAuthCandidateFilename))
	if err != nil {
		t.Fatalf("%s was not written: %v", fleetAuthCandidateFilename, err)
	}
	var suggestions FleetAuthSuggestions
	if err := json.Unmarshal(data, &suggestions); err != nil {
		t.Fatalf("%s is not valid JSON: %v", fleetAuthCandidateFilename, err)
	}
	if suggestions.Kind != "fleet-auth-suggestions" {
		t.Errorf("Kind = %q", suggestions.Kind)
	}
	if suggestions.TargetsContributed != 1 {
		t.Errorf("TargetsContributed = %d, want 1", suggestions.TargetsContributed)
	}
	if len(suggestions.Candidates) == 0 {
		t.Fatal("Candidates is empty, want at least one real candidate from the auth-wrappers fixture")
	}
}

func jsonString(s string) string {
	data, _ := json.Marshal(s)
	return string(data)
}
