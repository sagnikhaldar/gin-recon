package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/sagnikhaldar/gin-recon/internal/cli"
	"github.com/sagnikhaldar/gin-recon/internal/fleet"
)

func TestTargetConfigDraftWriterCreatesDirectoryBeforeCompletionsAndPublishesIncrementally(t *testing.T) {
	outDir := filepath.Join(t.TempDir(), "out")
	writer, err := newTargetConfigDraftWriter(outDir)
	if err != nil {
		t.Fatal(err)
	}
	draftDir := filepath.Join(outDir, targetConfigDraftDirName)
	if info, err := os.Stat(draftDir); err != nil || !info.IsDir() {
		t.Fatalf("draft directory was not initialized before completions: %v", err)
	}

	suggestionsRel := filepath.Join("targets", "repo-a", "suggestions.json")
	suggestionsPath := filepath.Join(outDir, suggestionsRel)
	if err := os.MkdirAll(filepath.Dir(suggestionsPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(suggestionsPath, []byte(`{"candidates":[{"canonicalSymbol":"example.RequireAuth","routeCount":2,"nameHint":true,"knownNonAuth":false}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	artifact, err := fleet.RecordArtifact("", outDir, suggestionsRel)
	if err != nil {
		t.Fatal(err)
	}
	result := fleet.TargetResult{Name: "repo-a", Status: fleet.StatusOK, Complete: true, Modules: []fleet.ModuleResult{{
		ID: "root", Path: ".", Status: fleet.StatusOK, Complete: true,
		Report: filepath.Join("targets", "repo-a", "routes.json"), SuggestionArtifact: &artifact,
	}}}
	if err := writer.Write(fleet.Target{Name: "repo-a"}, result, ""); err != nil {
		t.Fatal(err)
	}
	var draft targetConfigDraft
	data, err := os.ReadFile(filepath.Join(draftDir, "repo-a.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &draft); err != nil {
		t.Fatal(err)
	}
	if draft.ReviewState != "candidates-to-review" || draft.Candidates["example.RequireAuth"].RouteCount != 2 {
		t.Fatalf("draft = %+v", draft)
	}
	if _, err := os.Stat(filepath.Join(draftDir, "repo-b.json")); !os.IsNotExist(err) {
		t.Fatalf("uncompleted target was published early: %v", err)
	}
}

func TestTargetConfigDraftWriterRecordsZeroCandidatesAndFailures(t *testing.T) {
	outDir := t.TempDir()
	writer, err := newTargetConfigDraftWriter(outDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		res  fleet.TargetResult
		want string
	}{
		{"empty", fleet.TargetResult{Name: "empty", Status: fleet.StatusOK, Complete: true}, "no-candidates"},
		{"failed", fleet.TargetResult{Name: "failed", Status: fleet.StatusFailed, Error: "clone failed", TargetConfigDir: true}, "scan-failed"},
		{"skipped", fleet.TargetResult{Name: "skipped", Status: fleet.StatusNotGoModule, Complete: true}, "not-applicable"},
	} {
		if err := writer.Write(fleet.Target{Name: tc.name}, tc.res, ""); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(filepath.Join(outDir, targetConfigDraftDirName, tc.name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		var draft targetConfigDraft
		if err := json.Unmarshal(data, &draft); err != nil {
			t.Fatal(err)
		}
		if draft.ReviewState != tc.want {
			t.Errorf("%s state = %q, want %q", tc.name, draft.ReviewState, tc.want)
		}
		if tc.name == "failed" && !draft.ReviewedConfigApplied {
			t.Error("failed draft lost reviewed-config provenance")
		}
	}
}

func TestTargetConfigDraftWriterPreservesUnrecognizedFile(t *testing.T) {
	outDir := t.TempDir()
	writer, err := newTargetConfigDraftWriter(outDir)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(outDir, targetConfigDraftDirName, "repo.json")
	want := []byte(`{"manual":true}`)
	if err := os.WriteFile(path, want, 0o644); err != nil {
		t.Fatal(err)
	}
	err = writer.Write(fleet.Target{Name: "repo"}, fleet.TargetResult{Name: "repo", Status: fleet.StatusFailed}, "")
	if err == nil {
		t.Fatal("unrecognized draft was overwritten")
	}
	got, _ := os.ReadFile(path)
	if string(got) != string(want) {
		t.Fatalf("manual file changed: %q", got)
	}
}

func TestTargetConfigDraftWriterRefreshesLegacyGeneratedDraft(t *testing.T) {
	outDir := t.TempDir()
	writer, err := newTargetConfigDraftWriter(outDir)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(outDir, targetConfigDraftDirName, "repo.json")
	legacy := targetConfigDraft{Warning: legacyTargetConfigDraftWarning, Target: "repo", Candidates: map[string]targetConfigDraftEntry{}}
	data, _ := json.Marshal(legacy)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writer.Write(fleet.Target{Name: "repo"}, fleet.TargetResult{Name: "repo", Status: fleet.StatusOK, Complete: true}, "unchanged"); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got targetConfigDraft
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Kind != targetConfigDraftKind || got.ReviewState != "no-candidates" {
		t.Fatalf("refreshed legacy draft = %+v", got)
	}
}

func TestTargetConfigDraftWriterRecordsIncompleteScanEvenWithReviewedConfig(t *testing.T) {
	outDir := t.TempDir()
	writer, err := newTargetConfigDraftWriter(outDir)
	if err != nil {
		t.Fatal(err)
	}
	result := fleet.TargetResult{Name: "repo", Status: fleet.StatusOK, Complete: false, TargetConfigDir: true}
	if err := writer.Write(fleet.Target{Name: "repo"}, result, ""); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(outDir, targetConfigDraftDirName, "repo.json"))
	var draft targetConfigDraft
	if err := json.Unmarshal(data, &draft); err != nil {
		t.Fatal(err)
	}
	if draft.ReviewState != "scan-incomplete" || !draft.ReviewedConfigApplied {
		t.Fatalf("draft = %+v", draft)
	}
}

func TestFleetSuggestionEnrichmentEnabledForOrgWithoutFlag(t *testing.T) {
	if !fleetSuggestionEnrichmentEnabled(&cli.Options{Org: "acme"}) {
		t.Fatal("fresh org scan did not automatically enable suggestion enrichment")
	}
	if fleetSuggestionEnrichmentEnabled(&cli.Options{}) {
		t.Fatal("plain targets scan enabled suggestion enrichment without --suggest-auth")
	}
}

func TestWriteFleetTargetConfigSnapshotFailurePreservesPrevious(t *testing.T) {
	outDir := t.TempDir()
	dest := filepath.Join(outDir, targetConfigsSnapshotDirName)
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	want := []byte("reviewed")
	if err := os.WriteFile(filepath.Join(dest, "repo.json"), want, 0o600); err != nil {
		t.Fatal(err)
	}
	if code := writeFleetTargetConfigSnapshot(&cli.Options{OutDir: outDir}, filepath.Join(t.TempDir(), "missing"), io.Discard); code == cli.ExitSuccess {
		t.Fatal("snapshot publication unexpectedly succeeded")
	}
	got, err := os.ReadFile(filepath.Join(dest, "repo.json"))
	if err != nil || string(got) != string(want) {
		t.Fatalf("previous reviewed config was not preserved: %q, %v", got, err)
	}
}

func TestReusableTargetConfigSnapshotMigratesVerifiedLegacyDirectory(t *testing.T) {
	root := t.TempDir()
	snapshot := filepath.Join(root, targetConfigsSnapshotDirName)
	if err := os.MkdirAll(snapshot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(snapshot, "repo.json"), []byte(`{"version":1,"authMiddleware":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	hash, err := fleet.HashTargetConfigDirectory(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	aggregate := filepath.Join(root, fleetAggregateFilename)
	if err := os.WriteFile(aggregate, []byte(`{"targetConfigHash":"`+hash+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	reusable, err := reusableTargetConfigSnapshot(snapshot, aggregate)
	if err != nil || !reusable {
		t.Fatalf("verified legacy snapshot reusable = %v, err = %v", reusable, err)
	}
	if _, err := os.Stat(filepath.Join(snapshot, targetConfigsSnapshotMarker)); !os.IsNotExist(err) {
		t.Fatalf("legacy verification unexpectedly mutated snapshot: %v", err)
	}
}

func TestReusableTargetConfigSnapshotRejectsUnverifiablePartialDirectory(t *testing.T) {
	root := t.TempDir()
	snapshot := filepath.Join(root, targetConfigsSnapshotDirName)
	if err := os.MkdirAll(snapshot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(snapshot, "repo.json"), []byte(`{"partial":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if reusable, err := reusableTargetConfigSnapshot(snapshot, filepath.Join(root, fleetAggregateFilename)); err == nil || reusable {
		t.Fatalf("partial snapshot reusable = %v, err = %v", reusable, err)
	}
}
