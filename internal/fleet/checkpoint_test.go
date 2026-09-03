package fleet

import (
	"strings"
	"testing"
)

func TestLoadCheckpointMissingReturnsEmpty(t *testing.T) {
	dir := t.TempDir()
	want := identity{ManifestHash: "abc", Formats: []string{"json"}}
	cp, err := loadCheckpoint(dir, want)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cp.Complete) != 0 {
		t.Errorf("Complete = %v, want empty", cp.Complete)
	}
	if cp.Identity.ManifestHash != want.ManifestHash || !stringsEqual(cp.Identity.Formats, want.Formats) {
		t.Errorf("Identity = %+v, want %+v", cp.Identity, want)
	}
}

func TestSaveAndLoadCheckpointRoundTrip(t *testing.T) {
	dir := t.TempDir()
	want := identity{ManifestHash: "abc", ConfigHash: "def", Formats: []string{"json"}}
	cp := &checkpoint{Version: 1, Identity: want, Complete: map[string]TargetResult{
		"a": {Name: "a", Status: StatusOK, Complete: true},
	}}
	if err := saveCheckpoint(dir, cp); err != nil {
		t.Fatalf("saveCheckpoint: %v", err)
	}

	loaded, err := loadCheckpoint(dir, want)
	if err != nil {
		t.Fatalf("loadCheckpoint: %v", err)
	}
	if len(loaded.Complete) != 1 || loaded.Complete["a"].Status != StatusOK {
		t.Errorf("Complete = %+v", loaded.Complete)
	}
}

func TestLoadCheckpointRejectsManifestMismatch(t *testing.T) {
	dir := t.TempDir()
	original := identity{ManifestHash: "abc", Formats: []string{"json"}}
	if err := saveCheckpoint(dir, &checkpoint{Version: 1, Identity: original, Complete: map[string]TargetResult{}}); err != nil {
		t.Fatal(err)
	}

	_, err := loadCheckpoint(dir, identity{ManifestHash: "changed", Formats: []string{"json"}})
	if err == nil || !strings.Contains(err.Error(), "targets file has changed") {
		t.Fatalf("err = %v, want a targets-file-changed complaint", err)
	}
}

func TestLoadCheckpointRejectsConfigMismatch(t *testing.T) {
	dir := t.TempDir()
	original := identity{ManifestHash: "abc", ConfigHash: "x", Formats: []string{"json"}}
	if err := saveCheckpoint(dir, &checkpoint{Version: 1, Identity: original, Complete: map[string]TargetResult{}}); err != nil {
		t.Fatal(err)
	}

	_, err := loadCheckpoint(dir, identity{ManifestHash: "abc", ConfigHash: "y", Formats: []string{"json"}})
	if err == nil || !strings.Contains(err.Error(), "--config has changed") {
		t.Fatalf("err = %v, want a config-changed complaint", err)
	}
}

func TestLoadCheckpointRejectsFormatMismatch(t *testing.T) {
	dir := t.TempDir()
	original := identity{ManifestHash: "abc", Formats: []string{"json"}}
	if err := saveCheckpoint(dir, &checkpoint{Version: 1, Identity: original, Complete: map[string]TargetResult{}}); err != nil {
		t.Fatal(err)
	}

	_, err := loadCheckpoint(dir, identity{ManifestHash: "abc", Formats: []string{"md"}})
	if err == nil || !strings.Contains(err.Error(), "--format has changed") {
		t.Fatalf("err = %v, want a format-changed complaint", err)
	}
}

func TestRemoveCheckpointIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	if err := removeCheckpoint(dir); err != nil {
		t.Fatalf("removing a nonexistent checkpoint should not error: %v", err)
	}
}
