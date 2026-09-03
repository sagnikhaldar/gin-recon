package fleet

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeManifest(t *testing.T, dir, contents string) string {
	t.Helper()
	path := filepath.Join(dir, "targets.json")
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadManifestValid(t *testing.T) {
	dir := t.TempDir()
	path := writeManifest(t, dir, `{"version":1,"targets":[{"name":"a","src":"./a"},{"name":"b","src":"/abs/b"}]}`)

	m, data, err := LoadManifest(path)
	if err != nil {
		t.Fatalf("LoadManifest: unexpected error: %v", err)
	}
	if len(m.Targets) != 2 || m.Targets[0].Name != "a" || m.Targets[1].Name != "b" {
		t.Errorf("Targets = %+v", m.Targets)
	}
	if len(data) == 0 {
		t.Error("raw manifest bytes were not returned")
	}
}

func TestLoadManifestRejectsMissingFile(t *testing.T) {
	_, _, err := LoadManifest(filepath.Join(t.TempDir(), "missing.json"))
	if err == nil {
		t.Fatal("expected an error for a missing targets file")
	}
}

func TestLoadManifestRejectsWrongVersion(t *testing.T) {
	dir := t.TempDir()
	path := writeManifest(t, dir, `{"version":2,"targets":[{"name":"a","src":"."}]}`)
	_, _, err := LoadManifest(path)
	if err == nil || !strings.Contains(err.Error(), "version must be 1") {
		t.Fatalf("err = %v, want a version-1 complaint", err)
	}
}

func TestLoadManifestRejectsNoTargets(t *testing.T) {
	dir := t.TempDir()
	path := writeManifest(t, dir, `{"version":1,"targets":[]}`)
	_, _, err := LoadManifest(path)
	if err == nil || !strings.Contains(err.Error(), "no targets") {
		t.Fatalf("err = %v, want a no-targets complaint", err)
	}
}

func TestLoadManifestRejectsUnknownField(t *testing.T) {
	dir := t.TempDir()
	path := writeManifest(t, dir, `{"version":1,"targets":[{"name":"a","src":".","extra":true}]}`)
	_, _, err := LoadManifest(path)
	if err == nil {
		t.Fatal("expected an error for an unknown field")
	}
}

func TestLoadManifestRejectsTrailingContent(t *testing.T) {
	dir := t.TempDir()
	path := writeManifest(t, dir, `{"version":1,"targets":[{"name":"a","src":"."}]}{}`)
	_, _, err := LoadManifest(path)
	if err == nil || !strings.Contains(err.Error(), "trailing content") {
		t.Fatalf("err = %v, want a trailing-content complaint", err)
	}
}

func TestLoadManifestRejectsBadNames(t *testing.T) {
	for _, name := range []string{"", ".", "..", "../evil", "a/b", "a b", "a\x00b"} {
		dir := t.TempDir()
		path := writeManifest(t, dir, `{"version":1,"targets":[{"name":"`+strings.ReplaceAll(name, `"`, `\"`)+`","src":"."}]}`)
		if _, _, err := LoadManifest(path); err == nil {
			t.Errorf("name %q: expected an error, got none", name)
		}
	}
}

func TestLoadManifestRejectsDuplicateNames(t *testing.T) {
	dir := t.TempDir()
	path := writeManifest(t, dir, `{"version":1,"targets":[{"name":"a","src":"."},{"name":"a","src":".."}]}`)
	_, _, err := LoadManifest(path)
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("err = %v, want a duplicate-name complaint", err)
	}
}

func TestLoadManifestRejectsEmptySrc(t *testing.T) {
	dir := t.TempDir()
	path := writeManifest(t, dir, `{"version":1,"targets":[{"name":"a","src":""}]}`)
	_, _, err := LoadManifest(path)
	if err == nil || !strings.Contains(err.Error(), "src is required") {
		t.Fatalf("err = %v, want a src-required complaint", err)
	}
}
