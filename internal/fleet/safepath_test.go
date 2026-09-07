package fleet

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sagnikhaldar/gin-recon/internal/config"
)

func TestReadBoundedFileRejectsOversizedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "huge.json")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	// A sparse file: Truncate sets the file's reported size without actually
	// writing config.HardCapMaxOutputBytes+1 bytes to disk, so this test
	// stays fast regardless of the real limit's magnitude.
	if err := f.Truncate(config.HardCapMaxOutputBytes + 1); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := ReadBoundedFile(path); err == nil {
		t.Fatal("ReadBoundedFile succeeded on an oversized file, want an error")
	}
}

func TestReadBoundedFileRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.json")
	if err := os.WriteFile(real, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	if _, err := ReadBoundedFile(link); err == nil {
		t.Fatal("ReadBoundedFile succeeded on a symlink, want an error")
	}
}

func TestReadBoundedFileAcceptsARegularFileWithinLimits(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ok.json")
	want := []byte(`{"hello":"world"}`)
	if err := os.WriteFile(path, want, 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := ReadBoundedFile(path)
	if err != nil {
		t.Fatalf("ReadBoundedFile: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("ReadBoundedFile = %q, want %q", got, want)
	}
}
