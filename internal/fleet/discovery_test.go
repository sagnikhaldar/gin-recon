package fleet

import (
	"os"
	"path/filepath"
	"testing"
)

func writeDiscoveryFile(t *testing.T, root, relative, contents string) {
	t.Helper()
	path := filepath.Join(root, relative)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoverRepositoryFindsNestedModulesWithoutRootGoMod(t *testing.T) {
	root := t.TempDir()
	writeDiscoveryFile(t, root, "go.work", "go 1.25\n\nuse (\n\t./services/api\n\t./workers/jobs\n)\n")
	writeDiscoveryFile(t, root, "services/api/go.mod", "module example.com/api\n")
	writeDiscoveryFile(t, root, "services/api/main.go", "package main\n")
	writeDiscoveryFile(t, root, "workers/jobs/go.mod", "module example.com/jobs\n")
	writeDiscoveryFile(t, root, "workers/jobs/main.go", "package main\n")

	got, err := discoverRepository(root)
	if err != nil {
		t.Fatalf("discoverRepository: %v", err)
	}
	if got.Kind != RepositoryMultiModule || len(got.Modules) != 2 || !got.HasGoWork {
		t.Fatalf("discovery = %+v, want two-module go.work repository", got)
	}
	if got.Modules[0].RelPath != "services/api" || got.Modules[1].RelPath != "workers/jobs" {
		t.Fatalf("module paths = %+v", got.Modules)
	}
	if got.Modules[0].ID == got.Modules[1].ID || got.Modules[0].ID == "" {
		t.Fatalf("module IDs are not stable and distinct: %+v", got.Modules)
	}
}

func TestDiscoverRepositoryDistinguishesNoGoFromGoWithoutModule(t *testing.T) {
	noGo := t.TempDir()
	writeDiscoveryFile(t, noGo, "README.md", "fixture")
	got, err := discoverRepository(noGo)
	if err != nil || got.Kind != RepositoryNoGo {
		t.Fatalf("no-Go discovery = %+v, %v", got, err)
	}

	goWithoutModule := t.TempDir()
	writeDiscoveryFile(t, goWithoutModule, "main.go", "package main\n")
	got, err = discoverRepository(goWithoutModule)
	if err != nil || got.Kind != RepositoryGoNoModule {
		t.Fatalf("Go-without-module discovery = %+v, %v", got, err)
	}
}

func TestDiscoverRepositoryDoesNotFollowSymlinkedModule(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	writeDiscoveryFile(t, outside, "go.mod", "module example.com/outside\n")
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	got, err := discoverRepository(root)
	if err != nil {
		t.Fatalf("discoverRepository: %v", err)
	}
	if len(got.Modules) != 0 {
		t.Fatalf("followed symlink outside root: %+v", got.Modules)
	}
}

func TestDiscoverRepositoryFingerprintChangesWithGoSource(t *testing.T) {
	root := t.TempDir()
	writeDiscoveryFile(t, root, "go.mod", "module example.com/app\n")
	writeDiscoveryFile(t, root, "main.go", "package main\n")
	before, err := discoverRepository(root)
	if err != nil {
		t.Fatal(err)
	}
	writeDiscoveryFile(t, root, "main.go", "package main\n\nfunc main() {}\n")
	after, err := discoverRepository(root)
	if err != nil {
		t.Fatal(err)
	}
	if before.Fingerprint == after.Fingerprint {
		t.Fatal("repository source fingerprint did not change after Go source changed")
	}
}

func TestValidModuleID(t *testing.T) {
	for _, id := range []string{"root", "module-0123456789abcdef"} {
		if err := ValidModuleID(id); err != nil {
			t.Errorf("ValidModuleID(%q): %v", id, err)
		}
	}
	for _, id := range []string{"", "../escape", "module-short", "module-0123456789abcdeg"} {
		if err := ValidModuleID(id); err == nil {
			t.Errorf("ValidModuleID(%q) unexpectedly succeeded", id)
		}
	}
}

func TestDiscoverRepositoryRejectsWorkspaceUseOutsideRepository(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	writeDiscoveryFile(t, outside, "go.mod", "module example.com/outside\n")
	writeDiscoveryFile(t, root, "go.work", "go 1.25\n\nuse "+filepath.ToSlash(outside)+"\n")
	if _, err := discoverRepository(root); err == nil {
		t.Fatal("expected external go.work use to make repository discovery inconclusive")
	}
}

func TestDiscoverRepositoryCountsButDoesNotScanDependencyModules(t *testing.T) {
	root := t.TempDir()
	writeDiscoveryFile(t, root, "go.mod", "module example.com/app\n")
	writeDiscoveryFile(t, root, "vendor/example.com/dep/go.mod", "module example.com/dep\n")
	writeDiscoveryFile(t, root, "node_modules/tool/go.mod", "module example.com/tool\n")
	got, err := discoverRepository(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Modules) != 1 || got.Modules[0].RelPath != "." {
		t.Fatalf("dependency module roots leaked into application inventory: %+v", got.Modules)
	}
	if got.Files != 3 {
		t.Fatalf("Files = %d, want all three files counted toward repository bounds", got.Files)
	}
}
