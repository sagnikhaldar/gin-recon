package analyzer

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/sagnikhaldar/gin-recon/internal/model"
)

func fixtureDir(t *testing.T, name string) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not determine repo-relative fixture path")
	}
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")
	return filepath.Join(repoRoot, "testdata", "fixtures", name)
}

func loadAndInventory(t *testing.T, fixture string) *InventoryResult {
	t.Helper()
	loaded, err := Load(context.Background(), LoadOptions{
		Src:        fixtureDir(t, fixture),
		GOOS:       runtime.GOOS,
		GOARCH:     runtime.GOARCH,
		ModuleMode: model.ModuleReadonly,
		// AllowDownloads is a test-environment concession to populate the
		// persistent tool-owned module cache on first run; it is NOT the
		// production CLI default, which stays offline (docs/cli-contract.md:
		// "--allow-downloads ... default false").
		AllowDownloads: true,
	})
	if err != nil {
		t.Fatalf("Load(%s): %v", fixture, err)
	}
	if len(loaded.LoadErrors) != 0 {
		t.Fatalf("Load(%s) reported load errors: %+v", fixture, loaded.LoadErrors)
	}
	return Inventory(loaded)
}

func TestInventoryEndToEndMiddlewareOrderFixture(t *testing.T) {
	result := loadAndInventory(t, "middleware-order")

	if result.Module != "gin-recon-fixtures/middleware-order" {
		t.Errorf("Module = %q, want gin-recon-fixtures/middleware-order", result.Module)
	}
	if len(result.Diagnostics) != 0 {
		t.Errorf("unexpected diagnostics: %+v", result.Diagnostics)
	}
	if !result.ScanCoverage.Complete {
		t.Errorf("ScanCoverage.Complete = false, want true: %+v", result.ScanCoverage)
	}
	if result.ScanCoverage.DiscoveredPackages == 0 {
		t.Error("ScanCoverage.DiscoveredPackages = 0, want at least 1")
	}

	got := map[string]bool{}
	for _, r := range result.Routes {
		got[r.Method+" "+r.NormalizedPath] = true
	}
	for _, want := range []string{"GET /health", "GET /admin/users", "DELETE /admin/users/:id"} {
		if !got[want] {
			t.Errorf("missing route %s; got: %v", want, got)
		}
	}
	if len(result.Routes) != 3 {
		t.Errorf("got %d routes, want 3: %v", len(result.Routes), result.Routes)
	}
}

// TestInventoryPopulatesSourceAndBuildContext is the regression test for two
// bugs caught by inspecting real CLI output: model.Middleware.Source was
// never populated at all (buildMiddlewareList silently dropped it), and
// model.Route.Source carried the absolute checkout path instead of a
// root-relative one, violating docs/cli-contract.md's "never absolute
// checkout paths" rule. Both were invisible to every prior test because none
// asserted on Source or BuildContext specifically.
func TestInventoryPopulatesSourceAndBuildContext(t *testing.T) {
	result := loadAndInventory(t, "middleware-order")

	var admin *model.Route
	for i := range result.Routes {
		if result.Routes[i].Method == "GET" && result.Routes[i].NormalizedPath == "/admin/users" {
			admin = &result.Routes[i]
		}
	}
	if admin == nil {
		t.Fatalf("route GET /admin/users not found; routes: %+v", result.Routes)
	}

	if admin.Source == nil {
		t.Fatal("route Source is nil, want populated")
	}
	if filepath.IsAbs(admin.Source.File) {
		t.Errorf("route Source.File = %q, want root-relative, not absolute", admin.Source.File)
	}
	if admin.Source.File != "router.go" {
		t.Errorf("route Source.File = %q, want %q", admin.Source.File, "router.go")
	}

	if admin.BuildContext.GOOS == "" {
		t.Error("route BuildContext.GOOS is empty, want populated")
	}
	if admin.BuildContext.GOOS != result.ScanCoverage.BuildContext.GOOS ||
		admin.BuildContext.GOARCH != result.ScanCoverage.BuildContext.GOARCH ||
		admin.BuildContext.Profile != result.ScanCoverage.BuildContext.Profile {
		t.Errorf("route BuildContext = %+v, want it to match ScanCoverage.BuildContext = %+v", admin.BuildContext, result.ScanCoverage.BuildContext)
	}

	for _, mw := range admin.Middleware {
		if mw.Source == nil {
			t.Errorf("middleware %q Source is nil, want populated", mw.DisplayName)
			continue
		}
		if filepath.IsAbs(mw.Source.File) {
			t.Errorf("middleware %q Source.File = %q, want root-relative", mw.DisplayName, mw.Source.File)
		}
	}
}

func TestInventoryEndToEndRegistrarFunctionsFixture(t *testing.T) {
	result := loadAndInventory(t, "registrar-functions")

	got := map[string]bool{}
	for _, r := range result.Routes {
		got[r.Method+" "+r.NormalizedPath] = true
	}
	for _, want := range []string{"GET /health", "GET /api/users", "GET /users/:id"} {
		if !got[want] {
			t.Errorf("missing route %s discovered via whole-module registrar-following; got: %v", want, got)
		}
	}
	if got["GET /never-inventoried"] {
		t.Error("callback-registered route must not appear")
	}

	foundDiagnostic := false
	for _, d := range result.Diagnostics {
		if d.Code == "gin-unresolved-registrar" {
			foundDiagnostic = true
		}
	}
	if !foundDiagnostic {
		t.Errorf("expected a gin-unresolved-registrar diagnostic, got: %+v", result.Diagnostics)
	}
	if result.ScanCoverage.Complete {
		t.Error("ScanCoverage.Complete = true, want false — this fixture has an unresolved registrar call")
	}
	if result.ScanCoverage.UnresolvedRegistrations == 0 {
		t.Error("ScanCoverage.UnresolvedRegistrations = 0, want at least 1")
	}
}

func TestInventoryResultIsDeterministicAcrossRuns(t *testing.T) {
	first := loadAndInventory(t, "route-kinds")
	second := loadAndInventory(t, "route-kinds")

	if len(first.Routes) != len(second.Routes) {
		t.Fatalf("route count differs across runs: %d vs %d", len(first.Routes), len(second.Routes))
	}
	for i := range first.Routes {
		a, b := first.Routes[i], second.Routes[i]
		if a.Method != b.Method || a.NormalizedPath != b.NormalizedPath {
			t.Errorf("route order differs at index %d: %s %s vs %s %s", i, a.Method, a.NormalizedPath, b.Method, b.NormalizedPath)
		}
	}
}

func TestInventoryOnNonGinPackageIsEmptyNotError(t *testing.T) {
	// gin-recon's own internal/model package: a real, valid Go package
	// within a real module that has no Gin usage at all — must produce an
	// empty, unremarkable result rather than an error.
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not determine repo-relative path")
	}
	modelDir := filepath.Join(filepath.Dir(thisFile), "..", "model")

	loaded, err := Load(context.Background(), LoadOptions{
		Src:        modelDir,
		GOOS:       runtime.GOOS,
		GOARCH:     runtime.GOARCH,
		ModuleMode: model.ModuleReadonly,
	})
	if err != nil {
		t.Fatalf("Load(internal/model): %v", err)
	}
	if len(loaded.LoadErrors) != 0 {
		t.Fatalf("Load(internal/model) reported load errors: %+v", loaded.LoadErrors)
	}
	result := Inventory(loaded)
	if len(result.Routes) != 0 {
		t.Errorf("got %d routes for a non-Gin target, want 0", len(result.Routes))
	}
	if len(result.Diagnostics) != 0 {
		t.Errorf("got %d diagnostics for a non-Gin target, want 0: %+v", len(result.Diagnostics), result.Diagnostics)
	}
}
