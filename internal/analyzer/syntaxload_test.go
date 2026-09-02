package analyzer

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/sagnikhaldar/gin-recon/internal/model"
)

func syntaxOpts(src string) LoadOptions {
	return LoadOptions{Src: src, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH}
}

// TestLoadSyntaxMiddlewareOrderFixtureMatchesTypedRouteSet is the primary
// end-to-end proof that syntax-only recovers the same route/middleware-order
// evidence as typed mode for a fixture with no cross-package registrar
// following at all — exactly the "direct Gin-shaped registrations" case
// docs/threat-model.md scopes this profile to. No --allow-downloads is
// needed: LoadSyntax never invokes go/packages or the Go toolchain, so the
// fixture's go.sum/module graph is irrelevant to it.
func TestLoadSyntaxMiddlewareOrderFixtureMatchesTypedRouteSet(t *testing.T) {
	loaded, err := LoadSyntax(context.Background(), syntaxOpts(fixtureDir(t, "middleware-order")))
	if err != nil {
		t.Fatalf("LoadSyntax: %v", err)
	}
	result := InventorySyntax(loaded)

	health := routeByPath(t, result.Routes, "/health")
	if len(health.Middleware) != 0 {
		t.Errorf("/health Middleware = %+v, want none (registered before engine.Use)", health.Middleware)
	}

	adminUsers := routeByPath(t, result.Routes, "/admin/users")
	names := middlewareNames(adminUsers)
	if len(names) != 2 || names[0] != "RequestID" || names[1] != "RequireAuth" {
		t.Errorf("/admin/users Middleware = %v, want [RequestID RequireAuth]", names)
	}

	deleteUser := routeByMethodInResult(t, result.Routes, "DELETE", "/admin/users/:id")
	names = middlewareNames(deleteUser)
	if len(names) != 4 || names[0] != "RequestID" || names[1] != "RequireAuth" || names[2] != "RequireAdmin" || names[3] != "RateLimit" {
		t.Errorf("DELETE /admin/users/:id Middleware = %v, want [RequestID RequireAuth RequireAdmin RateLimit]", names)
	}

	if !result.ScanCoverage.Complete {
		t.Errorf("ScanCoverage.Complete = false, want true for a fixture with no unsupported patterns; diagnostics: %+v", result.Diagnostics)
	}
	if result.ScanCoverage.Profile != model.ProfileSyntaxOnly {
		t.Errorf("ScanCoverage.Profile = %q, want syntax-only", result.ScanCoverage.Profile)
	}
}

func routeByPath(t *testing.T, routes []model.Route, path string) model.Route {
	t.Helper()
	for _, r := range routes {
		if r.NormalizedPath == path {
			return r
		}
	}
	t.Fatalf("route with path %s not found in %+v", path, routes)
	return model.Route{}
}

func routeByMethodInResult(t *testing.T, routes []model.Route, method, path string) model.Route {
	t.Helper()
	for _, r := range routes {
		if r.Method == method && r.NormalizedPath == path {
			return r
		}
	}
	t.Fatalf("route %s %s not found in %+v", method, path, routes)
	return model.Route{}
}

func middlewareNames(r model.Route) []string {
	names := make([]string, len(r.Middleware))
	for i, mw := range r.Middleware {
		names[i] = mw.DisplayName
	}
	return names
}

// TestLoadSyntaxDefaultsModuleModeToReadonly is the regression for a real
// schema-validation bug found by validating live CLI output against
// schema/report-1.0.json: an empty --module-mode (LoadSyntax's typed sibling
// path always resolves one via ResolveModuleMode, but nothing did for
// syntax-only) marshaled as moduleMode:"" wherever BuildContext appears,
// which schema/report-1.0.json's closed enum rejects outright.
func TestLoadSyntaxDefaultsModuleModeToReadonly(t *testing.T) {
	loaded, err := LoadSyntax(context.Background(), syntaxOpts(fixtureDir(t, "middleware-order")))
	if err != nil {
		t.Fatalf("LoadSyntax: %v", err)
	}
	if loaded.BuildContext.ModuleMode != model.ModuleReadonly {
		t.Errorf("ModuleMode = %q, want readonly when --module-mode is unset", loaded.BuildContext.ModuleMode)
	}
}

// TestLoadSyntaxRejectsSymlinkEscapingRoot proves the hermetic walker
// honors docs/threat-model.md's syntax-only requirement verbatim: "Symlinks
// that resolve outside the root are rejected." A symlink pointing outside
// the scan root must never be followed into a .go file that gets parsed and
// contributes routes.
func TestLoadSyntaxRejectsSymlinkEscapingRoot(t *testing.T) {
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.go"), []byte(`package outside

import "github.com/gin-gonic/gin"

func H(c *gin.Context) {}

func NewRouter() *gin.Engine {
	r := gin.New()
	r.GET("/secret", H)
	return r
}
`), 0o644); err != nil {
		t.Fatal(err)
	}

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/app\n\ngo 1.25\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte(`package main

import "github.com/gin-gonic/gin"

func H(c *gin.Context) {}

func NewRouter() *gin.Engine {
	r := gin.New()
	r.GET("/health", H)
	return r
}

func main() {}
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Skipf("symlinks not supported in this environment: %v", err)
	}

	loaded, err := LoadSyntax(context.Background(), syntaxOpts(root))
	if err != nil {
		t.Fatalf("LoadSyntax: %v", err)
	}
	result := InventorySyntax(loaded)
	for _, r := range result.Routes {
		if r.NormalizedPath == "/secret" {
			t.Errorf("route from outside the scan root leaked in via a symlink: %+v", r)
		}
	}
	routeByPath(t, result.Routes, "/health") // the legitimate in-root route must still be found
}

// TestLoadSyntaxToleratesOneMalformedFile confirms a single parse failure
// is reported as a diagnostic and skipped, not treated as fatal for the
// whole scan — a hermetic parser deliberately tolerates malformed input
// elsewhere in a hostile or partially broken checkout.
func TestLoadSyntaxToleratesOneMalformedFile(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/app\n\ngo 1.25\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "broken.go"), []byte(`package main

this is not valid Go syntax {{{
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte(`package main

import "github.com/gin-gonic/gin"

func H(c *gin.Context) {}

func NewRouter() *gin.Engine {
	r := gin.New()
	r.GET("/health", H)
	return r
}

func main() {}
`), 0o644); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadSyntax(context.Background(), syntaxOpts(root))
	if err != nil {
		t.Fatalf("LoadSyntax: %v", err)
	}
	result := InventorySyntax(loaded)
	routeByPath(t, result.Routes, "/health")

	found := false
	for _, d := range result.Diagnostics {
		if d.Code == "gin-syntax-parse-error" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a gin-syntax-parse-error diagnostic for broken.go, got %+v", result.Diagnostics)
	}
	if result.ScanCoverage.Complete {
		t.Error("ScanCoverage.Complete = true, want false with a failed file present")
	}
}

// TestLoadSyntaxFailsOnRootWithNoGoFiles mirrors typed Load's own "fatal
// inability to load the requested root" behavior (docs/report-contract.md).
func TestLoadSyntaxFailsOnRootWithNoGoFiles(t *testing.T) {
	root := t.TempDir()
	if _, err := LoadSyntax(context.Background(), syntaxOpts(root)); err == nil {
		t.Error("LoadSyntax succeeded on an empty directory, want an error")
	}
}

// TestLoadSyntaxSkipsVendorDirectory confirms the walker does not descend
// into a vendor/ tree — scanning a target's own vendored dependency copies
// is never the intent of "inventory this module's routes."
func TestLoadSyntaxSkipsVendorDirectory(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/app\n\ngo 1.25\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte(`package main

import "github.com/gin-gonic/gin"

func H(c *gin.Context) {}

func NewRouter() *gin.Engine {
	r := gin.New()
	r.GET("/health", H)
	return r
}

func main() {}
`), 0o644); err != nil {
		t.Fatal(err)
	}
	vendorDir := filepath.Join(root, "vendor", "example.com", "dep")
	if err := os.MkdirAll(vendorDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vendorDir, "dep.go"), []byte(`package dep

import "github.com/gin-gonic/gin"

func H(c *gin.Context) {}

func NewRouter() *gin.Engine {
	r := gin.New()
	r.GET("/vendored", H)
	return r
}
`), 0o644); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadSyntax(context.Background(), syntaxOpts(root))
	if err != nil {
		t.Fatalf("LoadSyntax: %v", err)
	}
	result := InventorySyntax(loaded)
	for _, r := range result.Routes {
		if r.NormalizedPath == "/vendored" {
			t.Errorf("route from vendor/ leaked into the scan: %+v", r)
		}
	}
}

// TestLoadSyntaxHonorsExcludeGlob confirms --exclude scoping (already
// proven end-to-end for typed mode in scope_test.go) is wired through
// LoadSyntax's own filesystem walk too.
func TestLoadSyntaxHonorsExcludeGlob(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/app\n\ngo 1.25\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte(`package main

import "github.com/gin-gonic/gin"

func H(c *gin.Context) {}

func NewRouter() *gin.Engine {
	r := gin.New()
	r.GET("/health", H)
	return r
}

func main() {}
`), 0o644); err != nil {
		t.Fatal(err)
	}
	otherDir := filepath.Join(root, "internal")
	if err := os.MkdirAll(otherDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(otherDir, "other.go"), []byte(`package internal

import "github.com/gin-gonic/gin"

func H(c *gin.Context) {}

func NewRouter() *gin.Engine {
	r := gin.New()
	r.GET("/excluded", H)
	return r
}
`), 0o644); err != nil {
		t.Fatal(err)
	}

	opts := syntaxOpts(root)
	opts.Exclude = []string{"internal/**"}
	loaded, err := LoadSyntax(context.Background(), opts)
	if err != nil {
		t.Fatalf("LoadSyntax: %v", err)
	}
	result := InventorySyntax(loaded)
	routeByPath(t, result.Routes, "/health")
	for _, r := range result.Routes {
		if r.NormalizedPath == "/excluded" {
			t.Errorf("excluded file's route leaked in: %+v", r)
		}
	}
}
