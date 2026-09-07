package analyzer

import (
	"context"
	"runtime"
	"testing"

	"github.com/sagnikhaldar/gin-recon/internal/model"
)

// TestLoadExcludeRemovesFileFromEveryConsumer is the regression for a real
// gap: --include/--exclude/ignoreFile were parsed by internal/cli and
// schema-validated by internal/config, but LoadOptions had no Include/
// Exclude fields at all — packages.Load always loaded "./..." unconditionally
// regardless of what the CLI or a config file said. registrar-functions'
// cross-package route ("/api/users", registered via
// routes.RegisterAPIRoutes(r) in a separate file/package) is exactly the
// right fixture to prove exclusion is honored everywhere, not just in the
// route list: excluding that file must also remove it from the whole-module
// function index, so the registrar call that reaches into now-excluded
// scope honestly surfaces as gin-unresolved-registrar (the same diagnostic
// an external/unavailable-source callee already produces) instead of
// silently vanishing with no signal at all.
func TestLoadExcludeRemovesFileFromEveryConsumer(t *testing.T) {
	loaded, err := Load(context.Background(), LoadOptions{
		Src:            fixtureDir(t, "registrar-functions"),
		GOOS:           runtime.GOOS,
		GOARCH:         runtime.GOARCH,
		ModuleMode:     model.ModuleReadonly,
		AllowDownloads: true,
		Exclude:        []string{"routes/**"},
	})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(loaded.LoadErrors) != 0 {
		t.Fatalf("Load reported load errors: %+v", loaded.LoadErrors)
	}

	result := Inventory(loaded)
	for _, r := range result.Routes {
		if r.NormalizedPath == "/api/users" {
			t.Errorf("excluded file's route /api/users still present: %+v", r)
		}
	}
	foundDiagnostic := false
	for _, d := range result.Diagnostics {
		if d.Code == "gin-unresolved-registrar" {
			foundDiagnostic = true
		}
	}
	if !foundDiagnostic {
		t.Errorf("expected gin-unresolved-registrar once routes.RegisterAPIRoutes's file is excluded, got: %+v", result.Diagnostics)
	}

	// The routes NOT touching the excluded file must be completely
	// unaffected — exclusion must not have collateral effects on the rest
	// of the same module.
	foundHealth := false
	for _, r := range result.Routes {
		if r.NormalizedPath == "/health" {
			foundHealth = true
		}
	}
	if !foundHealth {
		t.Error("expected /health (registered outside the excluded file) to still be discovered")
	}
}

func TestLoadIncludeRestrictsScanToMatchingFiles(t *testing.T) {
	loaded, err := Load(context.Background(), LoadOptions{
		Src:            fixtureDir(t, "registrar-functions"),
		GOOS:           runtime.GOOS,
		GOARCH:         runtime.GOARCH,
		ModuleMode:     model.ModuleReadonly,
		AllowDownloads: true,
		Include:        []string{"routes/**"},
	})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	result := Inventory(loaded)
	// Nothing constructs a gin.Engine inside routes/routes.go (RegisterAPIRoutes
	// only registers onto an engine value it receives as a parameter), so
	// restricting the scan to just that file must yield zero routes: there is
	// no entry point left for Discover to start from.
	if len(result.Routes) != 0 {
		t.Errorf("expected 0 routes when scan is restricted to routes/**, got: %+v", result.Routes)
	}
}

func TestLoadWithNoScopeOptionsScansEverything(t *testing.T) {
	loaded, err := Load(context.Background(), LoadOptions{
		Src:            fixtureDir(t, "registrar-functions"),
		GOOS:           runtime.GOOS,
		GOARCH:         runtime.GOARCH,
		ModuleMode:     model.ModuleReadonly,
		AllowDownloads: true,
	})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	result := Inventory(loaded)
	foundAPIUsers := false
	for _, r := range result.Routes {
		if r.NormalizedPath == "/api/users" {
			foundAPIUsers = true
		}
	}
	if !foundAPIUsers {
		t.Error("expected /api/users to be discovered with no Include/Exclude restriction")
	}
}

// hasRoute reports whether routes contains one at path, for the
// --include-tests regression tests below.
func hasRoute(routes []model.Route, path string) bool {
	for _, r := range routes {
		if r.NormalizedPath == path {
			return true
		}
	}
	return false
}

// TestLoadIncludeTestsIsOffByDefault is a regression test for a real gap:
// --include-tests (cli.Options.IncludeTests) was parsed and schema-validated
// but never actually threaded into LoadOptions at all — packages.Config's
// Tests field was hardcoded false regardless of the flag. The
// include-tests fixture's /test-only-route lives only in router_test.go;
// without IncludeTests it must be invisible, same as before this fix.
func TestLoadIncludeTestsIsOffByDefault(t *testing.T) {
	loaded, err := Load(context.Background(), LoadOptions{
		Src:            fixtureDir(t, "include-tests"),
		GOOS:           runtime.GOOS,
		GOARCH:         runtime.GOARCH,
		ModuleMode:     model.ModuleReadonly,
		AllowDownloads: true,
	})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	result := Inventory(loaded)
	if !hasRoute(result.Routes, "/always-visible") {
		t.Errorf("expected /always-visible to be discovered, got: %+v", result.Routes)
	}
	if hasRoute(result.Routes, "/test-only-route") {
		t.Errorf("expected /test-only-route to be invisible without --include-tests, got: %+v", result.Routes)
	}
}

// TestLoadIncludeTestsScansTestFiles proves the flag actually does something
// once set — the fix half of the regression above.
func TestLoadIncludeTestsScansTestFiles(t *testing.T) {
	loaded, err := Load(context.Background(), LoadOptions{
		Src:            fixtureDir(t, "include-tests"),
		GOOS:           runtime.GOOS,
		GOARCH:         runtime.GOARCH,
		ModuleMode:     model.ModuleReadonly,
		AllowDownloads: true,
		IncludeTests:   true,
	})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	result := Inventory(loaded)
	if !hasRoute(result.Routes, "/always-visible") {
		t.Errorf("expected /always-visible to still be discovered, got: %+v", result.Routes)
	}
	if !hasRoute(result.Routes, "/test-only-route") {
		t.Errorf("expected /test-only-route to be discovered with --include-tests, got: %+v", result.Routes)
	}
}

// TestLoadSyntaxIncludeTestsScansTestFiles is the syntax-only-mode
// equivalent — syntaxload.go hardcoded its own, separate _test.go exclusion
// (it never uses go/packages, so packages.Config.Tests does not apply
// there), unconditionally, with no way to override it at all before this
// fix.
func TestLoadSyntaxIncludeTestsScansTestFiles(t *testing.T) {
	without, err := LoadSyntax(context.Background(), LoadOptions{
		Src:    fixtureDir(t, "include-tests"),
		GOOS:   runtime.GOOS,
		GOARCH: runtime.GOARCH,
	})
	if err != nil {
		t.Fatalf("LoadSyntax: %v", err)
	}
	withoutResult := InventorySyntax(without)
	if hasRoute(withoutResult.Routes, "/test-only-route") {
		t.Errorf("expected /test-only-route to be invisible without --include-tests, got: %+v", withoutResult.Routes)
	}

	with, err := LoadSyntax(context.Background(), LoadOptions{
		Src:          fixtureDir(t, "include-tests"),
		GOOS:         runtime.GOOS,
		GOARCH:       runtime.GOARCH,
		IncludeTests: true,
	})
	if err != nil {
		t.Fatalf("LoadSyntax: %v", err)
	}
	withResult := InventorySyntax(with)
	if !hasRoute(withResult.Routes, "/test-only-route") {
		t.Errorf("expected /test-only-route to be discovered with --include-tests, got: %+v", withResult.Routes)
	}
	if !hasRoute(withResult.Routes, "/always-visible") {
		t.Errorf("expected /always-visible to still be discovered, got: %+v", withResult.Routes)
	}
}
