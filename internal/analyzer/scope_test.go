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
