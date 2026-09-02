package analyzer

import (
	"context"
	"runtime"
	"strings"
	"testing"

	"github.com/sagnikhaldar/gin-recon/internal/model"
)

func loadCrossModuleTarget(t *testing.T, followModules []string) *Loaded {
	t.Helper()
	loaded, err := Load(context.Background(), LoadOptions{
		Src:            fixtureDir(t, "cross-module-target"),
		GOOS:           runtime.GOOS,
		GOARCH:         runtime.GOARCH,
		ModuleMode:     model.ModuleReadonly,
		AllowDownloads: true,
		FollowModules:  followModules,
	})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return loaded
}

// TestInventoryWithoutFollowModulesLeavesCrossModuleRegistrarUnresolved is
// the baseline: without analysis.followModules configured, a registrar call
// into a genuinely separate Go module (cross-module-library, wired in via
// a go.mod replace directive exactly like the real production repos this
// feature was built for) must stay unresolved, with a diagnostic naming the
// exact external symbol — never silently followed, and never left as a
// generic, unhelpful message.
func TestInventoryWithoutFollowModulesLeavesCrossModuleRegistrarUnresolved(t *testing.T) {
	loaded := loadCrossModuleTarget(t, nil)
	result := Inventory(loaded)

	for _, r := range result.Routes {
		if r.NormalizedPath == "/api/webhook" {
			t.Errorf("route %s was discovered without analysis.followModules configured, want it to stay unresolved", r.NormalizedPath)
		}
	}
	found := false
	for _, d := range result.Diagnostics {
		if d.Code == "gin-unresolved-registrar" && strings.Contains(d.Message, "gin-recon-fixtures/cross-module-library.Init") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a gin-unresolved-registrar diagnostic naming gin-recon-fixtures/cross-module-library.Init, got: %+v", result.Diagnostics)
	}
}

// TestInventoryWithFollowModulesResolvesCrossModuleRegistrar is the positive
// case: with the library module explicitly opted in via
// analysis.followModules, its Init function's route (and the middleware it
// applies) must be fully resolved, with a Source that is a stable
// "module@version/relative/path" label — never a raw absolute filesystem
// path, which would leak local module-cache layout and violate
// docs/cli-contract.md's "never absolute checkout paths" for a path that
// was never under --src to begin with.
func TestInventoryWithFollowModulesResolvesCrossModuleRegistrar(t *testing.T) {
	loaded := loadCrossModuleTarget(t, []string{"gin-recon-fixtures/cross-module-library"})
	result := Inventory(loaded)

	var route *model.Route
	for i := range result.Routes {
		if result.Routes[i].NormalizedPath == "/api/webhook" {
			route = &result.Routes[i]
		}
	}
	if route == nil {
		t.Fatalf("expected POST /api/webhook to be discovered, got routes: %+v", result.Routes)
	}
	if route.Method != "POST" {
		t.Errorf("Method = %q, want POST", route.Method)
	}
	if route.Source == nil || strings.HasPrefix(route.Source.File, "/") {
		t.Errorf("Source = %+v, want a non-absolute module@version label, never a raw filesystem path", route.Source)
	}
	if route.Source == nil || !strings.HasPrefix(route.Source.File, "gin-recon-fixtures/cross-module-library@") {
		t.Errorf("Source.File = %v, want it to start with the library module's own path", route.Source)
	}
	if len(route.Middleware) != 1 || route.Middleware[0].CanonicalSymbol == nil || *route.Middleware[0].CanonicalSymbol != "gin-recon-fixtures/cross-module-library.LogMiddleware" {
		t.Errorf("Middleware = %+v, want LogMiddleware resolved with its canonical symbol", route.Middleware)
	}
	if route.FinalHandler.CanonicalSymbol == nil || *route.FinalHandler.CanonicalSymbol != "gin-recon-fixtures/cross-module-library.Handler" {
		t.Errorf("FinalHandler = %+v, want Handler resolved with its canonical symbol", route.FinalHandler)
	}

	for _, d := range result.Diagnostics {
		if d.Code == "gin-unresolved-registrar" {
			t.Errorf("unexpected gin-unresolved-registrar diagnostic with analysis.followModules configured: %+v", d)
		}
	}

	health := false
	for _, r := range result.Routes {
		if r.NormalizedPath == "/health" {
			health = true
			if r.Source == nil || strings.Contains(r.Source.File, "@") {
				t.Errorf("the target module's own route Source = %+v, must stay a plain root-relative path, unaffected by cross-module resolution", r.Source)
			}
		}
	}
	if !health {
		t.Error("expected the target module's own GET /health route to still be discovered")
	}
}

// TestInventoryFollowModulesGlobDoesNotMatchUnlistedModule confirms the
// glob is exact: a pattern that does not match the library's actual module
// path must not accidentally resolve it either.
func TestInventoryFollowModulesGlobDoesNotMatchUnlistedModule(t *testing.T) {
	loaded := loadCrossModuleTarget(t, []string{"github.com/totally/unrelated"})
	result := Inventory(loaded)
	for _, r := range result.Routes {
		if r.NormalizedPath == "/api/webhook" {
			t.Errorf("route %s was discovered via a non-matching followModules pattern", r.NormalizedPath)
		}
	}
}
