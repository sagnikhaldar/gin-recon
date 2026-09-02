package analyzer

import (
	"context"
	"runtime"
	"testing"

	"github.com/sagnikhaldar/gin-recon/internal/model"
)

// TestInventoryResolvesStructLiteralAndPseudoConstRegistrars is the
// regression for a real completeness gap found scanning two production
// services (30 unresolved routes in one, 34 in the other) that both use a
// generic, data-driven registrar helper called from many sites with a
// literal Route{...} argument, some fields set from package-level `var`
// HTTP-method identifiers rather than real `const`s. It also proves the
// negative case: a var that is reassigned anywhere in its own package must
// never be trusted, even though it looks identical to a genuine
// pseudo-const at its declaration.
func TestInventoryResolvesStructLiteralAndPseudoConstRegistrars(t *testing.T) {
	loaded, err := Load(context.Background(), LoadOptions{
		Src:            fixtureDir(t, "struct-literal-registrar"),
		GOOS:           runtime.GOOS,
		GOARCH:         runtime.GOARCH,
		ModuleMode:     model.ModuleReadonly,
		AllowDownloads: true,
	})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	result := Inventory(loaded)

	want := map[string]bool{
		"/api/keyed":        false,
		"/api/positional":   false,
		"/api/pseudo-const": false,
		"/api/concat/GET":   false,
	}
	for _, r := range result.Routes {
		if r.NormalizedPath == "/api/never-inventoried" {
			t.Errorf("route %s was discovered, want it to stay unresolved — its Method comes from a var (Mutable) reassigned elsewhere in the package", r.NormalizedPath)
			continue
		}
		if _, known := want[r.NormalizedPath]; known {
			want[r.NormalizedPath] = true
		}
	}
	for path, found := range want {
		if !found {
			t.Errorf("expected route %s to be discovered, got routes: %+v", path, result.Routes)
		}
	}

	found := false
	for _, d := range result.Diagnostics {
		if d.Code == "gin-unresolved-method" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a gin-unresolved-method diagnostic for the never-inventoried route, got: %+v", result.Diagnostics)
	}
}
