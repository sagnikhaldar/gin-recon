package gin

import "testing"

// TestDiscoverFollowsFunctionLiteralRegistrars exercises
// resolveCalleeFuncLit/followFuncLitRegistrar via a real typed load of
// testdata/fixtures/func-literal-registrars: registrar-following must work
// through a function literal — a named local variable bound to one, an
// inline IIFE, and a two-level chain of them — exactly as it already does
// for a named function or method value.
func TestDiscoverFollowsFunctionLiteralRegistrars(t *testing.T) {
	pkgs, api := loadFixture(t, "func-literal-registrars")
	pkg, fn := findFunc(t, pkgs, "/func-literal-registrars", "NewRouter")

	reg := Discover(pkg.Fset, pkg.TypesInfo, api, fn, buildFuncIndex(pkgs), nil)

	if len(reg.Diagnostics) != 0 {
		t.Errorf("unexpected diagnostics: %+v", reg.Diagnostics)
	}

	want := map[string]bool{"/named": false, "/inline": false, "/chained": false}
	for _, r := range reg.Routes {
		if r.Method != "GET" {
			t.Errorf("route %s %s: method = %q, want GET", r.Method, r.NormalizedPath, r.Method)
		}
		if _, known := want[r.NormalizedPath]; !known {
			t.Errorf("unexpected route %s", r.NormalizedPath)
			continue
		}
		want[r.NormalizedPath] = true
		if r.FinalHandler.DisplayName != "A" {
			t.Errorf("%s: FinalHandler = %+v, want A", r.NormalizedPath, r.FinalHandler)
		}
	}
	for path, found := range want {
		if !found {
			t.Errorf("expected route %s to be discovered, got routes: %+v", path, reg.Routes)
		}
	}
}
