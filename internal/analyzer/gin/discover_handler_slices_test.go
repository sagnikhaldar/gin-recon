package gin

import (
	"strings"
	"testing"
)

// TestDiscoverResolvesLiteralHandlerSliceSpread exercises
// resolveHandlerSlice via a real typed load of
// testdata/fixtures/handler-slices, per its manifest.json: an inline or
// same-function-local literal []gin.HandlerFunc spread resolves to its
// individual handlers, while a function-call result or a keyed composite
// stays honestly unresolved.
func TestDiscoverResolvesLiteralHandlerSliceSpread(t *testing.T) {
	pkgs, api := loadFixture(t, "handler-slices")
	pkg, fn := findFunc(t, pkgs, "/handler-slices", "NewRouter")

	reg := Discover(pkg.Fset, pkg.TypesInfo, api, fn, buildFuncIndex(pkgs), nil)

	wantResolved := map[string]string{ // normalizedPath -> want middleware[0] DisplayName
		"/inline": "A",
		"/named":  "A",
	}
	seen := map[string]bool{}
	for _, r := range reg.Routes {
		seen[r.NormalizedPath] = true
		want, ok := wantResolved[r.NormalizedPath]
		if !ok {
			t.Errorf("unexpected resolved route %s %s", r.Method, r.NormalizedPath)
			continue
		}
		if len(r.Middleware) != 1 || r.Middleware[0].DisplayName != want {
			t.Errorf("%s: Middleware = %+v, want [%s]", r.NormalizedPath, r.Middleware, want)
		}
		if r.FinalHandler.DisplayName != "B" {
			t.Errorf("%s: FinalHandler = %+v, want B", r.NormalizedPath, r.FinalHandler)
		}
	}
	for path := range wantResolved {
		if !seen[path] {
			t.Errorf("expected route %s to be discovered, got routes: %+v", path, reg.Routes)
		}
	}

	// /dynamic and /keyed must never be fabricated.
	for _, path := range []string{"/dynamic", "/keyed"} {
		if seen[path] {
			t.Errorf("route %s was discovered, want it to stay unresolved (not a literal slice)", path)
		}
	}

	diagnosedPaths := map[string]bool{}
	for _, d := range reg.Diagnostics {
		if d.Code != "gin-unresolved-handlers" {
			continue
		}
		switch {
		case strings.Contains(d.Message, "/dynamic"):
			diagnosedPaths["/dynamic"] = true
		case strings.Contains(d.Message, "/keyed"):
			diagnosedPaths["/keyed"] = true
		}
	}
	if !diagnosedPaths["/dynamic"] {
		t.Errorf("expected a gin-unresolved-handlers diagnostic mentioning /dynamic, got: %+v", reg.Diagnostics)
	}
	if !diagnosedPaths["/keyed"] {
		t.Errorf("expected a gin-unresolved-handlers diagnostic mentioning /keyed, got: %+v", reg.Diagnostics)
	}
}
