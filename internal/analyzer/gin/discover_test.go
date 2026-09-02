package gin

import (
	"go/ast"
	"sort"
	"testing"

	"github.com/sagnikhaldar/gin-recon/internal/model"
	"golang.org/x/tools/go/packages"
)

// findFunc locates a top-level function declaration by name in the loaded
// package whose PkgPath has the given suffix (e.g. "/enforcement-shapes" for
// the root package, or "/shapes" for the shapes subpackage).
func findFunc(t *testing.T, pkgs []*packages.Package, pkgPathSuffix, funcName string) (*packages.Package, *ast.FuncDecl) {
	t.Helper()
	for _, pkg := range pkgs {
		if !hasSuffix(pkg.PkgPath, pkgPathSuffix) {
			continue
		}
		for _, file := range pkg.Syntax {
			for _, decl := range file.Decls {
				if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == funcName {
					return pkg, fn
				}
			}
		}
	}
	t.Fatalf("function %s not found in any package matching %q", funcName, pkgPathSuffix)
	return nil, nil
}

func hasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}

func TestDiscoverEnforcementShapesFixtureMatchesManifest(t *testing.T) {
	pkgs, api := loadFixture(t, "enforcement-shapes")
	pkg, fn := findFunc(t, pkgs, "/enforcement-shapes", "NewRouter")

	reg := Discover(pkg.Fset, pkg.TypesInfo, api, fn, buildFuncIndex(pkgs), nil)

	if len(reg.Diagnostics) != 0 {
		t.Errorf("unexpected diagnostics: %+v", reg.Diagnostics)
	}

	// Each fixture route is registered as
	// `r.GET(path, shapes.RequireAuth<Case>, ok)` — one route-scope
	// middleware entry (the guard under test) plus the shared `ok` final
	// handler, per testdata/fixtures/enforcement-shapes/router.go.
	want := map[string]string{
		"/confirmed/direct":               "gin-recon-fixtures/enforcement-shapes/shapes.RequireAuthDirect",
		"/confirmed/delegated-one-level":  "gin-recon-fixtures/enforcement-shapes/shapes.RequireAuthOneLevel",
		"/unresolved/delegated-two-level": "gin-recon-fixtures/enforcement-shapes/shapes.RequireAuthTwoLevel",
		"/unresolved/cross-package":       "gin-recon-fixtures/enforcement-shapes/shapes.RequireAuthCrossPackage",
		"/unresolved/defer-recover":       "gin-recon-fixtures/enforcement-shapes/shapes.RequireAuthDeferRecover",
		"/unresolved/goroutine":           "gin-recon-fixtures/enforcement-shapes/shapes.RequireAuthGoroutine",
		"/contradicted/passthrough":       "gin-recon-fixtures/enforcement-shapes/shapes.RequireAuthAlwaysPasses",
		"/factory/direct":                 "gin-recon-fixtures/enforcement-shapes/shapes.RequireRoleFactory",
		"/factory/one-hop":                "gin-recon-fixtures/enforcement-shapes/shapes.RequireAuthFactory",
		"/factory/too-deep":               "gin-recon-fixtures/enforcement-shapes/shapes.RequireAuthFactoryTooDeep",
		"/factory/cross-package":          "gin-recon-fixtures/enforcement-shapes/shapes.RequireAuthFactoryCrossPackage",
	}
	got := map[string]bool{}
	for _, r := range reg.Routes {
		if r.Method != "GET" {
			t.Errorf("route %s %s: method = %q, want GET", r.Method, r.NormalizedPath, r.Method)
		}
		got[r.NormalizedPath] = true
		wantSymbol, known := want[r.NormalizedPath]
		if !known {
			t.Errorf("unexpected route %s", r.NormalizedPath)
			continue
		}
		if len(r.Middleware) != 1 {
			t.Errorf("route %s: got %d middleware, want exactly 1 (the guard under test)", r.NormalizedPath, len(r.Middleware))
			continue
		}
		if r.Middleware[0].CanonicalSymbol == nil || *r.Middleware[0].CanonicalSymbol != wantSymbol {
			t.Errorf("route %s: middleware canonical symbol = %v, want %q", r.NormalizedPath, r.Middleware[0].CanonicalSymbol, wantSymbol)
		}
		if r.Middleware[0].ResolutionStatus != model.Resolved {
			t.Errorf("route %s: middleware resolutionStatus = %q, want resolved (a same-package function reference)", r.NormalizedPath, r.Middleware[0].ResolutionStatus)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("discovered %d routes, want %d; got: %v", len(got), len(want), got)
	}

	// Every route's final handler should resolve to the same canonical
	// symbol, since router.go registers the same `ok` closure for all six —
	// actually `ok` is a local func literal assigned to a variable, so it
	// should resolve as CallableAnonymous via the func literal, or as an
	// unresolved local identifier reference (ok is a local var, not
	// package-scope) — confirm it's classified consistently rather than
	// silently varying per route.
	var kinds []string
	for _, r := range reg.Routes {
		kinds = append(kinds, string(r.FinalHandler.CallableKind))
	}
	sort.Strings(kinds)
	for _, k := range kinds {
		if k != "identifier" {
			t.Errorf("finalHandler kind = %q for one route, want \"identifier\" (ok is a local variable reference) — got kinds: %v", k, kinds)
		}
	}
}

func TestDiscoverTracksMiddlewareOrderAndGroupScope(t *testing.T) {
	pkgs, api := loadFixture(t, "middleware-order")
	pkg, fn := findFunc(t, pkgs, "/middleware-order", "NewRouter")

	reg := Discover(pkg.Fset, pkg.TypesInfo, api, fn, buildFuncIndex(pkgs), nil)
	if len(reg.Diagnostics) != 0 {
		t.Fatalf("unexpected diagnostics: %+v", reg.Diagnostics)
	}

	var admin *model.Route
	for i := range reg.Routes {
		if reg.Routes[i].Method == "GET" && reg.Routes[i].NormalizedPath == "/admin/users" {
			admin = &reg.Routes[i]
			break
		}
	}
	if admin == nil {
		t.Fatalf("route GET /admin/users not found; routes: %+v", reg.Routes)
	}

	names := func() []string {
		var ns []string
		for _, m := range admin.Middleware {
			ns = append(ns, m.DisplayName)
		}
		return ns
	}()
	want := []string{"RequestID", "RequireAuth"}
	if len(names) != len(want) {
		t.Fatalf("middleware = %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Errorf("middleware[%d] = %q, want %q (order matters: global before group)", i, names[i], want[i])
		}
	}
	if admin.Middleware[0].RegistrationScope != "global" {
		t.Errorf("middleware[0].RegistrationScope = %q, want global", admin.Middleware[0].RegistrationScope)
	}
	if admin.Middleware[1].RegistrationScope != "group" {
		t.Errorf("middleware[1].RegistrationScope = %q, want group", admin.Middleware[1].RegistrationScope)
	}
	if admin.FinalHandler.DisplayName != "ListUsers" {
		t.Errorf("finalHandler = %q, want ListUsers", admin.FinalHandler.DisplayName)
	}
}

func TestDiscoverRouteKindsAndDynamicPathDiagnostic(t *testing.T) {
	pkgs, api := loadFixture(t, "route-kinds")
	pkg, fn := findFunc(t, pkgs, "/route-kinds", "NewRouter")

	reg := Discover(pkg.Fset, pkg.TypesInfo, api, fn, buildFuncIndex(pkgs), nil)

	type routeKey struct{ method, path string }
	got := map[routeKey]bool{}
	for _, r := range reg.Routes {
		got[routeKey{r.Method, r.NormalizedPath}] = true
	}
	want := []routeKey{
		{"POST", "/webhook"},
		// Any() expands to all nine of gin-gonic/gin's own anyMethods,
		// including CONNECT and TRACE — verified against vendored gin
		// source, not assumed (see anyMethods' doc comment in discover.go).
		{"GET", "/wildcard"}, {"POST", "/wildcard"}, {"PUT", "/wildcard"},
		{"PATCH", "/wildcard"}, {"DELETE", "/wildcard"}, {"HEAD", "/wildcard"}, {"OPTIONS", "/wildcard"},
		{"CONNECT", "/wildcard"}, {"TRACE", "/wildcard"},
		{"GET", "/matched"}, {"POST", "/matched"},
		{"GET", "/assets/*filepath"}, {"HEAD", "/assets/*filepath"},
		{"GET", "/favicon.ico"}, {"HEAD", "/favicon.ico"},
		{"GET", "/files/*filepath"}, {"HEAD", "/files/*filepath"},
		{"POST", "/generic"},
	}
	for _, w := range want {
		if !got[routeKey{w.method, w.path}] {
			t.Errorf("missing expected route %s %s", w.method, w.path)
		}
	}
	// The dynamic-path route must NOT silently appear as some literal path —
	// it must be entirely absent from Routes (never guessed at) and instead
	// surfaced only as a diagnostic.
	if len(reg.Routes) != len(want) {
		t.Errorf("got %d routes, want exactly %d (dynamic-path route must be excluded, not guessed): %v", len(reg.Routes), len(want), reg.Routes)
	}

	// The generic middleware's canonical symbol must be the base function,
	// with the type argument discarded — docs/configuration-contract.md:
	// "Generic instantiation arguments... are not part of identity."
	for _, r := range reg.Routes {
		if r.NormalizedPath != "/generic" {
			continue
		}
		var generic *model.Middleware
		for i := range r.Middleware {
			if r.Middleware[i].DisplayName == "BindAndValidate" {
				generic = &r.Middleware[i]
			}
		}
		if generic == nil {
			t.Fatalf("/generic: BindAndValidate middleware not found: %+v", r.Middleware)
		}
		wantSymbol := "gin-recon-fixtures/route-kinds.BindAndValidate"
		if generic.CanonicalSymbol == nil || *generic.CanonicalSymbol != wantSymbol {
			t.Errorf("/generic middleware canonicalSymbol = %v, want %q (type argument must be discarded)", generic.CanonicalSymbol, wantSymbol)
		}
		if generic.ResolutionStatus != model.Resolved {
			t.Errorf("/generic middleware resolutionStatus = %q, want resolved", generic.ResolutionStatus)
		}
	}

	if len(reg.FallbackSurfaces) != 2 {
		t.Fatalf("got %d fallback surfaces, want 2 (NoRoute + NoMethod)", len(reg.FallbackSurfaces))
	}
	var sawNoRoute, sawNoMethod bool
	for _, fb := range reg.FallbackSurfaces {
		switch fb.Kind {
		case model.FallbackNoRoute:
			sawNoRoute = true
		case model.FallbackNoMethod:
			sawNoMethod = true
		}
		// Both fallback surfaces must include the global Logger middleware,
		// since gin-gonic/gin always recombines NoRoute/NoMethod against the
		// engine's current global middleware — see registerFallback's doc
		// comment on why this can't just snapshot state at call time.
		if len(fb.Middleware) != 1 || fb.Middleware[0].DisplayName != "Logger" {
			t.Errorf("fallback %s: middleware = %+v, want exactly [Logger]", fb.Kind, fb.Middleware)
		}
		if fb.FinalHandler.DisplayName != "NotFound" {
			t.Errorf("fallback %s: finalHandler = %q, want NotFound", fb.Kind, fb.FinalHandler.DisplayName)
		}
	}
	if !sawNoRoute || !sawNoMethod {
		t.Errorf("expected both no-route and no-method fallback surfaces, got: %+v", reg.FallbackSurfaces)
	}

	foundDiagnostic := false
	for _, d := range reg.Diagnostics {
		if d.Code == "gin-unresolved-path" {
			foundDiagnostic = true
		}
	}
	if !foundDiagnostic {
		t.Errorf("expected a gin-unresolved-path diagnostic for the dynamic-prefix route, got: %+v", reg.Diagnostics)
	}
}

func TestDiscoverFollowsRegistrarFunctionsAcrossPackagesAndMethods(t *testing.T) {
	pkgs, api := loadFixture(t, "registrar-functions")
	pkg, fn := findFunc(t, pkgs, "/registrar-functions", "NewRouter")
	index := buildFuncIndex(pkgs)

	reg := Discover(pkg.Fset, pkg.TypesInfo, api, fn, index, nil)

	got := map[string]bool{}
	for _, r := range reg.Routes {
		got[r.Method+" "+r.NormalizedPath] = true
	}

	for _, want := range []string{"GET /health", "GET /api/users", "GET /users/:id"} {
		if !got[want] {
			t.Errorf("missing route %s discovered via registrar-following; routes: %v", want, got)
		}
	}
	if got["GET /never-inventoried"] {
		t.Error("route registered inside a callback parameter must NOT be discovered — resolveCalleeFunc does not follow function-typed parameters")
	}
	if len(reg.Routes) != 3 {
		t.Errorf("got %d routes, want exactly 3: %v", len(reg.Routes), reg.Routes)
	}

	foundDiagnostic := false
	for _, d := range reg.Diagnostics {
		if d.Code == "gin-unresolved-registrar" {
			foundDiagnostic = true
		}
	}
	if !foundDiagnostic {
		t.Errorf("expected a gin-unresolved-registrar diagnostic for the callback-parameter call, got: %+v", reg.Diagnostics)
	}
}

// TestDiscoverFollowsRegistrarsThroughIfErrPlainAssignAndReturn is the
// regression for a real false negative found by running gin-recon against a
// production Gin service: "if err := initializeRouter(r, ...); err != nil
// { ... }" — an extremely common idiom for an error-returning registrar
// call — silently hid an entire 120-route API surface. walkStmt never
// visited an *ast.IfStmt's Init clause at all, and handleAssign only ever
// checked an RHS call for producing a fresh engine/group value, never
// falling through to tryFollowRegistrarCall the way handleExprStmt already
// did for a bare "registrar(r)" statement. Both gaps, plus the equivalent
// "return registrar(r)" delegation shape, are fixed together here.
func TestDiscoverFollowsRegistrarsThroughIfErrPlainAssignAndReturn(t *testing.T) {
	pkgs, api := loadFixture(t, "registrar-functions")
	pkg, fn := findFunc(t, pkgs, "/registrar-functions", "NewRouterWithControlFlowRegistrars")
	index := buildFuncIndex(pkgs)

	reg := Discover(pkg.Fset, pkg.TypesInfo, api, fn, index, nil)

	got := map[string]bool{}
	for _, r := range reg.Routes {
		got[r.Method+" "+r.NormalizedPath] = true
	}
	for _, want := range []string{"GET /if-err-registrar", "GET /plain-assign-registrar", "GET /return-registrar"} {
		if !got[want] {
			t.Errorf("missing route %s discovered via registrar-following; routes: %v", want, got)
		}
	}
	if len(reg.Routes) != 3 {
		t.Errorf("got %d routes, want exactly 3: %v", len(reg.Routes), reg.Routes)
	}
	if len(reg.Diagnostics) != 0 {
		t.Errorf("expected no diagnostics for fully resolved registrar calls, got: %+v", reg.Diagnostics)
	}
}

func TestDiscoverWithoutFuncIndexDiagnosesEveryRegistrarCall(t *testing.T) {
	// Confirms the documented fallback behavior: passing a nil index (as the
	// three fixture tests above did before registrar-following existed)
	// must not silently skip anything — every registrar call becomes a
	// diagnostic instead of being followed.
	pkgs, api := loadFixture(t, "registrar-functions")
	pkg, fn := findFunc(t, pkgs, "/registrar-functions", "NewRouter")

	reg := Discover(pkg.Fset, pkg.TypesInfo, api, fn, nil, nil)

	if len(reg.Routes) != 0 {
		t.Errorf("got %d routes with no func index, want 0 (nothing should be followed): %v", len(reg.Routes), reg.Routes)
	}
	if len(reg.Diagnostics) < 3 {
		t.Errorf("got %d diagnostics with no func index, want at least 3 (one per registrar call site): %+v", len(reg.Diagnostics), reg.Diagnostics)
	}
}

// TestDiscoverResolvesUnambiguousEngineFactoryButNotAmbiguousOne exercises
// resolveEngineFactoryCall's exact boundary via testdata/fixtures/untracked-factory:
// a factory whose return statements agree on which engine they return
// resolves as if inlined — including middleware/routes the factory applied
// to the engine before returning it — while a factory whose return
// statements disagree is still left untracked with the pre-existing
// gin-untracked-router-value diagnostic, never guessed at.
func TestDiscoverResolvesUnambiguousEngineFactoryButNotAmbiguousOne(t *testing.T) {
	pkgs, api := loadFixture(t, "untracked-factory")
	pkg, fn := findFunc(t, pkgs, "/untracked-factory", "NewRouter")

	reg := Discover(pkg.Fset, pkg.TypesInfo, api, fn, buildFuncIndex(pkgs), nil)

	wantRoutes := map[string][]string{ // normalizedPath -> want middleware DisplayNames
		"/resolved-factory":   nil,
		"/factory-internal":   {"RequestLogger"},
		"/via-logged-factory": {"RequestLogger"},
	}
	seen := map[string]bool{}
	for _, r := range reg.Routes {
		if r.NormalizedPath == "/never-inventoried" {
			t.Errorf("route %s was discovered, want it to stay untracked — its factory's return statements are ambiguous", r.NormalizedPath)
			continue
		}
		want, ok := wantRoutes[r.NormalizedPath]
		if !ok {
			t.Errorf("unexpected route %s %s", r.Method, r.NormalizedPath)
			continue
		}
		seen[r.NormalizedPath] = true
		var got []string
		for _, mw := range r.Middleware {
			got = append(got, mw.DisplayName)
		}
		if len(got) != len(want) {
			t.Errorf("%s: Middleware = %v, want %v", r.NormalizedPath, got, want)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("%s: Middleware = %v, want %v", r.NormalizedPath, got, want)
				break
			}
		}
	}
	for path := range wantRoutes {
		if !seen[path] {
			t.Errorf("expected route %s to be discovered, got routes: %+v", path, reg.Routes)
		}
	}

	found := false
	for _, d := range reg.Diagnostics {
		if d.Code == "gin-untracked-router-value" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a gin-untracked-router-value diagnostic for the ambiguous factory, got: %+v", reg.Diagnostics)
	}
}
