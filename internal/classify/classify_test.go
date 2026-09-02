package classify

import (
	"go/ast"
	"go/types"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/sagnikhaldar/gin-recon/internal/analyzer/gin"
	"github.com/sagnikhaldar/gin-recon/internal/config"
	"github.com/sagnikhaldar/gin-recon/internal/model"
	"github.com/sagnikhaldar/gin-recon/internal/report"
	"golang.org/x/tools/go/packages"
)

// loadEnforcementShapesFixture loads the real fixture module and runs
// Discover across it, mirroring what internal/analyzer's orchestration does,
// so this package's tests exercise the same real compiled-Gin-type pipeline
// internal/analyzer/gin's own tests do rather than hand-built model.Route
// literals that could drift from what Discover actually produces.
func loadEnforcementShapesFixture(t *testing.T) ([]model.Route, *gin.API, map[*types.Func]gin.FuncInfo, map[string]*types.Func) {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not determine repo-relative fixture path")
	}
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")
	dir := filepath.Join(repoRoot, "testdata", "fixtures", "enforcement-shapes")

	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedImports |
			packages.NeedDeps | packages.NeedTypes | packages.NeedSyntax | packages.NeedTypesInfo,
		Dir: dir,
	}
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		t.Fatalf("packages.Load: %v", err)
	}
	if packages.PrintErrors(pkgs) > 0 {
		t.Fatal("fixture module has package errors")
	}

	imports := map[string]*types.Package{}
	funcIndex := map[*types.Func]gin.FuncInfo{}
	for _, pkg := range pkgs {
		imports[pkg.PkgPath] = pkg.Types
		for path, imp := range pkg.Imports {
			imports[path] = imp.Types
		}
		for _, file := range pkg.Syntax {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok {
					continue
				}
				obj, ok := pkg.TypesInfo.Defs[fn.Name].(*types.Func)
				if !ok {
					continue
				}
				funcIndex[obj] = gin.FuncInfo{Decl: fn, Info: pkg.TypesInfo, Fset: pkg.Fset}
			}
		}
	}
	api, ok := gin.Find(imports)
	if !ok {
		t.Fatal("gin-gonic/gin not found among loaded imports")
	}

	symbolIndex := map[string]*types.Func{}
	for fn := range funcIndex {
		if sym := gin.FuncCanonicalSymbol(fn); sym != "" {
			symbolIndex[sym] = fn
		}
	}

	var routes []model.Route
	var rootPkg *packages.Package
	for _, pkg := range pkgs {
		if hasSuffix(pkg.PkgPath, "/enforcement-shapes") {
			rootPkg = pkg
		}
	}
	if rootPkg == nil {
		t.Fatal("root package not found")
	}
	for _, file := range rootPkg.Syntax {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name.Name != "NewRouter" || fn.Body == nil {
				continue
			}
			reg := gin.Discover(rootPkg.Fset, rootPkg.TypesInfo, api, fn, funcIndex, nil)
			routes = append(routes, reg.Routes...)
		}
	}

	return routes, api, funcIndex, symbolIndex
}

func hasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}

func fixtureConfig() *config.Config {
	entry := config.AuthMiddlewareEntry{Assurance: config.AssuranceAnalyze}
	return &config.Config{
		Version: 1,
		AuthMiddleware: map[string]config.AuthMiddlewareEntry{
			"gin-recon-fixtures/enforcement-shapes/shapes.RequireAuthDirect":       entry,
			"gin-recon-fixtures/enforcement-shapes/shapes.RequireAuthOneLevel":     entry,
			"gin-recon-fixtures/enforcement-shapes/shapes.RequireAuthTwoLevel":     entry,
			"gin-recon-fixtures/enforcement-shapes/shapes.RequireAuthCrossPackage": entry,
			"gin-recon-fixtures/enforcement-shapes/shapes.RequireAuthDeferRecover": entry,
			"gin-recon-fixtures/enforcement-shapes/shapes.RequireAuthGoroutine":    entry,
			"gin-recon-fixtures/enforcement-shapes/shapes.RequireAuthAlwaysPasses": entry,
		},
	}
}

func TestClassifyAllMatchesADR0005OnRealFixture(t *testing.T) {
	routes, api, funcIndex, symbolIndex := loadEnforcementShapesFixture(t)
	in := Inputs{Config: fixtureConfig(), API: api, FuncIndex: funcIndex, SymbolIndex: symbolIndex}

	result := ClassifyAll(routes, in)

	byPath := map[string]*model.Route{}
	for i := range routes {
		byPath[routes[i].NormalizedPath] = &routes[i]
	}

	for _, tc := range []struct {
		path            string
		wantStatus      model.AuthStatus
		wantEnforcement model.EnforcementAnalysis
	}{
		{"/confirmed/direct", model.AuthProven, model.EnforcementConfirmedShape},
		{"/confirmed/delegated-one-level", model.AuthProven, model.EnforcementConfirmedShape},
		{"/unresolved/delegated-two-level", model.AuthUnknown, model.EnforcementUnresolved},
		{"/unresolved/cross-package", model.AuthUnknown, model.EnforcementUnresolved},
		{"/unresolved/defer-recover", model.AuthUnknown, model.EnforcementUnresolved},
		{"/unresolved/goroutine", model.AuthUnknown, model.EnforcementUnresolved},
		{"/contradicted/passthrough", model.AuthUnknown, model.EnforcementContradicted},
	} {
		t.Run(tc.path, func(t *testing.T) {
			route, ok := byPath[tc.path]
			if !ok {
				t.Fatalf("route %s not found", tc.path)
			}
			if route.Auth == nil {
				t.Fatal("Auth is nil")
			}
			if route.Auth.AuthStatus != tc.wantStatus {
				t.Errorf("AuthStatus = %q, want %q", route.Auth.AuthStatus, tc.wantStatus)
			}
			if route.Auth.EnforcementAnalysis == nil || *route.Auth.EnforcementAnalysis != tc.wantEnforcement {
				t.Errorf("EnforcementAnalysis = %v, want %q", route.Auth.EnforcementAnalysis, tc.wantEnforcement)
			}
		})
	}

	foundMatchedButUnenforced := false
	for _, f := range result.Findings {
		if f.RuleID == "matched-but-unenforced" {
			foundMatchedButUnenforced = true
		}
	}
	if !foundMatchedButUnenforced {
		t.Errorf("expected a matched-but-unenforced finding for the contradicted guard, got: %+v", result.Findings)
	}
}

func TestClassifyRouteAttestedPromotesUnresolvedToProven(t *testing.T) {
	routes, api, funcIndex, symbolIndex := loadEnforcementShapesFixture(t)
	cfg := fixtureConfig()
	sym := "gin-recon-fixtures/enforcement-shapes/shapes.RequireAuthTwoLevel"
	cfg.AuthMiddleware[sym] = config.AuthMiddlewareEntry{Assurance: config.AssuranceAttested}
	in := Inputs{Config: cfg, API: api, FuncIndex: funcIndex, SymbolIndex: symbolIndex}

	var route model.Route
	for _, r := range routes {
		if r.NormalizedPath == "/unresolved/delegated-two-level" {
			route = r
		}
	}
	result := ClassifyRoute(route, in)
	if result.Auth.AuthStatus != model.AuthProven {
		t.Errorf("AuthStatus = %q, want proven (attested + unresolved)", result.Auth.AuthStatus)
	}
	if result.Auth.Assurance == nil || *result.Auth.Assurance != model.AssuranceAttested {
		t.Errorf("Assurance = %v, want attested", result.Auth.Assurance)
	}
}

func TestClassifyRouteAttestedNeverPromotesContradicted(t *testing.T) {
	routes, api, funcIndex, symbolIndex := loadEnforcementShapesFixture(t)
	cfg := fixtureConfig()
	sym := "gin-recon-fixtures/enforcement-shapes/shapes.RequireAuthAlwaysPasses"
	cfg.AuthMiddleware[sym] = config.AuthMiddlewareEntry{Assurance: config.AssuranceAttested}
	in := Inputs{Config: cfg, API: api, FuncIndex: funcIndex, SymbolIndex: symbolIndex}

	var route model.Route
	for _, r := range routes {
		if r.NormalizedPath == "/contradicted/passthrough" {
			route = r
		}
	}
	result := ClassifyRoute(route, in)
	if result.Auth.AuthStatus != model.AuthUnknown {
		t.Errorf("AuthStatus = %q, want unknown — attested must never promote a contradicted guard", result.Auth.AuthStatus)
	}
}

func TestStaleAuthConfigFindingFiresForUnmatchedSymbol(t *testing.T) {
	routes, api, funcIndex, symbolIndex := loadEnforcementShapesFixture(t)
	cfg := fixtureConfig()
	cfg.AuthMiddleware["gin-recon-fixtures/enforcement-shapes/shapes.DoesNotExist"] = config.AuthMiddlewareEntry{Assurance: config.AssuranceAnalyze}
	in := Inputs{Config: cfg, API: api, FuncIndex: funcIndex, SymbolIndex: symbolIndex}

	result := ClassifyAll(routes, in)
	found := false
	for _, f := range result.Findings {
		if f.RuleID == "stale-auth-config" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a stale-auth-config finding, got: %+v", result.Findings)
	}
}

// TestStaleAuthConfigFindingSuppressedForSyntaxOnly is the regression for a
// real bug found while validating a live syntax-only report against
// schema/report-1.0.json: every syntax-only route has a nil CanonicalSymbol
// on every middleware entry by construction, so without this suppression
// every configured authMiddleware entry would spuriously report
// stale-auth-config on every syntax-only audit, even for a symbol genuinely
// present and used in the scanned code — "never matched" and "matched but
// unresolvable" are indistinguishable without canonical identity.
func TestStaleAuthConfigFindingSuppressedForSyntaxOnly(t *testing.T) {
	cfg := &config.Config{
		Version: 1,
		AuthMiddleware: map[string]config.AuthMiddlewareEntry{
			"example.com/app.RequireAuth": {Assurance: config.AssuranceAnalyze},
		},
	}
	routes := []model.Route{{Method: "GET", NormalizedPath: "/x"}} // no middleware at all, unresolved either way
	result := ClassifyAll(routes, Inputs{Config: cfg, Profile: model.ProfileSyntaxOnly})
	for _, f := range result.Findings {
		if f.RuleID == "stale-auth-config" {
			t.Errorf("expected no stale-auth-config finding under syntax-only, got: %+v", result.Findings)
		}
	}
}

func TestPublicRouteFindingSuppressedByAcceptedPublic(t *testing.T) {
	routes, api, funcIndex, symbolIndex := loadEnforcementShapesFixture(t)
	cfg := &config.Config{Version: 1, AcceptedPublic: []string{"GET /confirmed/direct"}}
	// Strip the config so /confirmed/direct has no matched guard at all,
	// making it genuinely public (its middleware, RequireAuthDirect, is
	// still named/resolved, so it is public, not unknown-via-opacity).
	in := Inputs{Config: cfg, API: api, FuncIndex: funcIndex, SymbolIndex: symbolIndex}

	var route model.Route
	for _, r := range routes {
		if r.NormalizedPath == "/confirmed/direct" {
			route = r
		}
	}
	result := ClassifyRoute(route, in)
	if result.Auth.AuthStatus != model.AuthPublic {
		t.Fatalf("AuthStatus = %q, want public", result.Auth.AuthStatus)
	}
	if !result.Auth.Accepted {
		t.Error("Accepted = false, want true")
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected no findings (accepted-public suppresses public-route), got: %+v", result.Findings)
	}
}

func routeWithAuth(method, path string, status model.AuthStatus, accepted bool) model.Route {
	return model.Route{
		Method:         method,
		NormalizedPath: path,
		Auth:           &model.AuthClassification{AuthStatus: status, Accepted: accepted, Confidence: model.ConfidenceHigh},
	}
}

// TestPerVerbGapFindingFiresForInconsistentAuthAcrossMethods is the
// regression for a real gap: docs/report-contract.md documents per-verb-gap
// as a built-in finding, and it even has SARIF rule metadata, but nothing
// ever produced it — mirroring express-recon's own inconsistentPaths check,
// which does fire in the reference implementation. A classic write-path
// bypass (GET proven, DELETE public on the same resource) must be caught.
func TestPerVerbGapFindingFiresForInconsistentAuthAcrossMethods(t *testing.T) {
	routes := []model.Route{
		routeWithAuth("GET", "/widgets/:id", model.AuthProven, false),
		routeWithAuth("DELETE", "/widgets/:id", model.AuthPublic, false),
	}
	findings := perVerbGapFindings(routes)
	if len(findings) != 1 {
		t.Fatalf("expected 1 per-verb-gap finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.RuleID != report.RulePerVerbGap {
		t.Errorf("RuleID = %q, want per-verb-gap", f.RuleID)
	}
	if f.Severity != report.SeverityHigh {
		t.Errorf("Severity = %q, want high", f.Severity)
	}
	if f.Evidence["normalizedPath"] != "/widgets/:id" {
		t.Errorf("Evidence[normalizedPath] = %v, want /widgets/:id", f.Evidence["normalizedPath"])
	}
}

func TestPerVerbGapFindingDoesNotFireForConsistentAuth(t *testing.T) {
	routes := []model.Route{
		routeWithAuth("GET", "/widgets", model.AuthPublic, false),
		routeWithAuth("POST", "/widgets", model.AuthPublic, false),
	}
	if findings := perVerbGapFindings(routes); len(findings) != 0 {
		t.Errorf("expected no findings for consistent auth across methods, got: %+v", findings)
	}
}

// TestPerVerbGapFindingSuppressedByAcceptedPublic documents the deliberate
// improvement over express-recon's equivalent check: an accepted-public
// route (already reviewed and intentionally open) does not itself count
// toward a gap, the same suppression already applied to public-route
// findings elsewhere in this package.
func TestPerVerbGapFindingSuppressedByAcceptedPublic(t *testing.T) {
	routes := []model.Route{
		routeWithAuth("GET", "/health", model.AuthProven, false),
		routeWithAuth("HEAD", "/health", model.AuthPublic, true), // accepted-public
	}
	if findings := perVerbGapFindings(routes); len(findings) != 0 {
		t.Errorf("expected no findings — the public sibling is accepted-public, not a gap; got: %+v", findings)
	}
}

func TestPerVerbGapFindingIgnoresRoutesWithNoAuthClassification(t *testing.T) {
	// Inventory-shaped routes (Auth == nil) must never panic or be treated
	// as a gap — per-verb-gap is audit-only.
	routes := []model.Route{
		{Method: "GET", NormalizedPath: "/x"},
		{Method: "POST", NormalizedPath: "/x"},
	}
	if findings := perVerbGapFindings(routes); len(findings) != 0 {
		t.Errorf("expected no findings for unclassified routes, got: %+v", findings)
	}
}
