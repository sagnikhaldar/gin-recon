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
	"golang.org/x/tools/go/packages"
)

// loadAuthWrappersFixture mirrors loadEnforcementShapesFixture exactly,
// pointed at the auth-wrappers fixture — see testdata/fixtures/auth-wrappers's
// manifest.json for the full positive/negative/opaque/nested/factory/
// contradicted-wrapper matrix this backs.
func loadAuthWrappersFixture(t *testing.T) ([]model.Route, *gin.API, map[*types.Func]gin.FuncInfo, map[string]*types.Func) {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not determine repo-relative fixture path")
	}
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")
	dir := filepath.Join(repoRoot, "testdata", "fixtures", "auth-wrappers")

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
		if hasSuffix(pkg.PkgPath, "/auth-wrappers") {
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

func authWrappersConfig() *config.Config {
	analyze := config.AuthMiddlewareEntry{Assurance: config.AssuranceAnalyze}
	return &config.Config{
		Version: 1,
		AuthMiddleware: map[string]config.AuthMiddlewareEntry{
			"gin-recon-fixtures/auth-wrappers.RequireAuth":             analyze,
			"gin-recon-fixtures/auth-wrappers.RequireAuthContradicted": analyze,
			"gin-recon-fixtures/auth-wrappers.RequireRoleFactory":      analyze,
		},
		AuthWrappers: []string{"gin-recon-fixtures/auth-wrappers.LoggedAuth"},
	}
}

func routeByPath(t *testing.T, routes []model.Route, path string) model.Route {
	t.Helper()
	for _, r := range routes {
		if r.NormalizedPath == path {
			return r
		}
	}
	t.Fatalf("fixture route %s not found", path)
	return model.Route{}
}

func classifyFixtureRoute(t *testing.T, path string) Result {
	t.Helper()
	routes, api, funcIndex, symbolIndex := loadAuthWrappersFixture(t)
	route := routeByPath(t, routes, path)
	return ClassifyRoute(route, Inputs{
		Config:      authWrappersConfig(),
		API:         api,
		FuncIndex:   funcIndex,
		SymbolIndex: symbolIndex,
	})
}

func TestAuthWrappersPositiveExposesWrappedGuard(t *testing.T) {
	result := classifyFixtureRoute(t, "/wrapped/positive")
	if result.Auth.AuthStatus != model.AuthProven {
		t.Fatalf("AuthStatus = %q, want proven", result.Auth.AuthStatus)
	}
	if result.Auth.EnforcementAnalysis == nil || *result.Auth.EnforcementAnalysis != model.EnforcementConfirmedShape {
		t.Errorf("EnforcementAnalysis = %v, want confirmed-shape", result.Auth.EnforcementAnalysis)
	}
	if result.Auth.MatchedEvidence == nil || *result.Auth.MatchedEvidence != "gin-recon-fixtures/auth-wrappers.RequireAuth" {
		t.Errorf("MatchedEvidence = %v, want RequireAuth (the wrapped symbol, not the wrapper)", result.Auth.MatchedEvidence)
	}
}

func TestAuthWrappersNegativeWrappedNonGuardStaysPublic(t *testing.T) {
	result := classifyFixtureRoute(t, "/wrapped/negative")
	if result.Auth.AuthStatus != model.AuthPublic {
		t.Fatalf("AuthStatus = %q, want public (Handler is not a configured guard)", result.Auth.AuthStatus)
	}
}

// TestAuthWrappersOpaqueUnconfiguredWrapperNeverExposesInnerGuard is the
// core safety property: ConditionalWrapper is NOT in authWrappers, so
// RequireAuth inside it must never become evidence, no matter how
// guard-like the wrapped call is.
func TestAuthWrappersOpaqueUnconfiguredWrapperNeverExposesInnerGuard(t *testing.T) {
	result := classifyFixtureRoute(t, "/wrapped/opaque")
	if result.Auth.AuthStatus != model.AuthPublic {
		t.Fatalf("AuthStatus = %q, want public — an unconfigured wrapper must never expose its argument as evidence", result.Auth.AuthStatus)
	}
}

func TestAuthWrappersNestedTwoHopChainResolves(t *testing.T) {
	result := classifyFixtureRoute(t, "/wrapped/nested")
	if result.Auth.AuthStatus != model.AuthProven {
		t.Fatalf("AuthStatus = %q, want proven (LoggedAuth(LoggedAuth(RequireAuth)))", result.Auth.AuthStatus)
	}
	if result.Auth.MatchedEvidence == nil || *result.Auth.MatchedEvidence != "gin-recon-fixtures/auth-wrappers.RequireAuth" {
		t.Errorf("MatchedEvidence = %v, want RequireAuth resolved through two wrapper hops", result.Auth.MatchedEvidence)
	}
}

func TestAuthWrappersFactoryComposesWithWrapping(t *testing.T) {
	result := classifyFixtureRoute(t, "/wrapped/factory")
	if result.Auth.AuthStatus != model.AuthProven {
		t.Fatalf("AuthStatus = %q, want proven (LoggedAuth wraps RequireRoleFactory(\"admin\"))", result.Auth.AuthStatus)
	}
	if result.Auth.MatchedEvidence == nil || *result.Auth.MatchedEvidence != "gin-recon-fixtures/auth-wrappers.RequireRoleFactory" {
		t.Errorf("MatchedEvidence = %v, want RequireRoleFactory (the factory's own symbol, not \"admin\")", result.Auth.MatchedEvidence)
	}
}

// TestAuthWrappersContradictedNeverBecomesProven is the security invariant
// this whole feature must never weaken: wrapping a guard whose own control
// flow is provably a no-op must still classify unknown with
// matched-but-unenforced, regardless of the wrapper.
func TestAuthWrappersContradictedNeverBecomesProven(t *testing.T) {
	result := classifyFixtureRoute(t, "/wrapped/contradicted")
	if result.Auth.AuthStatus != model.AuthUnknown {
		t.Fatalf("AuthStatus = %q, want unknown — a contradicted guard must never become proven, wrapped or not", result.Auth.AuthStatus)
	}
	if result.Auth.EnforcementAnalysis == nil || *result.Auth.EnforcementAnalysis != model.EnforcementContradicted {
		t.Errorf("EnforcementAnalysis = %v, want contradicted", result.Auth.EnforcementAnalysis)
	}
	found := false
	for _, f := range result.Findings {
		if f.RuleID == "matched-but-unenforced" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a matched-but-unenforced finding, got: %+v", result.Findings)
	}
}

// TestAuthWrappersContradictedNeverBecomesProvenEvenAttested proves the
// security invariant holds regardless of assurance mode — attested only
// relaxes "unresolved", never "contradicted".
func TestAuthWrappersContradictedNeverBecomesProvenEvenAttested(t *testing.T) {
	routes, api, funcIndex, symbolIndex := loadAuthWrappersFixture(t)
	route := routeByPath(t, routes, "/wrapped/contradicted")
	cfg := authWrappersConfig()
	cfg.AuthMiddleware["gin-recon-fixtures/auth-wrappers.RequireAuthContradicted"] = config.AuthMiddlewareEntry{Assurance: config.AssuranceAttested}

	result := ClassifyRoute(route, Inputs{Config: cfg, API: api, FuncIndex: funcIndex, SymbolIndex: symbolIndex})
	if result.Auth.AuthStatus != model.AuthUnknown {
		t.Fatalf("AuthStatus = %q, want unknown even under attested assurance", result.Auth.AuthStatus)
	}
}
