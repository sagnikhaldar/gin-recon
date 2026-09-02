package gin

import (
	"go/ast"
	"go/types"
	"path/filepath"
	"runtime"
	"testing"

	"golang.org/x/tools/go/packages"
)

// loadFixture type-checks a real fixture Go module (under
// testdata/fixtures/<name> relative to the repo root) using the actual
// compiled gin-gonic/gin package, and returns its loaded packages plus the
// resolved gin.API. Using a real fixture module here — rather than
// hand-built go/types objects — means these tests exercise the exact same
// type information the real analyzer will see when it eventually runs
// through golang.org/x/tools/go/packages, not an approximation of it.
func loadFixture(t *testing.T, name string) ([]*packages.Package, *API) {
	t.Helper()

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not determine repo-relative fixture path")
	}
	// this file is internal/analyzer/gin/loadfixture_test.go; the repo root
	// is three directories up.
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..", "..")
	dir := filepath.Join(repoRoot, "testdata", "fixtures", name)

	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedImports |
			packages.NeedDeps | packages.NeedTypes | packages.NeedSyntax |
			packages.NeedTypesInfo,
		Dir:   dir,
		Tests: false,
	}
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		t.Fatalf("packages.Load(%s): %v", dir, err)
	}
	if packages.PrintErrors(pkgs) > 0 {
		t.Fatalf("fixture module %s has package errors", name)
	}

	imports := map[string]*types.Package{}
	for _, p := range pkgs {
		imports[p.PkgPath] = p.Types
		for path, imp := range p.Imports {
			imports[path] = imp.Types
		}
	}
	api, ok := Find(imports)
	if !ok {
		t.Fatalf("fixture module %s: gin-gonic/gin not found among loaded imports", name)
	}
	return pkgs, api
}

// buildFuncIndex constructs the same whole-module function index a real
// orchestration layer would build: every top-level function and method
// declaration across every loaded package, keyed by its *types.Func. This is
// what makes registrar-following testable without the orchestration layer
// existing yet.
func buildFuncIndex(pkgs []*packages.Package) map[*types.Func]FuncInfo {
	index := map[*types.Func]FuncInfo{}
	for _, pkg := range pkgs {
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
				index[obj] = FuncInfo{Decl: fn, Info: pkg.TypesInfo, Fset: pkg.Fset}
			}
		}
	}
	return index
}
