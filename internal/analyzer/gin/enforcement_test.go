package gin

import (
	"go/ast"
	"go/types"
	"testing"

	"github.com/sagnikhaldar/gin-recon/internal/model"
	"golang.org/x/tools/go/packages"
)

// funcObjInPackage finds a *types.Func by name in the loaded package whose
// PkgPath has the given suffix — mirroring findFunc but returning the
// *types.Func (what AnalyzeEnforcement takes) rather than the *ast.FuncDecl.
func funcObjInPackage(t *testing.T, pkgs []*packages.Package, pkgPathSuffix, name string) *types.Func {
	t.Helper()
	for _, pkg := range pkgs {
		if !hasSuffix(pkg.PkgPath, pkgPathSuffix) {
			continue
		}
		obj := pkg.Types.Scope().Lookup(name)
		if obj == nil {
			continue
		}
		if fn, ok := obj.(*types.Func); ok {
			return fn
		}
	}
	t.Fatalf("function %s not found in any package matching %q", name, pkgPathSuffix)
	return nil
}

func TestAnalyzeEnforcementMatchesADR0008BoundaryOnRealFixture(t *testing.T) {
	pkgs, api := loadFixture(t, "enforcement-shapes")
	index := buildFuncIndex(pkgs)

	for _, tc := range []struct {
		name string
		want model.EnforcementAnalysis
	}{
		{"RequireAuthDirect", model.EnforcementConfirmedShape},
		{"RequireAuthOneLevel", model.EnforcementConfirmedShape},
		{"RequireAuthTwoLevel", model.EnforcementUnresolved},
		{"RequireAuthCrossPackage", model.EnforcementUnresolved},
		{"RequireAuthDeferRecover", model.EnforcementUnresolved},
		{"RequireAuthGoroutine", model.EnforcementUnresolved},
		{"RequireAuthAlwaysPasses", model.EnforcementContradicted},
		{"RequireRoleFactory", model.EnforcementConfirmedShape},
		{"RequireAuthFactory", model.EnforcementConfirmedShape},
		{"RequireAuthFactoryTooDeep", model.EnforcementUnresolved},
		{"RequireAuthFactoryCrossPackage", model.EnforcementUnresolved},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fn := funcObjInPackage(t, pkgs, "/shapes", tc.name)
			got := AnalyzeEnforcement(index, api, fn)
			if got != tc.want {
				t.Errorf("AnalyzeEnforcement(%s) = %q, want %q", tc.name, got, tc.want)
			}
		})
	}
}

// declNames extracts each *ast.FuncDecl's own identifier, in order, for
// readable assertions below.
func declNames(decls []*ast.FuncDecl) []string {
	names := make([]string, len(decls))
	for i, d := range decls {
		names[i] = d.Name.Name
	}
	return names
}

// TestEnforcementExcerptIncludesFactoryDelegate guards a real evidence gap:
// RequireAuthFactory (this fixture's own doc comment: "mirrors the
// real-world JWTMiddleware/jwtMiddleware pattern exactly") delegates via a
// same-package factory-return call to requireAuthImpl, the function whose
// body actually contains the abort AnalyzeEnforcement's confirmed-shape
// verdict is based on. A reviewer given only RequireAuthFactory's own
// declaration would see the delegating call, never the abort itself.
func TestEnforcementExcerptIncludesFactoryDelegate(t *testing.T) {
	pkgs, api := loadFixture(t, "enforcement-shapes")
	index := buildFuncIndex(pkgs)
	fn := funcObjInPackage(t, pkgs, "/shapes", "RequireAuthFactory")

	decls, ok := EnforcementExcerpt(index, api, fn)
	if !ok {
		t.Fatal("EnforcementExcerpt: ok = false, want true")
	}
	want := []string{"RequireAuthFactory", "requireAuthImpl"}
	got := declNames(decls)
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("EnforcementExcerpt decl names = %v, want %v", got, want)
	}
}

// TestEnforcementExcerptIncludesMidBodyDelegate guards the second,
// independent delegation mechanism: RequireAuthOneLevel itself takes
// *gin.Context directly (no factory-return resolution needed), but its own
// body delegates the deny decision to denyUnlessAuthorized — the function
// whose body actually contains the abort. A reviewer given only
// RequireAuthOneLevel's own declaration would see the helper call, never
// the helper's own abort.
func TestEnforcementExcerptIncludesMidBodyDelegate(t *testing.T) {
	pkgs, api := loadFixture(t, "enforcement-shapes")
	index := buildFuncIndex(pkgs)
	fn := funcObjInPackage(t, pkgs, "/shapes", "RequireAuthOneLevel")

	decls, ok := EnforcementExcerpt(index, api, fn)
	if !ok {
		t.Fatal("EnforcementExcerpt: ok = false, want true")
	}
	want := []string{"RequireAuthOneLevel", "denyUnlessAuthorized"}
	got := declNames(decls)
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("EnforcementExcerpt decl names = %v, want %v", got, want)
	}
}

// TestEnforcementExcerptDirectShapeIsJustItself confirms the common case —
// a direct-abort shape with no delegation at all — carries only its own
// declaration, no unrelated extras.
func TestEnforcementExcerptDirectShapeIsJustItself(t *testing.T) {
	pkgs, api := loadFixture(t, "enforcement-shapes")
	index := buildFuncIndex(pkgs)
	fn := funcObjInPackage(t, pkgs, "/shapes", "RequireAuthDirect")

	decls, ok := EnforcementExcerpt(index, api, fn)
	if !ok {
		t.Fatal("EnforcementExcerpt: ok = false, want true")
	}
	if len(decls) != 1 || decls[0].Name.Name != "RequireAuthDirect" {
		t.Fatalf("EnforcementExcerpt decl names = %v, want [RequireAuthDirect]", declNames(decls))
	}
}

func TestAnalyzeEnforcementUnresolvedWithoutFuncIndexEntry(t *testing.T) {
	pkgs, api := loadFixture(t, "enforcement-shapes")
	fn := funcObjInPackage(t, pkgs, "/shapes", "RequireAuthDirect")

	got := AnalyzeEnforcement(map[*types.Func]FuncInfo{}, api, fn)
	if got != model.EnforcementUnresolved {
		t.Errorf("AnalyzeEnforcement with empty index = %q, want unresolved", got)
	}
}
