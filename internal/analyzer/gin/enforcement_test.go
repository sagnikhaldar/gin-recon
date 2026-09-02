package gin

import (
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

func TestAnalyzeEnforcementUnresolvedWithoutFuncIndexEntry(t *testing.T) {
	pkgs, api := loadFixture(t, "enforcement-shapes")
	fn := funcObjInPackage(t, pkgs, "/shapes", "RequireAuthDirect")

	got := AnalyzeEnforcement(map[*types.Func]FuncInfo{}, api, fn)
	if got != model.EnforcementUnresolved {
		t.Errorf("AnalyzeEnforcement with empty index = %q, want unresolved", got)
	}
}
