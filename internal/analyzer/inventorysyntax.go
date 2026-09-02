package analyzer

import (
	"github.com/sagnikhaldar/gin-recon/internal/analyzer/gin"
	"github.com/sagnikhaldar/gin-recon/internal/model"
)

// syntaxCoverageAffectingCodes mirrors coverageAffectingCodes for the
// syntax-only profile: the shared "route not inventoried" codes typed mode
// also produces, plus the syntax-only-specific gaps this profile's narrower
// discovery boundary introduces (see discover_syntax.go's package doc
// comment) — an unfollowed possible-registrar call, an untraceable router
// value, a file that failed to parse, a rejected symlink, or a walk error.
var syntaxCoverageAffectingCodes = map[string]bool{
	"gin-unresolved-path":             true,
	"gin-unresolved-method":           true,
	"gin-unresolved-methods":          true,
	"gin-unresolved-handlers":         true,
	"gin-no-handlers":                 true,
	"gin-syntax-untracked-value":      true,
	"gin-syntax-unresolved-registrar": true,
	"gin-syntax-parse-error":          true,
	"gin-syntax-walk-error":           true,
	"gin-syntax-symlink-escape":       true,
}

// InventorySyntax is Inventory's syntax-only equivalent: it runs
// gin.DiscoverFileSyntax across every parsed file and merges the results,
// using exactly the same normalization/ordering/source-relativization rules
// as the typed path so a report from either profile has the same
// deterministic shape.
func InventorySyntax(loaded *LoadedSyntax) *InventoryResult {
	result := &InventoryResult{
		Module:           loaded.Module,
		Routes:           []model.Route{},
		GlobalMiddleware: []model.Middleware{},
		FallbackSurfaces: []model.FallbackSurface{},
		Diagnostics:      append([]model.Diagnostic{}, loaded.Diagnostics...),
	}

	for _, sf := range loaded.Files {
		reg := gin.DiscoverFileSyntax(loaded.Fset, sf.File)
		for i := range reg.Routes {
			reg.Routes[i].BuildContext = loaded.BuildContext
		}
		result.Routes = append(result.Routes, reg.Routes...)
		result.GlobalMiddleware = append(result.GlobalMiddleware, reg.GlobalMiddleware...)
		result.FallbackSurfaces = append(result.FallbackSurfaces, reg.FallbackSurfaces...)
		result.Diagnostics = append(result.Diagnostics, reg.Diagnostics...)
	}

	relativizeSources(result, loaded.Root, nil)
	normalize(result)
	result.ScanCoverage = buildSyntaxScanCoverage(loaded, result.Diagnostics)
	return result
}

func buildSyntaxScanCoverage(loaded *LoadedSyntax, diagnostics []model.Diagnostic) model.ScanCoverage {
	unresolved := 0
	for _, d := range diagnostics {
		if syntaxCoverageAffectingCodes[d.Code] {
			unresolved++
		}
	}
	return model.ScanCoverage{
		DiscoveredPackages:      1,
		AnalyzedPackages:        1,
		FailedPackages:          0,
		DiscoveredFiles:         loaded.DiscoveredFiles,
		AnalyzedFiles:           loaded.AnalyzedFiles,
		FailedFiles:             loaded.FailedFiles,
		UnresolvedRegistrations: unresolved,
		BuildContext:            loaded.BuildContext,
		Profile:                 model.ProfileSyntaxOnly,
		Complete:                loaded.FailedFiles == 0 && unresolved == 0,
	}
}
