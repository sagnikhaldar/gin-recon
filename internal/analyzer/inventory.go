package analyzer

import (
	"go/ast"
	"go/types"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sagnikhaldar/gin-recon/internal/analyzer/gin"
	"github.com/sagnikhaldar/gin-recon/internal/model"
	"golang.org/x/tools/go/packages"
)

// coverageAffectingCodes are diagnostic codes that represent a registration
// this analyzer could not resolve — as opposed to a purely informational
// note — and therefore both count toward ScanCoverage.UnresolvedRegistrations
// and make ScanCoverage.Complete false. Keeping this as an explicit allowlist
// (rather than "any diagnostic") means a future informational-only
// diagnostic code does not silently start marking otherwise-complete scans
// incomplete.
var coverageAffectingCodes = map[string]bool{
	"gin-unresolved-path":          true,
	"gin-unresolved-method":        true,
	"gin-unresolved-methods":       true,
	"gin-unresolved-handlers":      true,
	"gin-no-handlers":              true,
	"gin-unresolved-registrar":     true,
	"gin-registrar-depth-exceeded": true,
	"gin-recursive-registrar":      true,
	"gin-untracked-router-value":   true,
	"gin-library-entry-point":      true,
}

// InventoryResult is the merged, deterministically ordered discovery output
// for a whole loaded module — the normalized form report.NewInventoryReport
// consumes.
type InventoryResult struct {
	Module           string
	Routes           []model.Route
	GlobalMiddleware []model.Middleware
	FallbackSurfaces []model.FallbackSurface
	Diagnostics      []model.Diagnostic
	ScanCoverage     model.ScanCoverage
}

// Inventory runs Gin discovery across every function in every loaded
// package and merges the results. A target that does not import Gin at all
// is a valid, empty result, not an error — most Go modules gin-recon might
// be pointed at will not use Gin, and that is not itself a finding.
func Inventory(loaded *Loaded) *InventoryResult {
	result, _, _ := discover(loaded)
	return result
}

// discover is Inventory's implementation, additionally returning the
// resolved Gin API and whole-module function index — both of which Audit
// also needs for classification, and which are expensive enough (a full
// package walk) that Audit should not have to recompute them by calling
// Inventory and then separately redoing this work itself.
func discover(loaded *Loaded) (*InventoryResult, *gin.API, map[*types.Func]gin.FuncInfo) {
	modulePath := modulePathOf(loaded.Packages)
	result := &InventoryResult{
		Module:           modulePath,
		Routes:           []model.Route{},
		GlobalMiddleware: []model.Middleware{},
		FallbackSurfaces: []model.FallbackSurface{},
		Diagnostics:      []model.Diagnostic{},
	}

	imports := mergedImports(loaded.Packages)
	api, ok := gin.Find(imports)
	if !ok {
		result.ScanCoverage = buildScanCoverage(loaded, nil)
		return result, nil, nil
	}

	index := buildFuncIndex(loaded.Packages)
	calledFuncs := buildCalledFuncsIndex(loaded.Packages)
	pseudoConsts := buildPseudoConstIndex(loaded.Packages)
	externalFiles := map[string]*packages.Module{}
	buildCrossModuleFuncIndex(loaded.Packages, loaded.FollowModules, index, externalFiles)

	for _, pkg := range loaded.Packages {
		for _, file := range pkg.Syntax {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				// Only a function that constructs an engine itself is a
				// legitimate top-level entry — see HasEngineConstruction's
				// doc comment for why running Discover standalone on a pure
				// registrar function (reachable only via registrar-following
				// from a real entry) produces spurious
				// gin-untracked-router-value diagnostics for routes it
				// registers perfectly correctly once reached the right way.
				if !gin.HasEngineConstruction(pkg.TypesInfo, fn) {
					// A function that never constructs its own engine but
					// registers routes on a router-typed parameter, and is
					// never called anywhere else in this module either
					// (buildCalledFuncsIndex), has no possible entry point
					// this analyzer could ever reach — not via this loop,
					// and not via tryFollowRegistrarCall from some other
					// function's walk, since nothing calls it at all. That
					// is a real, distinct visibility gap from an untracked
					// value inside an otherwise-reachable entry point, so it
					// gets its own diagnostic rather than silence. A
					// function that IS called from elsewhere is deliberately
					// skipped here even if that call site couldn't resolve
					// it (already covered by gin-unresolved-registrar/
					// gin-untracked-router-value at the call site itself —
					// this check exists only for the "nobody calls this at
					// all" case those cannot reach).
					if fnObj, ok := pkg.TypesInfo.Defs[fn.Name].(*types.Func); ok && !calledFuncs[fnObj] {
						if d := gin.DetectLibraryEntryPoint(pkg.Fset, pkg.TypesInfo, api, fn); d != nil {
							result.Diagnostics = append(result.Diagnostics, *d)
						}
					}
					continue
				}
				reg := gin.Discover(pkg.Fset, pkg.TypesInfo, api, fn, index, pseudoConsts)
				// gin.Discover has no notion of the analyzer's build
				// context (GOOS/GOARCH/tags/etc.) — that is exclusively
				// this orchestration layer's concern, so it is backfilled
				// here rather than threaded down into the walker.
				for i := range reg.Routes {
					reg.Routes[i].BuildContext = loaded.BuildContext
				}
				result.Routes = append(result.Routes, reg.Routes...)
				result.GlobalMiddleware = append(result.GlobalMiddleware, reg.GlobalMiddleware...)
				result.FallbackSurfaces = append(result.FallbackSurfaces, reg.FallbackSurfaces...)
				result.Diagnostics = append(result.Diagnostics, reg.Diagnostics...)
			}
		}
	}

	applySwagAnnotations(result, index)
	relativizeSources(result, loaded.Root, externalFiles)
	normalize(result)
	result.ScanCoverage = buildScanCoverage(loaded, result.Diagnostics)
	return result, api, index
}

// applySwagAnnotations enriches every route whose final handler resolved to
// a canonical symbol with that handler's own swaggo/swag doc-comment
// evidence, per docs/adr/0012-swag-annotation-evidence.md. This runs here,
// in the orchestration layer, rather than inside gin.Discover itself,
// because only this layer has funcIndex — the whole-module symbol-to-decl
// index gin.Discover's own registrar-following already relies on
// (buildFuncIndex's doc comment) — needed to go from a resolved
// CanonicalSymbol back to the *ast.FuncDecl whose Doc comment might carry
// swag directives. A route whose handler never resolved to a canonical
// symbol (anonymous, unresolved, or a symbol outside this module's own
// funcIndex) is left completely unchanged — this is purely additive
// evidence, never a source of new coverage gaps.
func applySwagAnnotations(result *InventoryResult, funcIndex map[*types.Func]gin.FuncInfo) {
	symbolIndex := BuildSymbolIndex(funcIndex)
	for i := range result.Routes {
		route := &result.Routes[i]
		if route.FinalHandler.CanonicalSymbol == nil {
			continue
		}
		fn, ok := symbolIndex[*route.FinalHandler.CanonicalSymbol]
		if !ok {
			continue
		}
		fi, ok := funcIndex[fn]
		if !ok || fi.Decl == nil || fi.Decl.Doc == nil {
			continue
		}
		if diag := gin.ApplySwagFromDoc(route, fi.Decl.Doc); diag != nil {
			result.Diagnostics = append(result.Diagnostics, *diag)
		}
	}
}

// relativizeSource rewrites a single model.Source.File from the absolute
// path go/packages naturally produces into a root-relative, slash-separated
// path, per docs/cli-contract.md: "Reports store root-relative
// slash-separated paths, never absolute checkout paths." internal/analyzer/gin's
// Discover and AnalyzeEngineSecurity have no concept of "the scan root" (they
// only ever see a *token.FileSet), so this conversion can only happen in
// internal/analyzer. Audit (audit.go, same package) calls this directly for
// its engine-security findings/diagnostics, which are computed after
// discover has already relativized everything discover itself produced and
// so need the same conversion applied to their own Source fields before they
// reach a report.
//
// externalFiles maps an absolute file path to the *packages.Module it
// belongs to, for a source that resolveEngineFactoryCall/
// tryFollowRegistrarCall (via analysis.followModules) reached outside root
// — see docs/adr/0010-opt-in-cross-module-registrar-following.md. Every
// call site that can never produce such a source (audit's own
// engine-security findings, and the entire syntax-only path, neither of
// which ever crosses a module boundary) passes nil, which behaves exactly
// as before this parameter existed: a nil map lookup is always "not found,"
// so those call sites are unaffected. A path that does escape root without
// a match in externalFiles is a should-never-happen case handled
// defensively (never left as, or overwritten with, an absolute path).
func relativizeSource(root string, externalFiles map[string]*packages.Module, s *model.Source) {
	if s == nil {
		return
	}
	rel, err := filepath.Rel(root, s.File)
	if err == nil && !relEscapesRoot(rel) {
		s.File = filepath.ToSlash(rel)
		return
	}
	if len(externalFiles) == 0 {
		return // no cross-module resolution configured; leave as-is, matching pre-existing behavior for this rare/unexpected case
	}
	relativizeCrossModuleSource(externalFiles, s)
}

// relEscapesRoot reports whether rel (the result of filepath.Rel(root, ...))
// climbs above root rather than staying beneath it.
func relEscapesRoot(rel string) bool {
	return rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// relativizeSources rewrites every model.Source.File in an InventoryResult
// from the absolute path go/packages naturally produces into a
// root-relative, slash-separated path — see relativizeSource.
func relativizeSources(result *InventoryResult, root string, externalFiles map[string]*packages.Module) {
	rel := func(s *model.Source) { relativizeSource(root, externalFiles, s) }
	relMiddleware := func(list []model.Middleware) {
		for i := range list {
			rel(list[i].Source)
		}
	}
	for i := range result.Routes {
		r := &result.Routes[i]
		rel(r.Source)
		relMiddleware(r.Middleware)
		rel(r.FinalHandler.Source)
	}
	relMiddleware(result.GlobalMiddleware)
	for i := range result.FallbackSurfaces {
		fb := &result.FallbackSurfaces[i]
		rel(fb.Source)
		relMiddleware(fb.Middleware)
		rel(fb.FinalHandler.Source)
	}
	for i := range result.Diagnostics {
		rel(result.Diagnostics[i].Source)
	}
}

// mergedImports flattens every loaded package's own type-checked package
// plus everything it imports into one lookup table keyed by import path, so
// gin.Find can locate gin-gonic/gin regardless of which package in the
// target module actually imports it directly.
func mergedImports(pkgs []*packages.Package) map[string]*types.Package {
	imports := map[string]*types.Package{}
	packages.Visit(pkgs, nil, func(pkg *packages.Package) {
		if pkg.Types != nil {
			imports[pkg.PkgPath] = pkg.Types
		}
	})
	return imports
}

// buildFuncIndex indexes every function and method declaration across every
// loaded package by its *types.Func, giving gin.Discover whole-module
// visibility for registrar-function following (internal/analyzer/gin's
// Discover cannot build this itself — only the orchestration layer loads
// more than one function's package at a time).
//
// This deliberately iterates pkgs directly — the packages.Load(cfg, "./...")
// result, which already includes every package in the target module — and
// not packages.Visit's transitive dependency walk. Registrar-following and
// enforcement-shape resolution are both semantically bounded to the
// target's own source (crossing into a third-party dependency's internals
// to "follow a registrar" or "resolve an abort path" makes no sense the way
// crossing into another of the target's own packages does); the earlier
// version used packages.Visit and was measured pulling in tens of thousands
// of unrelated stdlib/dependency functions on a real codebase — wasted work
// with no effect on results, since none of those functions could ever be
// reached by either resolution path anyway.
func buildFuncIndex(pkgs []*packages.Package) map[*types.Func]gin.FuncInfo {
	index := map[*types.Func]gin.FuncInfo{}
	for _, pkg := range pkgs {
		if pkg.TypesInfo == nil {
			continue
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
				index[obj] = gin.FuncInfo{Decl: fn, Info: pkg.TypesInfo, Fset: pkg.Fset}
			}
		}
	}
	return index
}

// buildCalledFuncsIndex records every *types.Func that is the resolved
// callee of at least one call expression anywhere in the loaded module —
// used solely by DetectLibraryEntryPoint's "is this function reachable from
// anywhere in this scanned module at all" check. A function absent from
// this set is never called by any visible code in the module, which is
// exactly the condition under which its own route registrations on a
// router-typed parameter are genuinely unresolvable rather than merely
// unresolved at one particular call site (the latter is already covered by
// gin-unresolved-registrar/gin-untracked-router-value at that call site).
func buildCalledFuncsIndex(pkgs []*packages.Package) map[*types.Func]bool {
	called := map[*types.Func]bool{}
	for _, pkg := range pkgs {
		if pkg.TypesInfo == nil {
			continue
		}
		for _, file := range pkg.Syntax {
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if fn := gin.ResolveCalleeFunc(pkg.TypesInfo, call.Fun); fn != nil {
					called[fn] = true
				}
				return true
			})
		}
	}
	return called
}

// BuildSymbolIndex inverts a function index into canonical-symbol lookup,
// using the exact same formatting resolveCallable uses when it stamps a
// route's middleware.canonicalSymbol — so internal/classify can go from a
// configured authMiddleware key, or a matched route's canonical symbol
// string, back to the *types.Func needed to run gin.AnalyzeEnforcement.
func BuildSymbolIndex(funcIndex map[*types.Func]gin.FuncInfo) map[string]*types.Func {
	index := make(map[string]*types.Func, len(funcIndex))
	for fn := range funcIndex {
		if sym := gin.FuncCanonicalSymbol(fn); sym != "" {
			index[sym] = fn
		}
	}
	return index
}

func modulePathOf(pkgs []*packages.Package) string {
	for _, pkg := range pkgs {
		if pkg.Module != nil {
			return pkg.Module.Path
		}
	}
	return ""
}

// normalize sorts every slice into a stable, deterministic order per
// docs/report-contract.md's "Deterministically ordered routes,
// globalMiddleware, and fallbackSurfaces" — required so two runs over
// identical source produce byte-identical JSON regardless of incidental
// go/packages file-visitation order.
func normalize(result *InventoryResult) {
	sort.SliceStable(result.Routes, func(i, j int) bool {
		a, b := result.Routes[i], result.Routes[j]
		if a.Method != b.Method {
			return a.Method < b.Method
		}
		if a.NormalizedPath != b.NormalizedPath {
			return a.NormalizedPath < b.NormalizedPath
		}
		return sourceLess(a.Source, b.Source)
	})
	sort.SliceStable(result.GlobalMiddleware, func(i, j int) bool {
		return result.GlobalMiddleware[i].DisplayName < result.GlobalMiddleware[j].DisplayName
	})
	sort.SliceStable(result.FallbackSurfaces, func(i, j int) bool {
		return result.FallbackSurfaces[i].Kind < result.FallbackSurfaces[j].Kind
	})
	sort.SliceStable(result.Diagnostics, func(i, j int) bool {
		a, b := result.Diagnostics[i], result.Diagnostics[j]
		if a.Code != b.Code {
			return a.Code < b.Code
		}
		return sourceLess(a.Source, b.Source)
	})
}

func sourceLess(a, b *model.Source) bool {
	if a == nil || b == nil {
		return b != nil // nil sorts first
	}
	if a.File != b.File {
		return a.File < b.File
	}
	if a.Line == nil || b.Line == nil {
		return b.Line != nil
	}
	return *a.Line < *b.Line
}

func buildScanCoverage(loaded *Loaded, diagnostics []model.Diagnostic) model.ScanCoverage {
	discoveredFiles, analyzedFiles, failedFiles := 0, 0, 0
	failedPackages := 0
	for _, pkg := range loaded.Packages {
		discoveredFiles += len(pkg.CompiledGoFiles)
		if len(pkg.Errors) > 0 {
			failedPackages++
			failedFiles += len(pkg.CompiledGoFiles)
		} else {
			analyzedFiles += len(pkg.CompiledGoFiles)
		}
	}

	unresolved := 0
	for _, d := range diagnostics {
		if coverageAffectingCodes[d.Code] {
			unresolved++
		}
	}

	return model.ScanCoverage{
		DiscoveredPackages:      len(loaded.Packages),
		AnalyzedPackages:        len(loaded.Packages) - failedPackages,
		FailedPackages:          failedPackages,
		DiscoveredFiles:         discoveredFiles,
		AnalyzedFiles:           analyzedFiles,
		FailedFiles:             failedFiles,
		UnresolvedRegistrations: unresolved,
		BuildContext:            loaded.BuildContext,
		Profile:                 model.ProfileTyped,
		Complete:                failedPackages == 0 && len(loaded.LoadErrors) == 0 && unresolved == 0,
	}
}
