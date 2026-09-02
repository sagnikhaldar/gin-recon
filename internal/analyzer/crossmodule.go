package analyzer

import (
	"go/ast"
	"go/types"
	"path/filepath"

	"github.com/sagnikhaldar/gin-recon/internal/analyzer/gin"
	"github.com/sagnikhaldar/gin-recon/internal/globmatch"
	"github.com/sagnikhaldar/gin-recon/internal/model"
	"golang.org/x/tools/go/packages"
)

// buildCrossModuleFuncIndex extends a function index with functions from
// dependency packages whose owning Go module path matches one of the
// configured globs — never anything else. This is the only mechanism in
// gin-recon that lets registrar-following (internal/analyzer/gin's
// tryFollowRegistrarCall) cross a module boundary, and it does so only when
// a reviewer has explicitly opted specific modules in via
// analysis.followModules; see
// docs/adr/0010-opt-in-cross-module-registrar-following.md for the full
// rationale.
//
// It deliberately uses packages.Visit's full transitive closure — unlike
// buildFuncIndex, which stays within loaded.Packages precisely to avoid
// that cost (see its own doc comment) — but the glob filter keeps the
// actual work bounded to however many modules a reviewer names, not the
// whole dependency graph: a package whose module does not match is skipped
// before its Decls are ever walked.
//
// externalFiles is populated as a side effect with every matched package's
// compiled file paths mapped to that package's *packages.Module, letting
// relativizeCrossModuleSource later turn an absolute path into a stable,
// non-leaking "module@version/relative/path" label instead of an absolute
// filesystem path.
func buildCrossModuleFuncIndex(roots []*packages.Package, globs []string, index map[*types.Func]gin.FuncInfo, externalFiles map[string]*packages.Module) {
	if len(globs) == 0 {
		return
	}
	seen := map[*packages.Package]bool{}
	packages.Visit(roots, nil, func(pkg *packages.Package) {
		if seen[pkg] || pkg.TypesInfo == nil || pkg.Module == nil {
			return
		}
		seen[pkg] = true
		if !globmatch.Any(globs, pkg.Module.Path) {
			return
		}
		for _, f := range pkg.CompiledGoFiles {
			externalFiles[f] = pkg.Module
		}
		for _, f := range pkg.GoFiles {
			externalFiles[f] = pkg.Module
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
	})
}

// relativizeCrossModuleSource is relativizeSource's counterpart for a
// source file that resolveEngineFactoryCall/tryFollowRegistrarCall reached
// outside the target module's own root: rather than a raw absolute
// filesystem path (which would leak local module-cache layout and,
// incidentally, violate docs/cli-contract.md's "never absolute checkout
// paths" for a path that was never under --src to begin with), it becomes
// "<module path>@<version>/<path within the module>" — stable across
// machines, never containing a local cache directory or username, and
// self-evidently external via the module-path prefix. s.File must still be
// the original absolute path when this is called (relativizeSource calls it
// before ever overwriting s.File).
func relativizeCrossModuleSource(externalFiles map[string]*packages.Module, s *model.Source) {
	mod, ok := externalFiles[s.File]
	if !ok {
		// Should not happen in practice — every file Discover can reach
		// through the cross-module index was recorded in externalFiles
		// above — but never fall through to leaking the raw absolute path
		// if it somehow does.
		s.File = "external:unresolved"
		return
	}
	rel, err := filepath.Rel(mod.Dir, s.File)
	if err != nil {
		s.File = "external:" + mod.Path
		return
	}
	label := mod.Path
	if mod.Version != "" {
		label += "@" + mod.Version
	}
	s.File = label + "/" + filepath.ToSlash(rel)
}
