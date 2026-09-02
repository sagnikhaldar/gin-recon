// Package analyzer orchestrates package loading and Gin discovery across a
// whole target module, producing a normalized model.Route/model.Middleware
// registry. It is the caller of internal/analyzer/gin's type-identity
// recognition and route-discovery walker; this package owns everything that
// requires visibility across the whole loaded package set (the trust
// boundary and sanitized environment for typed loading, and the whole-module
// function index that makes registrar-following possible).
package analyzer

import (
	"context"
	"fmt"
	"go/ast"
	"os"
	"path/filepath"
	"strings"

	"github.com/sagnikhaldar/gin-recon/internal/globmatch"
	"github.com/sagnikhaldar/gin-recon/internal/model"
	"golang.org/x/tools/go/packages"
)

// LoadOptions mirrors the subset of cli.Options that affects package
// loading. It is a separate type (not cli.Options itself) so this package
// has no dependency on internal/cli, keeping the loader usable from the MCP
// server or a library caller that never goes through the CLI at all.
type LoadOptions struct {
	Src            string // must already be an absolute, symlink-resolved root (see cli.Validate)
	GOOS           string
	GOARCH         string
	Tags           []string
	Workspace      string // "off" or an absolute path beneath Src
	ModuleMode     model.ModuleMode
	AllowDownloads bool

	// Include/Exclude are root-relative "*"/"**" globs (see internal/globmatch)
	// scoping the scan to a subset of the target's own source files, per
	// docs/cli-contract.md's --include/--exclude (the caller is responsible
	// for folding an --ignore-file's patterns into Exclude — this package has
	// no filesystem-path concept of "the ignore file", only the resolved glob
	// list). An excluded file is removed from the scan as completely as if it
	// did not exist: not just absent from discovered routes, but also
	// unavailable to registrar-following and enforcement-shape analysis, so a
	// registrar call reaching into excluded scope honestly surfaces as
	// unresolved (via the same gin-unresolved-registrar diagnostic an
	// external/unavailable-source callee already produces) rather than
	// silently reaching outside the declared scope. Include, when non-empty,
	// restricts the scan to only matching files; Exclude removes matching
	// files regardless of Include.
	Include []string
	Exclude []string

	// FollowModules is a list of Go module import-path glob patterns
	// (internal/globmatch) that registrar-following is explicitly permitted
	// to cross into, beyond the target module's own source — see
	// docs/adr/0010-opt-in-cross-module-registrar-following.md. Empty by
	// default: no module boundary is ever crossed unless a reviewer
	// configures this explicitly via analysis.followModules.
	FollowModules []string
}

// Loaded is the result of a typed load: every package in the target module,
// the resolved Gin API (nil if the target does not import Gin at all), and
// the whole-module function index that lets gin.Discover follow registrar
// calls across files and packages.
type Loaded struct {
	Packages      []*packages.Package
	BuildContext  model.BuildContext
	LoadErrors    []packages.Error // dependency-resolution and parse failures collected by go/packages itself
	Root          string           // the resolved scan root every model.Source.File is made relative to
	FollowModules []string         // see LoadOptions.FollowModules
}

// Load type-checks every package in opts.Src using the sanitized,
// offline-by-default environment docs/threat-model.md's typed profile
// requires. It never runs the target application — packages.Load only
// invokes the Go toolchain's package-loading machinery (effectively `go
// list`/`go build -n`-equivalent introspection), not `go run` or `go test`.
//
// ctx bounds wall time; the caller (internal/cli or the MCP server) is
// responsible for deriving it from the configured/resolved timeout limit.
func Load(ctx context.Context, opts LoadOptions) (*Loaded, error) {
	cacheDir, err := prepareCacheDir()
	if err != nil {
		return nil, err
	}

	cfg := &packages.Config{
		Context: ctx,
		Dir:     opts.Src,
		Env:     sanitizedEnv(opts, cacheDir),
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedImports | packages.NeedDeps |
			packages.NeedTypes | packages.NeedSyntax | packages.NeedTypesInfo |
			packages.NeedModule,
		Tests: false,
	}

	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		return nil, fmt.Errorf("loading packages under %s: %w", opts.Src, err)
	}

	// packages.Load frequently reports a fatal condition (no go.mod, no Go
	// files, a directory outside any module) not through its own err return
	// but as a single synthetic package whose Errors describe the failure —
	// docs/report-contract.md's "Fatal inability to load the requested root"
	// must exit 1, not silently produce an empty "successful" report for a
	// root that was never actually analyzable at all.
	if allPackagesFailed(pkgs) {
		return nil, fmt.Errorf("loading packages under %s: %s", opts.Src, joinPackageErrors(pkgs))
	}

	filterPackagesByScope(pkgs, opts.Src, opts.Include, opts.Exclude)

	var loadErrors []packages.Error
	packages.Visit(pkgs, nil, func(pkg *packages.Package) {
		loadErrors = append(loadErrors, pkg.Errors...)
	})

	return &Loaded{
		Packages: pkgs,
		BuildContext: model.BuildContext{
			GOOS:          opts.GOOS,
			GOARCH:        opts.GOARCH,
			Tags:          append([]string{}, opts.Tags...),
			WorkspaceMode: workspaceMode(opts.Workspace),
			ModuleMode:    opts.ModuleMode,
			Profile:       model.ProfileTyped,
		},
		LoadErrors:    loadErrors,
		Root:          opts.Src,
		FollowModules: opts.FollowModules,
	}, nil
}

// allPackagesFailed reports whether every discovered package carries an
// error — the signature of a root that was never actually analyzable (no
// go.mod, no Go files, outside any module), as opposed to a real module
// where some packages loaded fine and others merely have issues.
func allPackagesFailed(pkgs []*packages.Package) bool {
	if len(pkgs) == 0 {
		return true
	}
	for _, pkg := range pkgs {
		if len(pkg.Errors) == 0 {
			return false
		}
	}
	return true
}

func joinPackageErrors(pkgs []*packages.Package) string {
	var messages []string
	packages.Visit(pkgs, nil, func(pkg *packages.Package) {
		for _, e := range pkg.Errors {
			messages = append(messages, e.Error())
		}
	})
	return strings.Join(messages, "; ")
}

// filterPackagesByScope removes every file outside opts.Include/Exclude's
// scope from each package's Syntax, CompiledGoFiles, and GoFiles, in place.
// This is the only place scope filtering happens — every downstream
// consumer (buildFuncIndex, discover's per-file walk, engineSecurityFindings,
// buildScanCoverage's file counts) iterates these same fields, so filtering
// once here propagates everywhere with no changes needed to any of them,
// and an excluded file is uniformly invisible rather than invisible to some
// consumers and not others.
func filterPackagesByScope(pkgs []*packages.Package, root string, include, exclude []string) {
	if len(include) == 0 && len(exclude) == 0 {
		return
	}
	for _, pkg := range pkgs {
		if pkg.Fset == nil {
			continue // a synthetic error-only package (e.g. the "no go.mod" placeholder) has no files to filter
		}
		kept := make([]*ast.File, 0, len(pkg.Syntax))
		for _, file := range pkg.Syntax {
			tokFile := pkg.Fset.File(file.Pos())
			if tokFile == nil || inScope(tokFile.Name(), root, include, exclude) {
				kept = append(kept, file)
			}
		}
		pkg.Syntax = kept
		pkg.CompiledGoFiles = filterFilePaths(pkg.CompiledGoFiles, root, include, exclude)
		pkg.GoFiles = filterFilePaths(pkg.GoFiles, root, include, exclude)
	}
}

func filterFilePaths(paths []string, root string, include, exclude []string) []string {
	kept := make([]string, 0, len(paths))
	for _, p := range paths {
		if inScope(p, root, include, exclude) {
			kept = append(kept, p)
		}
	}
	return kept
}

// inScope reports whether absPath (an absolute file path) falls within the
// requested include/exclude scope relative to root. A path outside root
// entirely (should not normally occur — every loaded file belongs to the
// scanned module) is kept rather than silently dropped, since dropping it
// could only ever hide a real file, never correctly narrow the scan.
func inScope(absPath, root string, include, exclude []string) bool {
	rel, err := filepath.Rel(root, absPath)
	if err != nil {
		return true
	}
	rel = filepath.ToSlash(rel)
	if globmatch.Any(exclude, rel) {
		return false
	}
	if len(include) > 0 && !globmatch.Any(include, rel) {
		return false
	}
	return true
}

func workspaceMode(workspace string) model.WorkspaceMode {
	if workspace == "" || workspace == "off" {
		return model.WorkspaceOff
	}
	return model.WorkspaceWorkspace
}

// ResolveModuleMode applies docs/cli-contract.md's default: "--module-mode
// readonly|vendor: default vendor when a valid root-contained vendor tree
// exists, otherwise readonly." given is returned unchanged when it is
// already set explicitly (e.g. from --module-mode); only an empty value is
// resolved here.
func ResolveModuleMode(src string, given model.ModuleMode) model.ModuleMode {
	if given != "" {
		return given
	}
	if info, err := os.Stat(filepath.Join(src, "vendor", "modules.txt")); err == nil && !info.IsDir() {
		return model.ModuleVendor
	}
	return model.ModuleReadonly
}
