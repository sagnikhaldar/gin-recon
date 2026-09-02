package analyzer

import (
	"context"
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/sagnikhaldar/gin-recon/internal/model"
)

// SyntaxFile is one successfully parsed file from a syntax-only load.
type SyntaxFile struct {
	Path string // root-relative, slash-separated
	File *ast.File
}

// LoadedSyntax is the result of a syntax-only (hermetic) load: every parsed
// .go file beneath the resolved root, sharing one token.FileSet, with no
// go/packages or Go toolchain invocation anywhere in its construction — see
// docs/threat-model.md's syntax-only trust profile.
type LoadedSyntax struct {
	Fset         *token.FileSet
	Files        []*SyntaxFile
	BuildContext model.BuildContext
	Root         string
	Module       string
	Diagnostics  []model.Diagnostic

	DiscoveredFiles int
	AnalyzedFiles   int
	FailedFiles     int
}

// LoadSyntax hermetically parses every in-scope .go file beneath opts.Src
// using only go/parser and go/build's pure file-content build-tag matching —
// it never invokes go/packages, the Go toolchain, or any network access, and
// rejects any symlink that resolves outside opts.Src rather than following
// it, per docs/threat-model.md's syntax-only trust profile ("Symlinks that
// resolve outside the root are rejected").
//
// A per-file parse error is recorded as a diagnostic and that file is
// skipped, not treated as fatal — a hermetic parser deliberately tolerates
// malformed input elsewhere in a hostile or partially-broken checkout rather
// than refusing to analyze anything at all. Only a root with zero
// successfully parsed .go files at all is fatal, mirroring typed Load's own
// "fatal inability to load the requested root" behavior.
func LoadSyntax(ctx context.Context, opts LoadOptions) (*LoadedSyntax, error) {
	moduleMode := opts.ModuleMode
	if moduleMode == "" {
		// Module mode governs go/packages' -mod flag, which syntax-only
		// never invokes at all — there is no vendor/readonly distinction to
		// make. "readonly" is stamped purely so this report field satisfies
		// schema/report-1.0.json's closed moduleMode enum; it carries no
		// behavioral meaning for this profile.
		moduleMode = model.ModuleReadonly
	}
	fset := token.NewFileSet()
	loaded := &LoadedSyntax{
		Fset: fset,
		Root: opts.Src,
		BuildContext: model.BuildContext{
			GOOS:          opts.GOOS,
			GOARCH:        opts.GOARCH,
			Tags:          append([]string{}, opts.Tags...),
			WorkspaceMode: workspaceMode(opts.Workspace),
			ModuleMode:    moduleMode,
			Profile:       model.ProfileSyntaxOnly,
		},
	}
	loaded.Module = readModulePath(opts.Src)

	buildCtx := build.Context{GOOS: opts.GOOS, GOARCH: opts.GOARCH, Compiler: "gc", BuildTags: opts.Tags}

	err := filepath.WalkDir(opts.Src, func(path string, d fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			loaded.diagnose("gin-syntax-walk-error", fmt.Sprintf("could not read %s: %v", relOrAbs(opts.Src, path), err), "")
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if path == opts.Src {
			return nil
		}

		if d.Type()&fs.ModeSymlink != 0 {
			if escapesRoot(opts.Src, path) {
				loaded.diagnose("gin-syntax-symlink-escape", "symlink resolves outside the scan root and was rejected: "+relOrAbs(opts.Src, path), "")
				return nil
			}
			// A symlink that stays within root is otherwise treated like any
			// other entry below (WalkDir does not itself follow symlinks to
			// directories, so a symlinked directory is simply skipped rather
			// than traversed — a narrow recall limitation, never a safety
			// issue, since nothing outside root is ever read either way).
			return nil
		}

		if d.IsDir() {
			name := d.Name()
			if name == "vendor" || name == ".git" || strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			return nil
		}

		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, relErr := filepath.Rel(opts.Src, path)
		if relErr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if !inScope(path, opts.Src, opts.Include, opts.Exclude) {
			return nil
		}

		match, matchErr := buildCtx.MatchFile(filepath.Dir(path), filepath.Base(path))
		if matchErr == nil && !match {
			return nil // excluded by the file's own build tags for the selected GOOS/GOARCH/tags
		}

		loaded.DiscoveredFiles++
		file, parseErr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if parseErr != nil {
			loaded.FailedFiles++
			loaded.diagnose("gin-syntax-parse-error", "could not parse "+rel+": "+parseErr.Error(), rel)
			return nil
		}
		loaded.AnalyzedFiles++
		loaded.Files = append(loaded.Files, &SyntaxFile{Path: rel, File: file})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking %s: %w", opts.Src, err)
	}

	if len(loaded.Files) == 0 {
		return nil, fmt.Errorf("no analyzable .go files found under %s", opts.Src)
	}

	return loaded, nil
}

// escapesRoot reports whether path — after resolving every symlink in it —
// no longer falls beneath root. Used only for entries WalkDir has already
// identified as themselves being a symlink; a non-symlink path can never
// escape root since WalkDir only ever visits descendants of root.
func escapesRoot(root, path string) bool {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return true // unresolvable symlink (dangling, permission denied): reject rather than guess
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		resolvedRoot = root
	}
	rel, err := filepath.Rel(resolvedRoot, resolved)
	if err != nil {
		return true
	}
	return rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func relOrAbs(root, path string) string {
	if rel, err := filepath.Rel(root, path); err == nil {
		return filepath.ToSlash(rel)
	}
	return path
}

func (l *LoadedSyntax) diagnose(code, message, relPath string) {
	d := model.Diagnostic{Code: code, Severity: model.DiagnosticWarning, Message: message}
	if relPath != "" {
		d.Source = &model.Source{File: relPath}
	}
	l.Diagnostics = append(l.Diagnostics, d)
}

// readModulePath best-effort reads the module path from go.mod's first
// "module " line using a plain text scan — never `go list`, never any
// toolchain invocation, consistent with syntax-only's hermetic-parsing-only
// contract. An unreadable or missing go.mod yields an empty module path
// rather than an error: the report's module field is informational, not
// load-bearing for discovery itself.
func readModulePath(root string) string {
	data, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if after, ok := strings.CutPrefix(line, "module "); ok {
			return strings.TrimSpace(after)
		}
	}
	return ""
}
