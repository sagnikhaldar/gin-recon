package gin

import (
	"go/ast"
	"go/token"
	"strconv"

	"github.com/sagnikhaldar/gin-recon/internal/model"
)

// This file implements the syntax-only profile's route discovery: hermetic,
// go/types-free parsing per docs/threat-model.md's syntax-only trust
// profile. It deliberately trades recall for a strictly smaller trust
// boundary (no go/packages, no Go toolchain invocation at all) and is
// scoped to exactly what docs/adr/0001-static-first-v1.md and PLAN.md
// promise for it: "hermetic parsing... inventories direct Gin-shaped
// registrations but cannot provide canonical symbol identity... or
// inter-package registrar resolution."
//
// Concretely, relative to the typed discoverer (discover.go), this walker:
//   - Tracks engine/group values by source variable name within a single
//     function body, not by go/types object identity across the whole
//     module. A same-named local variable shadowing an outer one in a
//     nested scope is not distinguished — a known, narrow imprecision this
//     analyzer accepts in exchange for needing no type information at all.
//   - Recognizes an inline, unassigned Group() chain
//     ("e.Group("/x").GET(...)") by recursively resolving the receiver
//     expression, in addition to the named-variable case
//     ("admin := e.Group("/x"); admin.GET(...)").
//   - Does not follow registrar functions across calls at all (typed's
//     tryFollowRegistrarCall requires a whole-module function index built
//     from typed packages). A call that passes a same-named tracked value
//     to another function is flagged with a coverage diagnostic instead of
//     silently dropped, but never actually followed.
//   - Never resolves a middleware/handler reference to a canonical package
//     symbol — every model.Middleware this walker produces has
//     ResolutionStatus Unresolved and a nil CanonicalSymbol, which in turn
//     means internal/classify can never match it against a configured
//     authMiddleware/authWrappers entry: syntax-only audit results are
//     always "public" (or opaque-flagged), never "proven". This is the
//     enforcement mechanism behind "syntax-only cannot emit proven" — no
//     special-casing exists or is needed in internal/classify itself.
//   - Only resolves a path/method argument that is a literal string (or
//     literal string slice for Match); named/qualified constants and
//     concatenation, which go/types' constant folding resolves for typed
//     mode, are not — the same "route not inventoried" diagnostic fires as
//     for any other non-literal path, correctly reporting reduced recall
//     rather than guessing.

// ginImportAlias returns the local identifier gin-gonic/gin is imported as
// in file, and whether it is imported at all. A blank ("_") import can never
// be referenced and a dot (".") import's bare New()/Default() calls are not
// recognized — without type information this analyzer cannot rule out an
// unrelated dot-imported package's own New/Default function, and a false
// engine-construction match would let every method call inside that
// function be silently misread as Gin route registration.
// GinImportAlias is the exported form of ginImportAlias, for callers outside
// this package (internal/analyzer's engine-security orchestration needs the
// same alias resolution DiscoverFileSyntax uses internally, to recognize
// "<ginAlias>.SetMode(<ginAlias>.DebugMode)" the same way).
func GinImportAlias(file *ast.File) (string, bool) { return ginImportAlias(file) }

func ginImportAlias(file *ast.File) (string, bool) {
	for _, imp := range file.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil || path != PackagePath {
			continue
		}
		if imp.Name == nil {
			return "gin", true
		}
		if imp.Name.Name == "_" || imp.Name.Name == "." {
			return "", false
		}
		return imp.Name.Name, true
	}
	return "", false
}

// isNewEngineCallSyntax recognizes "<ginAlias>.New()"/"<ginAlias>.Default()"
// purely from the identifier text resolved from the file's own import
// declaration — the syntax-only equivalent of isNewEngineCall's package-path
// identity check, which needs go/types to rule out a same-named local
// shadowing the package identifier. Accepting that narrow imprecision here
// is exactly the "reduced confidence" trade this profile is documented to
// make.
func isNewEngineCallSyntax(ginAlias string, call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkgIdent, ok := sel.X.(*ast.Ident)
	if !ok || pkgIdent.Name != ginAlias {
		return false
	}
	return sel.Sel.Name == "New" || sel.Sel.Name == "Default"
}

// HasEngineConstructionSyntax is DiscoverSyntax's entry-point gate, mirroring
// HasEngineConstruction's role for the typed discoverer: only a function
// whose body directly calls "<ginAlias>.New()"/"<ginAlias>.Default()" is a
// legitimate syntax-only discovery entry point.
func HasEngineConstructionSyntax(ginAlias string, fn *ast.FuncDecl) bool {
	if fn.Body == nil {
		return false
	}
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if found {
			return false
		}
		if call, ok := n.(*ast.CallExpr); ok && isNewEngineCallSyntax(ginAlias, call) {
			found = true
			return false
		}
		return true
	})
	return found
}

// pendingSyntaxFallback mirrors typed's pendingFallback, keyed by a direct
// *groupEntry pointer rather than a re-looked-up types.Object: since entry
// is the exact mutable struct later Use() calls append to in place, reading
// entry.middleware in finish() automatically reflects the engine's final
// accumulated state with no separate lookup step needed.
type pendingSyntaxFallback struct {
	kind     model.FallbackSurfaceKind
	entry    *groupEntry
	handlers []callableRef
	source   *model.Source
}

// syntaxDiscoverer is DiscoverSyntax's per-function walker state. It reuses
// discover.go's groupEntry and callableRef types unchanged — both are
// already free of any go/types-specific field, so no parallel type is
// needed.
type syntaxDiscoverer struct {
	fset     *token.FileSet
	ginAlias string

	groups      map[string]*groupEntry // tracked by source variable name
	rootEntries []*groupEntry          // every root engine created, for GlobalMiddleware output

	// fileFuncs indexes every top-level function declared in the same file
	// by name, purely by source text — syntax-only has no type information
	// to resolve a handler reference to a declaration the way the typed
	// path's funcIndex does. This is deliberately narrower than the typed
	// path's swag support: only a handler referenced by a bare identifier
	// that happens to be declared in the very same file is matched. A
	// handler from another file or package, or referenced through a
	// selector/method value, is not — a known, accepted gap consistent with
	// this whole profile's "reduced recall, hermetic parsing only" trade
	// (see this file's package doc comment).
	fileFuncs map[string]*ast.FuncDecl

	routes      []model.Route
	fallbacks   []pendingSyntaxFallback
	diagnostics []model.Diagnostic
}

// discoverSyntax is the syntax-only, hermetic-parsing equivalent of Discover
// for a single function. fn must be a function HasEngineConstructionSyntax
// has already confirmed constructs a Gin engine directly; ginAlias is the
// local identifier gin-gonic/gin resolves to in fn's file (from
// ginImportAlias). fileFuncs is the same file's own top-level function index
// (see syntaxDiscoverer.fileFuncs), used only for swag doc-comment lookup.
func discoverSyntax(fset *token.FileSet, ginAlias string, fn *ast.FuncDecl, fileFuncs map[string]*ast.FuncDecl) *Registry {
	d := &syntaxDiscoverer{
		fset:      fset,
		ginAlias:  ginAlias,
		groups:    map[string]*groupEntry{},
		fileFuncs: fileFuncs,
	}
	if fn.Body != nil {
		d.walkStmts(fn.Body.List)
	}
	return d.finish()
}

// DiscoverFileSyntax is the syntax-only orchestration entry point for one
// parsed file: it resolves gin-gonic/gin's local import alias (if the file
// imports it at all — a file that does not is a valid, empty result, not an
// error, the same as a whole module that never uses Gin), finds every
// top-level function that directly constructs an engine, and merges their
// discovered routes/middleware/diagnostics. This is the only syntax-only
// discovery function internal/analyzer needs to call; it deliberately
// mirrors internal/analyzer's own typed discover() loop shape (one exported
// call per file/package) so the two orchestration paths read the same way.
func DiscoverFileSyntax(fset *token.FileSet, file *ast.File) *Registry {
	merged := &Registry{}
	ginAlias, ok := ginImportAlias(file)
	if !ok {
		return merged
	}
	fileFuncs := map[string]*ast.FuncDecl{}
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			fileFuncs[fn.Name.Name] = fn
		}
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		if !HasEngineConstructionSyntax(ginAlias, fn) {
			continue
		}
		reg := discoverSyntax(fset, ginAlias, fn, fileFuncs)
		merged.Routes = append(merged.Routes, reg.Routes...)
		merged.GlobalMiddleware = append(merged.GlobalMiddleware, reg.GlobalMiddleware...)
		merged.FallbackSurfaces = append(merged.FallbackSurfaces, reg.FallbackSurfaces...)
		merged.Diagnostics = append(merged.Diagnostics, reg.Diagnostics...)
	}
	return merged
}

// walkStmts/walkStmt mirror the typed discoverer's own traversal exactly
// (see discover.go's copy for the rationale behind descending into every
// nested block without tracking branch/loop identity) — duplicated rather
// than shared because Go has no way to share a method across two distinct
// receiver types without an interface layer that would only obscure this
// small, stable traversal for no real benefit.
func (d *syntaxDiscoverer) walkStmts(stmts []ast.Stmt) {
	for _, stmt := range stmts {
		d.walkStmt(stmt)
	}
}

func (d *syntaxDiscoverer) walkStmt(stmt ast.Stmt) {
	switch s := stmt.(type) {
	case *ast.AssignStmt:
		d.handleAssign(s)
	case *ast.ExprStmt:
		d.handleExprStmt(s)
	case *ast.BlockStmt:
		d.walkStmts(s.List)
	case *ast.IfStmt:
		if s.Init != nil {
			d.walkStmt(s.Init)
		}
		d.walkStmt(s.Body)
		if s.Else != nil {
			d.walkStmt(s.Else)
		}
	case *ast.ForStmt:
		if s.Init != nil {
			d.walkStmt(s.Init)
		}
		d.walkStmt(s.Body)
	case *ast.RangeStmt:
		d.walkStmt(s.Body)
	case *ast.SwitchStmt:
		if s.Init != nil {
			d.walkStmt(s.Init)
		}
		for _, c := range s.Body.List {
			if cc, ok := c.(*ast.CaseClause); ok {
				d.walkStmts(cc.Body)
			}
		}
	case *ast.TypeSwitchStmt:
		if s.Init != nil {
			d.walkStmt(s.Init)
		}
		for _, c := range s.Body.List {
			if cc, ok := c.(*ast.CaseClause); ok {
				d.walkStmts(cc.Body)
			}
		}
	}
	// No ReturnStmt case: typed's ReturnStmt handling exists solely to feed
	// tryFollowRegistrarCall, which syntax-only does not implement (see the
	// package-level doc comment above) — a returned registrar call is a
	// cross-function propagation case out of scope here.
}

// handleAssign processes each RHS call in an assignment, binding an
// engine/group-producing call's result to its LHS variable name.
func (d *syntaxDiscoverer) handleAssign(s *ast.AssignStmt) {
	for i, rhs := range s.Rhs {
		call, ok := rhs.(*ast.CallExpr)
		if !ok {
			continue
		}
		var lhsName string
		if i < len(s.Lhs) {
			if id, ok := s.Lhs[i].(*ast.Ident); ok && id.Name != "_" {
				lhsName = id.Name
			}
		}
		if isNewEngineCallSyntax(d.ginAlias, call) {
			entry := &groupEntry{isRoot: true, basePath: "/"}
			d.rootEntries = append(d.rootEntries, entry)
			if lhsName != "" {
				d.groups[lhsName] = entry
			}
			continue
		}
		if entry, ok := d.resolveReceiver(call); ok {
			if lhsName != "" {
				d.groups[lhsName] = entry
			}
			continue
		}
		d.tryDiagnoseUnfollowedCall(call)
	}
}

// resolveReceiver resolves expr — the X in "X.Method(...)" — to its
// groupEntry. It handles both a named, previously-bound variable and an
// inline, unassigned Group() chain ("e.Group("/x")") by recursing into the
// call's own receiver, so "e.Group("/x").GET(...)" resolves correctly with
// no intermediate variable required. A chained .Use() call within such an
// inline expression is not supported (there is no lasting binding for it to
// mutate) — real Gin code overwhelmingly assigns a group it plans to call
// Use() on to a variable, so this is a narrow, accepted gap.
func (d *syntaxDiscoverer) resolveReceiver(expr ast.Expr) (*groupEntry, bool) {
	switch e := expr.(type) {
	case *ast.Ident:
		entry, ok := d.groups[e.Name]
		return entry, ok
	case *ast.CallExpr:
		sel, ok := e.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Group" {
			return nil, false
		}
		parent, ok := d.resolveReceiver(sel.X)
		if !ok {
			return nil, false
		}
		relPath, ok := d.stringConst(e.Args, 0)
		if !ok {
			d.diagnose("gin-unresolved-path", "Group() path is not a string literal; group and its routes are not inventoried", e.Pos())
			return nil, false
		}
		child := &groupEntry{basePath: JoinPaths(parent.basePath, relPath), middleware: append([]callableRef{}, parent.middleware...)}
		for _, arg := range e.Args[1:] {
			child.middleware = append(child.middleware, callableRef{
				callable: resolveCallableSyntax(arg),
				source:   d.sourceOf(arg.Pos()),
				scope:    model.ScopeGroup,
			})
		}
		return child, true
	default:
		return nil, false
	}
}

func (d *syntaxDiscoverer) handleExprStmt(s *ast.ExprStmt) {
	call, ok := s.X.(*ast.CallExpr)
	if !ok {
		return
	}
	if d.tryHandleGinMethodCall(call) {
		return
	}
	d.tryDiagnoseUnfollowedCall(call)
}

func (d *syntaxDiscoverer) tryHandleGinMethodCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	entry, tracked := d.resolveReceiver(sel.X)
	if !tracked {
		d.diagnoseUntrackedValue(sel)
		return false
	}

	switch sel.Sel.Name {
	case "Use":
		scope := model.ScopeGroup
		if entry.isRoot {
			scope = model.ScopeGlobal
		}
		for _, arg := range call.Args {
			entry.middleware = append(entry.middleware, callableRef{
				callable: resolveCallableSyntax(arg),
				source:   d.sourceOf(arg.Pos()),
				scope:    scope,
			})
		}

	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
		d.registerRoute(entry, sel.Sel.Name, call, 0, model.RegistrationVerb)

	case "Handle":
		method, ok := d.stringConst(call.Args, 0)
		if !ok {
			d.diagnose("gin-unresolved-method", "Handle() method is not a string literal; route not inventoried", call.Pos())
			return true
		}
		d.registerRoute(entry, method, call, 1, model.RegistrationHandle)

	case "Any":
		for _, method := range anyMethods {
			d.registerRoute(entry, method, call, 0, model.RegistrationAny)
		}

	case "Match":
		methods, ok := d.stringSliceLiteral(call.Args, 0)
		if !ok {
			d.diagnose("gin-unresolved-methods", "Match() methods argument is not a literal string slice; route not inventoried", call.Pos())
			return true
		}
		for _, method := range methods {
			d.registerRoute(entry, method, call, 1, model.RegistrationMatch)
		}

	case "Static", "StaticFile", "StaticFS", "StaticFileFS":
		d.registerStatic(entry, sel.Sel.Name, call)

	case "NoRoute":
		d.registerFallback(model.FallbackNoRoute, entry, call)

	case "NoMethod":
		d.registerFallback(model.FallbackNoMethod, entry, call)
	}
	return true
}

// diagnoseUntrackedValue is the syntax-only, name-only equivalent of typed's
// diagnoseUntrackedRouterValue: it cannot confirm via a type check that the
// receiver is actually a *gin.Engine/*gin.RouterGroup (syntax-only has no
// type information at all), so it fires for any route-relevant method call
// on an untracked identifier. This trades some false-positive risk (an
// unrelated type that happens to have a method named e.g. "Use") for the
// threat model's overriding priority: a hidden route is worse than a noisy
// diagnostic about a route that turns out not to exist.
func (d *syntaxDiscoverer) diagnoseUntrackedValue(sel *ast.SelectorExpr) {
	if !routeRelevantMethodNames[sel.Sel.Name] {
		return
	}
	d.diagnose("gin-syntax-untracked-value",
		sel.Sel.Name+"() called on a value this hermetic parse could not trace to "+d.ginAlias+".New()/"+d.ginAlias+".Default() in this function; routes registered through it are not inventoried (syntax-only cannot follow values across functions)",
		sel.Sel.Pos())
}

// tryDiagnoseUnfollowedCall flags — without ever following it — a call that
// passes an identifier sharing a name with a tracked group/engine variable,
// the syntax-only signature of the "registerRoutes(r)" registrar pattern
// typed mode's tryFollowRegistrarCall actually follows. Matching by name
// only (not by any stable identity, since none is available without types)
// is a deliberately conservative, coverage-only signal: it never causes a
// route to be fabricated or a registrar to actually be entered, only a
// diagnostic that some registrations may not be inventoried.
func (d *syntaxDiscoverer) tryDiagnoseUnfollowedCall(call *ast.CallExpr) {
	for _, arg := range call.Args {
		ident, ok := arg.(*ast.Ident)
		if !ok {
			continue
		}
		if _, tracked := d.groups[ident.Name]; tracked {
			d.diagnose("gin-syntax-unresolved-registrar",
				"a value that may be a tracked gin.Engine/RouterGroup was passed to another call; syntax-only does not follow registrar functions across calls, so routes it may register are not inventoried",
				call.Pos())
			return
		}
	}
}

func (d *syntaxDiscoverer) registerRoute(entry *groupEntry, method string, call *ast.CallExpr, pathArgIndex int, kind model.RegistrationKind) {
	relPath, ok := d.stringConst(call.Args, pathArgIndex)
	if !ok {
		d.diagnose("gin-unresolved-path", method+" path is not a string literal; route not inventoried", call.Pos())
		return
	}
	absolutePath := JoinPaths(entry.basePath, relPath)

	handlerArgs := call.Args[pathArgIndex+1:]
	if len(handlerArgs) == 0 {
		d.diagnose("gin-no-handlers", method+" "+absolutePath+" has no handler arguments", call.Pos())
		return
	}
	if call.Ellipsis != token.NoPos {
		d.diagnose("gin-unresolved-handlers", method+" "+absolutePath+" passes handlers via a spread slice; individual handlers not inventoried", call.Pos())
		return
	}

	chain := append([]callableRef{}, entry.middleware...)
	for _, arg := range handlerArgs {
		chain = append(chain, callableRef{callable: resolveCallableSyntax(arg), source: d.sourceOf(arg.Pos()), scope: model.ScopeRoute})
	}

	route := model.Route{
		Method:           method,
		GinPath:          absolutePath,
		NormalizedPath:   normalizePath(absolutePath),
		SurfaceKind:      model.SurfaceRoute,
		RegistrationKind: registrationKindPtr(kind),
		// PathConfidence is High because the literal path text is exactly
		// what is written in source; AnalysisConfidence is Low because
		// syntax-only cannot type-check that the receiver genuinely is a
		// *gin.Engine/*gin.RouterGroup at all, per docs/threat-model.md.
		PathConfidence:     model.ConfidenceHigh,
		AnalysisConfidence: model.ConfidenceLow,
		EvidenceOrigins:    []string{"ast"},
	}
	route.Source = d.sourceOf(call.Pos())
	route.Middleware, route.FinalHandler = buildChain(chain)
	d.applySwagIfSameFileHandler(&route)
	d.routes = append(d.routes, route)
}

// applySwagIfSameFileHandler looks up route's final handler in fileFuncs —
// only when it was written as a bare identifier resolved to a function
// declared in this same file, per fileFuncs' own doc comment — and, if that
// declaration carries a swag doc comment, attaches it exactly as the typed
// path's applySwagAnnotations does.
func (d *syntaxDiscoverer) applySwagIfSameFileHandler(route *model.Route) {
	if route.FinalHandler.CallableKind != model.CallableIdentifier {
		return
	}
	fn, ok := d.fileFuncs[route.FinalHandler.DisplayName]
	if !ok || fn.Doc == nil {
		return
	}
	if diag := ApplySwagFromDoc(route, fn.Doc); diag != nil {
		d.diagnostics = append(d.diagnostics, *diag)
	}
}

func (d *syntaxDiscoverer) registerStatic(entry *groupEntry, method string, call *ast.CallExpr) {
	relPath, ok := d.stringConst(call.Args, 0)
	if !ok {
		d.diagnose("gin-unresolved-path", method+" path is not a string literal; route not inventoried", call.Pos())
		return
	}

	relPattern := relPath
	methods := []string{"GET", "HEAD"}
	if method != "StaticFile" && method != "StaticFileFS" {
		relPattern = JoinPaths(relPath, "/*filepath")
	}
	urlPattern := JoinPaths(entry.basePath, relPattern)

	for _, m := range methods {
		chain := append([]callableRef{}, entry.middleware...)
		chain = append(chain, callableRef{
			callable: callable{DisplayName: "<static-handler>", CallableKind: model.CallableUnknown, ResolutionStatus: model.Unresolved},
			source:   d.sourceOf(call.Pos()),
			scope:    model.ScopeRoute,
		})
		route := model.Route{
			Method:             m,
			GinPath:            urlPattern,
			NormalizedPath:     normalizePath(urlPattern),
			SurfaceKind:        model.SurfaceStatic,
			RegistrationKind:   registrationKindPtr(model.RegistrationStatic),
			PathConfidence:     model.ConfidenceHigh,
			AnalysisConfidence: model.ConfidenceLow,
			EvidenceOrigins:    []string{"ast"},
		}
		route.Source = d.sourceOf(call.Pos())
		route.Middleware, route.FinalHandler = buildChain(chain)
		d.routes = append(d.routes, route)
	}
}

func (d *syntaxDiscoverer) registerFallback(kind model.FallbackSurfaceKind, entry *groupEntry, call *ast.CallExpr) {
	var handlers []callableRef
	for _, arg := range call.Args {
		handlers = append(handlers, callableRef{callable: resolveCallableSyntax(arg), source: d.sourceOf(arg.Pos()), scope: model.ScopeRoute})
	}
	d.fallbacks = append(d.fallbacks, pendingSyntaxFallback{kind: kind, entry: entry, handlers: handlers, source: d.sourceOf(call.Pos())})
}

func (d *syntaxDiscoverer) finish() *Registry {
	reg := &Registry{}

	seen := map[*groupEntry]struct{}{}
	for _, root := range d.rootEntries {
		if _, dup := seen[root]; dup {
			continue
		}
		seen[root] = struct{}{}
		reg.GlobalMiddleware = append(reg.GlobalMiddleware, buildMiddlewareList(root.middleware)...)
	}

	for _, pf := range d.fallbacks {
		chain := append([]callableRef{}, pf.entry.middleware...)
		chain = append(chain, pf.handlers...)
		middleware, finalHandler := buildChain(chain)
		reg.FallbackSurfaces = append(reg.FallbackSurfaces, model.FallbackSurface{
			Kind:         pf.kind,
			Middleware:   middleware,
			FinalHandler: finalHandler,
			Source:       pf.source,
		})
	}

	reg.Routes = d.routes
	reg.Diagnostics = d.diagnostics
	return reg
}

func (d *syntaxDiscoverer) diagnose(code, message string, pos token.Pos) {
	d.diagnostics = append(d.diagnostics, model.Diagnostic{
		Code:     code,
		Severity: model.DiagnosticWarning,
		Message:  message,
		Source:   d.sourceOf(pos),
	})
}

func (d *syntaxDiscoverer) sourceOf(pos token.Pos) *model.Source {
	if pos == token.NoPos {
		return nil
	}
	p := d.fset.Position(pos)
	line := p.Line
	return &model.Source{File: p.Filename, Line: &line}
}

// stringConst resolves args[index] to a string only when it is written
// directly as a string literal. Unlike typed's stringConst (which uses
// go/types' constant folding to also resolve named constants, qualified
// constants, and constant concatenation), this is deliberately narrower:
// without type information there is no reliable way to confirm an
// identifier actually refers to a constant of string type rather than, say,
// a package-level variable that merely looks like one, so those cases
// honestly fall through to the same "not a string literal" diagnostic path
// every other unresolved path already uses.
func (d *syntaxDiscoverer) stringConst(args []ast.Expr, index int) (string, bool) {
	if index >= len(args) {
		return "", false
	}
	lit, ok := args[index].(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	value, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false
	}
	return value, true
}

func (d *syntaxDiscoverer) stringSliceLiteral(args []ast.Expr, index int) ([]string, bool) {
	if index >= len(args) {
		return nil, false
	}
	comp, ok := args[index].(*ast.CompositeLit)
	if !ok {
		return nil, false
	}
	result := make([]string, 0, len(comp.Elts))
	for _, elt := range comp.Elts {
		s, ok := d.stringConst([]ast.Expr{elt}, 0)
		if !ok {
			return nil, false
		}
		result = append(result, s)
	}
	return result, true
}
