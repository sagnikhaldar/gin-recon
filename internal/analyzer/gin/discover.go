package gin

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"path"
	"strings"

	"github.com/sagnikhaldar/gin-recon/internal/model"
)

// Registry is one function's discovered Gin route surface. Discover returns
// one Registry per analyzed function; the caller (internal/analyzer,
// phase 3+) merges these across a package/module.
type Registry struct {
	Routes           []model.Route
	GlobalMiddleware []model.Middleware
	FallbackSurfaces []model.FallbackSurface
	Diagnostics      []model.Diagnostic
}

// groupEntry is the accumulated state for one tracked *gin.Engine or
// *gin.RouterGroup value, keyed by its types.Object identity so the same
// underlying value is recognized however it is referenced.
//
// middleware is deliberately mutated in place by Use() and copied (never
// mutated) by Group() — this mirrors gin-gonic/gin's own combineHandlers
// semantics exactly (routergroup.go): a child group snapshots its parent's
// middleware at creation time, so a later Use() on the parent does not
// retroactively affect groups already created from it, and a later Use() on
// the child does not affect the parent.
type groupEntry struct {
	isRoot     bool
	basePath   string
	middleware []callableRef
}

// callableRef pairs a resolved callable with the source location it was
// written at, deferring model.Middleware construction until the entry's
// final RegistrationScope and OrderingIndex are known (which happens only
// once, at the point a route or fallback surface is actually built).
//
// source is resolved eagerly, at the point the ref is created, rather than
// stored as a bare token.Pos to be resolved later: a token.Pos is only
// meaningful relative to the exact *token.FileSet it came from, and
// tryFollowRegistrarCall's whole purpose is to accumulate callableRefs
// across function bodies that can belong to different files and packages —
// each with their own FileSet. Resolving lazily against whatever FileSet
// happens to be "current" at build time would silently attribute the wrong
// file/line to any middleware carried over from an earlier function.
type callableRef struct {
	callable
	source *model.Source
	scope  model.RegistrationScope
}

// FuncInfo is everything Discover needs to walk into a registrar function it
// finds by call reference rather than by direct entry — its syntax plus the
// type-checking results and file set for whichever package declared it,
// which may differ from the entry function's own package. The caller
// (internal/analyzer's orchestration layer) builds this index once across
// every loaded package before calling Discover, since only the orchestration
// layer has visibility across package boundaries.
type FuncInfo struct {
	Decl *ast.FuncDecl
	Info *types.Info
	Fset *token.FileSet
}

// maxRegistrarDepth bounds how many nested registrar calls Discover follows.
// Unlike ADR 0008's same-function-only boundary for enforcement-shape
// analysis — deliberately narrow because a false "confirmed-shape" is the
// worse failure there — route discovery follows the opposite risk
// asymmetry: docs/threat-model.md names a hidden route as this project's
// single most damaging failure mode, so registrar-following favors recall
// and is bounded only by depth and cycle detection, not by a package
// boundary.
const maxRegistrarDepth = 32

// discoverer walks a Gin engine's construction and every registrar function
// reachable from it (see tryFollowRegistrarCall), bounded by maxRegistrarDepth
// and cycle detection via visiting. Registrar functions whose body is not
// available (external package without source, or unresolved callee) produce
// a diagnostic rather than a silently incomplete registry.
type discoverer struct {
	fset      *token.FileSet
	info      *types.Info
	api       *API
	funcIndex map[*types.Func]FuncInfo
	states    map[types.Object]*groupEntry
	depth     int
	visiting  map[*types.Func]bool

	routes           []model.Route
	fallbacks        []pendingFallback
	globalMiddleware map[types.Object]struct{} // root engine objects seen, for GlobalMiddleware output
	diagnostics      []model.Diagnostic

	// sliceLiterals records same-function local variables bound to a
	// literal slice composite ("handlers := []gin.HandlerFunc{A, B}"), so a
	// later "...handlers" spread argument at a route-registration call can
	// be resolved to A and B individually instead of being diagnosed as
	// unresolved — see resolveHandlerSlice.
	sliceLiterals map[types.Object][]ast.Expr

	// funcLiterals records same-function local variables bound to an
	// anonymous function literal ("registerRoutes := func(r *gin.Engine)
	// {...}"), so a later call through that variable name can be followed
	// as a registrar exactly like a named function/method value — see
	// tryFollowRegistrarCall's function-literal branch. visitingLit is
	// funcLiterals' own cycle-detection set, parallel to visiting (which is
	// keyed by *types.Func and cannot key a FuncLit, which has no *types.Func
	// of its own).
	funcLiterals map[types.Object]*ast.FuncLit
	visitingLit  map[*ast.FuncLit]bool

	// structLiteralParams records, for a callee parameter bound at some
	// registrar call site to a struct composite-literal argument (e.g.
	// "registerRoute(group, Route{Type: PATCH, Path: "/x"}, ...)" binds the
	// callee's "route Route" parameter here), that literal's own resolved
	// string-constant field values — keyed by field name, e.g. {"Type":
	// "PATCH", "Path": "/x"}. resolveStringExpr consults this so a later
	// "route.Type"/"route.Path" read inside the callee's body (which cannot
	// itself be constant-folded, since route is a parameter, not a literal
	// at that point) resolves through to the value actually passed at this
	// specific call site — the common "generic route-descriptor registrar
	// helper called from many sites with a literal Route{...} each time"
	// shape. Field values are resolved eagerly at the call site, against
	// the caller's own *types.Info, because by the time the callee's body
	// is walked d.info has already been swapped to the callee's package.
	structLiteralParams map[types.Object]map[string]string

	// pseudoConsts resolves a package-level `var` with a single string
	// literal initializer, confirmed never reassigned anywhere in its own
	// package, to that initializer's value — see Discover's doc comment
	// and internal/analyzer's buildPseudoConstIndex, its only producer.
	pseudoConsts map[*types.Var]string
}

type pendingFallback struct {
	kind     model.FallbackSurfaceKind
	engine   types.Object
	handlers []callableRef
	source   *model.Source // resolved eagerly; see callableRef's doc comment for why
}

// Discover analyzes a function body for Gin engine/group construction,
// middleware registration, and route registration, using api to recognize
// Gin's own types by identity rather than name. fset and info must be the
// same FileSet/Info fn's enclosing package was type-checked with.
//
// When Discover encounters a call passing a tracked router value to a
// function that is not itself a recognized Gin method — the "func
// registerRoutes(r *gin.Engine) { ... }" pattern — it looks the callee up in
// funcIndex and, if found, continues discovery inside it with the matching
// parameter bound to the same accumulated state, so routes registered
// through a registrar function are not silently missed. Pass nil or an
// empty map to disable this (every such call then produces a
// "gin-unresolved-registrar" diagnostic instead).
//
// pseudoConsts resolves a package-level `var` reference (e.g. "var GET =
// \"GET\""; a real const is already constant-folded by go/types without any
// help from this) to its declared string value, but only for a var the
// caller has already confirmed is never reassigned anywhere in its own
// package — see internal/analyzer's buildPseudoConstIndex, the only
// intended producer of this map. Pass nil or an empty map to disable this
// resolution entirely.
func Discover(fset *token.FileSet, info *types.Info, api *API, fn *ast.FuncDecl, funcIndex map[*types.Func]FuncInfo, pseudoConsts map[*types.Var]string) *Registry {
	d := &discoverer{
		fset:                fset,
		info:                info,
		api:                 api,
		funcIndex:           funcIndex,
		pseudoConsts:        pseudoConsts,
		states:              map[types.Object]*groupEntry{},
		visiting:            map[*types.Func]bool{},
		globalMiddleware:    map[types.Object]struct{}{},
		sliceLiterals:       map[types.Object][]ast.Expr{},
		funcLiterals:        map[types.Object]*ast.FuncLit{},
		visitingLit:         map[*ast.FuncLit]bool{},
		structLiteralParams: map[types.Object]map[string]string{},
	}
	if fn.Body != nil {
		d.walkStmts(fn.Body.List)
	}
	return d.finish()
}

func (d *discoverer) walkStmts(stmts []ast.Stmt) {
	for _, stmt := range stmts {
		d.walkStmt(stmt)
	}
}

// walkStmt descends into nested blocks (if/for/range/switch) so registration
// calls are not silently missed just because they are conditionally or
// repeatedly reached — see the discoverer doc comment on scope. It does not
// track branch/loop identity, so two registrations of the same route on
// different branches are both recorded as discovered (a coverage
// completeness property), not deduplicated or confidence-scored by
// reachability, which is a refinement left for later.
func (d *discoverer) walkStmt(stmt ast.Stmt) {
	switch s := stmt.(type) {
	case *ast.AssignStmt:
		d.handleAssign(s)
	case *ast.ExprStmt:
		d.handleExprStmt(s)
	case *ast.BlockStmt:
		d.walkStmts(s.List)
	case *ast.IfStmt:
		// s.Init runs the extremely common "if err := registrar(r); err !=
		// nil { ... }" idiom for an error-returning registrar call — without
		// visiting it, that call (and every route it registers) would be
		// silently invisible, identical in effect to the untracked-router-
		// value gap diagnoseUntrackedRouterValue exists to catch, but for a
		// pattern common enough to have caused a real 0-routes false
		// negative on a production Gin service during accuracy testing.
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
	case *ast.ReturnStmt:
		// "return registrar(r)" delegates further exactly like a bare
		// registrar call or an if-err-wrapped one — the returned value
		// itself is not tracked (that would require the separate,
		// out-of-scope factory-return-value case diagnoseUntrackedRouterValue
		// already documents), but a tracked router value passed as an
		// argument to the returned call must still be followed.
		for _, result := range s.Results {
			if call, ok := result.(*ast.CallExpr); ok {
				d.tryFollowRegistrarCall(call)
			}
		}
	}
}

// handleAssign processes each RHS call in an assignment. An engine/group-
// producing call ("r := gin.New()", "api := r.Group(...)") binds its result
// to the LHS identifier so later statements can look it up by that name. Any
// other call falls through to tryFollowRegistrarCall — an assignment is not
// only how an engine/group value comes into existence, it is also the
// idiomatic shape of a registrar call whose only return value is an error
// ("err := initializeRouter(r, ...)"), which must be followed exactly like
// the bare-statement form handleExprStmt already handles, or every route it
// registers is silently invisible. The LHS identifier is only required for
// binding an engine/group result, not for reaching the RHS call itself, so a
// blank identifier ("_ = initializeRouter(r, ...)") still gets followed.
func (d *discoverer) handleAssign(s *ast.AssignStmt) {
	for i, rhs := range s.Rhs {
		var lhsIdent *ast.Ident
		if i < len(s.Lhs) {
			if id, ok := s.Lhs[i].(*ast.Ident); ok && id.Name != "_" {
				lhsIdent = id
			}
		}

		if lit, ok := rhs.(*ast.CompositeLit); ok {
			d.recordSliceLiteral(lhsIdent, lit)
			continue
		}

		if lit, ok := rhs.(*ast.FuncLit); ok {
			d.recordFuncLiteral(lhsIdent, lit)
			continue
		}

		call, ok := rhs.(*ast.CallExpr)
		if !ok {
			continue
		}
		if entry, ok := d.newEngineFromCall(call); ok {
			if lhsIdent != nil {
				d.bind(lhsIdent, entry)
			}
			continue
		}
		if entry, ok := d.groupFromCall(call); ok {
			if lhsIdent != nil {
				d.bind(lhsIdent, entry)
			}
			continue
		}
		if entry, ok := d.resolveEngineFactoryCall(call); ok {
			if lhsIdent != nil {
				d.bind(lhsIdent, entry)
				if entry.isRoot && len(entry.middleware) > 0 {
					// The factory already called Use() on this engine
					// before returning it — mirror what a direct Use() call
					// at this scope would do, so finish() still emits it as
					// GlobalMiddleware at the caller, not only as evidence
					// on whatever routes get registered here.
					if obj := d.info.Defs[lhsIdent]; obj != nil {
						d.globalMiddleware[obj] = struct{}{}
					} else if obj := d.info.Uses[lhsIdent]; obj != nil {
						d.globalMiddleware[obj] = struct{}{}
					}
				}
			}
			continue
		}
		d.tryFollowRegistrarCall(call)
	}
}

// resolveEngineFactoryCall resolves a call to a wrapping factory function —
// "func NewEngine() *gin.Engine { r := gin.New(); ...; return r }" — by
// running a bounded sub-walk of the factory's own body and extracting the
// groupEntry corresponding to whatever it returns, so "r := NewEngine();
// r.GET(...)" discovers exactly as if NewEngine's body had been inlined.
// This is deliberately a different operation from tryFollowRegistrarCall:
// a registrar call receives an existing tracked value and mutates it in
// place, while a factory call produces a brand new one this discoverer has
// never seen before this call.
//
// It returns ok=false — leaving the existing gin-untracked-router-value
// diagnostic path to fire at the point of use, exactly as before this
// resolution existed — whenever the callee is not itself a real engine
// constructor, its source is unavailable, depth/cycle bounds are reached,
// or its return statements disagree about which tracked value they return
// (this analyzer never guesses which of two different engines a caller
// actually receives).
func (d *discoverer) resolveEngineFactoryCall(call *ast.CallExpr) (*groupEntry, bool) {
	calleeFunc := d.resolveCalleeFunc(call.Fun)
	if calleeFunc == nil {
		return nil, false
	}
	if d.depth >= maxRegistrarDepth {
		d.diagnose("gin-registrar-depth-exceeded", "engine-factory call chain exceeds the analyzer's depth limit; the returned engine could not be resolved", call.Pos())
		return nil, false
	}
	if d.visiting[calleeFunc] {
		d.diagnose("gin-recursive-registrar", "recursive engine-factory call detected; not followed further to avoid infinite recursion", call.Pos())
		return nil, false
	}
	fi, ok := d.funcIndex[calleeFunc]
	if !ok || fi.Decl == nil || fi.Decl.Body == nil {
		return nil, false // external/unavailable source — the caller's own diagnostic path handles this
	}
	if !HasEngineConstruction(fi.Info, fi.Decl) {
		return nil, false // not an engine-constructing function at all
	}

	sub := &discoverer{
		fset:                fi.Fset,
		info:                fi.Info,
		api:                 d.api,
		funcIndex:           d.funcIndex,
		pseudoConsts:        d.pseudoConsts,
		states:              map[types.Object]*groupEntry{},
		visiting:            d.visiting, // shared by reference: cycle detection must see across factory/registrar calls alike
		globalMiddleware:    map[types.Object]struct{}{},
		sliceLiterals:       map[types.Object][]ast.Expr{},
		funcLiterals:        map[types.Object]*ast.FuncLit{},
		visitingLit:         map[*ast.FuncLit]bool{},
		structLiteralParams: map[types.Object]map[string]string{},
		depth:               d.depth + 1,
	}
	sub.visiting[calleeFunc] = true
	sub.walkStmts(fi.Decl.Body.List)
	sub.visiting[calleeFunc] = false

	entry, ok := sub.returnedEntry(fi.Decl.Body)
	if !ok {
		return nil, false
	}

	// The factory may itself have registered real routes/fallbacks before
	// returning (e.g. it sets up a health check on the engine it builds) —
	// those must not be lost just because this call is being resolved as a
	// factory rather than inlined source. Every object key below is a
	// genuine *types.Object from the type-checked program, unique
	// regardless of which Info map it was looked up through, so merging
	// sub's bookkeeping directly into d's is safe even across a package
	// boundary.
	d.routes = append(d.routes, sub.routes...)
	d.fallbacks = append(d.fallbacks, sub.fallbacks...)
	d.diagnostics = append(d.diagnostics, sub.diagnostics...)
	for obj := range sub.states {
		d.states[obj] = sub.states[obj]
	}
	for obj := range sub.globalMiddleware {
		d.globalMiddleware[obj] = struct{}{}
	}

	return entry, true
}

// returnedEntry scans body (including nested blocks) for every return
// statement and resolves each one's single result expression to the
// groupEntry it refers to, requiring every resolving return to agree on
// exactly which entry that is — a return that resolves to nothing (an
// early "return nil" on an error path, say) is not itself a disagreement,
// only two DIFFERENT resolved entries are.
func (d *discoverer) returnedEntry(body *ast.BlockStmt) (*groupEntry, bool) {
	var found *groupEntry
	ambiguous := false
	ast.Inspect(body, func(n ast.Node) bool {
		ret, ok := n.(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			return true
		}
		entry, ok := d.resolveReturnedEngineExpr(ret.Results[0])
		if !ok {
			return true
		}
		if found != nil && found != entry {
			ambiguous = true
			return true
		}
		found = entry
		return true
	})
	if ambiguous || found == nil {
		return nil, false
	}
	return found, true
}

// resolveReturnedEngineExpr resolves a single return-statement result
// expression to a groupEntry: either a tracked identifier ("return r") or a
// direct engine/group-producing call written inline ("return gin.New()").
func (d *discoverer) resolveReturnedEngineExpr(expr ast.Expr) (*groupEntry, bool) {
	switch e := expr.(type) {
	case *ast.Ident:
		obj := d.info.Uses[e]
		if obj == nil {
			return nil, false
		}
		entry, ok := d.states[obj]
		return entry, ok
	case *ast.CallExpr:
		if entry, ok := d.newEngineFromCall(e); ok {
			return entry, true
		}
		if entry, ok := d.groupFromCall(e); ok {
			return entry, true
		}
	}
	return nil, false
}

// recordSliceLiteral records lhsIdent's binding to lit's elements when lit
// is a slice composite literal ("handlers := []gin.HandlerFunc{A, B}") —
// see sliceLiterals' field doc comment and resolveHandlerSlice, which is
// the only consumer. Only a genuine slice ([]T{...}, ArrayType.Len == nil)
// is recorded; a fixed-size array literal can never be the target of a
// "..." spread in valid Go, so there is nothing for resolveHandlerSlice to
// ever look up for one.
func (d *discoverer) recordSliceLiteral(lhsIdent *ast.Ident, lit *ast.CompositeLit) {
	if lhsIdent == nil {
		return
	}
	arrType, ok := lit.Type.(*ast.ArrayType)
	if !ok || arrType.Len != nil {
		return
	}
	obj := d.info.Defs[lhsIdent]
	if obj == nil {
		obj = d.info.Uses[lhsIdent]
	}
	if obj == nil {
		return
	}
	d.sliceLiterals[obj] = lit.Elts
}

// recordFuncLiteral records lhsIdent's binding to an anonymous function
// literal ("registerRoutes := func(r *gin.Engine) {...}"), so a later call
// through that variable name can be followed as a registrar exactly like a
// named function — see tryFollowRegistrarCall's function-literal branch.
func (d *discoverer) recordFuncLiteral(lhsIdent *ast.Ident, lit *ast.FuncLit) {
	if lhsIdent == nil {
		return
	}
	obj := d.info.Defs[lhsIdent]
	if obj == nil {
		obj = d.info.Uses[lhsIdent]
	}
	if obj == nil {
		return
	}
	d.funcLiterals[obj] = lit
}

// resolveHandlerSlice resolves a "...handlers"-spread route-registration
// argument (Go's variadic-call syntax guarantees exactly one expression in
// args when call.Ellipsis is set) to its individual elements — either an
// inline composite literal at the call site
// ("r.GET(path, []gin.HandlerFunc{A, B}...)") or a same-function local
// variable previously bound to one via recordSliceLiteral
// ("handlers := []gin.HandlerFunc{A, B}; r.GET(path, handlers...)"). A
// keyed element (a sparse or reordering composite like "{0: A, 2: B}") is
// deliberately not resolved: middleware/handler order is registration
// order, and a keyed literal's positional meaning cannot be trusted the
// same way an ordinary unkeyed one can. Anything else — a function call's
// return value, a parameter, append()'s result, a slice copied from
// another via "existing..." inside the literal — is not resolved either;
// this analyzer never fabricates a handler list from anything but a
// literal it can see in full.
func (d *discoverer) resolveHandlerSlice(args []ast.Expr) ([]ast.Expr, bool) {
	if len(args) != 1 {
		return nil, false
	}
	var elts []ast.Expr
	switch e := args[0].(type) {
	case *ast.CompositeLit:
		elts = e.Elts
	case *ast.Ident:
		obj := d.info.Uses[e]
		if obj == nil {
			return nil, false
		}
		found, ok := d.sliceLiterals[obj]
		if !ok {
			return nil, false
		}
		elts = found
	default:
		return nil, false
	}
	for _, elt := range elts {
		if _, keyed := elt.(*ast.KeyValueExpr); keyed {
			return nil, false
		}
	}
	return elts, true
}

func (d *discoverer) bind(ident *ast.Ident, entry *groupEntry) {
	obj := d.info.Defs[ident]
	if obj == nil {
		obj = d.info.Uses[ident]
	}
	if obj == nil {
		return
	}
	d.states[obj] = entry
}

// newEngineFromCall recognizes gin.New() and gin.Default() specifically
// (identified by package path, not by the local import alias) as the only
// ways a new root engine comes into existence.
func (d *discoverer) newEngineFromCall(call *ast.CallExpr) (*groupEntry, bool) {
	if !isNewEngineCall(d.info, call) {
		return nil, false
	}
	return &groupEntry{isRoot: true, basePath: "/"}, true
}

// isNewEngineCall recognizes gin.New()/gin.Default() specifically by package
// path, not by local import alias. Factored out of newEngineFromCall so
// HasEngineConstruction (used by the orchestration layer to decide which
// functions are legitimate Discover entry points at all) shares the exact
// same recognition rule rather than a second, potentially-drifting copy.
func isNewEngineCall(info *types.Info, call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkgIdent, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	pkgName, ok := info.Uses[pkgIdent].(*types.PkgName)
	if !ok || pkgName.Imported().Path() != PackagePath {
		return false
	}
	return sel.Sel.Name == "New" || sel.Sel.Name == "Default"
}

// HasEngineConstruction reports whether fn's body calls gin.New()/
// gin.Default() anywhere (not just at the top level — it may be behind a
// conditional). The orchestration layer (internal/analyzer) uses this to
// decide which functions are legitimate top-level Discover entry points: a
// function that never constructs an engine itself can only ever be reached
// through registrar-following from a real entry point, and analyzing it
// standalone would see its router-typed parameter as untracked — identical
// in shape to the genuine "wrapping factory function" case
// diagnoseUntrackedRouterValue exists to catch — producing a spurious
// diagnostic for every route the function legitimately registers once
// reached the right way.
func HasEngineConstruction(info *types.Info, fn *ast.FuncDecl) bool {
	if fn.Body == nil {
		return false
	}
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if found {
			return false
		}
		if call, ok := n.(*ast.CallExpr); ok && isNewEngineCall(info, call) {
			found = true
			return false
		}
		return true
	})
	return found
}

// groupFromCall recognizes receiver.Group(path, middleware...) where
// receiver is already a tracked engine/group value.
func (d *discoverer) groupFromCall(call *ast.CallExpr) (*groupEntry, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Group" {
		return nil, false
	}
	parent, ok := d.trackedReceiver(sel.X)
	if !ok {
		return nil, false
	}
	relPath, ok := d.stringConst(call.Args, 0)
	if !ok {
		d.diagnose("gin-unresolved-path", "Group() path is not a string literal; group and its routes are not inventoried", call.Pos())
		return nil, false
	}
	child := &groupEntry{
		isRoot:     false,
		basePath:   JoinPaths(parent.basePath, relPath),
		middleware: append([]callableRef{}, parent.middleware...),
	}
	for _, arg := range call.Args[1:] {
		child.middleware = append(child.middleware, callableRef{
			callable: resolveMiddlewareCallable(d.info, arg),
			source:   d.sourceOf(arg.Pos()),
			scope:    model.ScopeGroup,
		})
	}
	return child, true
}

// trackedReceiver resolves expr (the X in X.Method(...)) to its groupEntry,
// if expr both has Gin router type and was previously bound by an assignment
// this discoverer already saw.
func (d *discoverer) trackedReceiver(expr ast.Expr) (*groupEntry, bool) {
	ident, ok := expr.(*ast.Ident)
	if !ok {
		return nil, false
	}
	obj := d.info.Uses[ident]
	if obj == nil {
		return nil, false
	}
	entry, ok := d.states[obj]
	return entry, ok
}

func (d *discoverer) handleExprStmt(s *ast.ExprStmt) {
	call, ok := s.X.(*ast.CallExpr)
	if !ok {
		return
	}
	if d.tryHandleGinMethodCall(call) {
		return
	}
	d.tryFollowRegistrarCall(call)
}

// tryHandleGinMethodCall handles the "X.Method(...)" shape where X is a
// tracked router value. It returns true whenever the call has that shape at
// all — including a method name it does not specifically process (e.g. a
// phase-4 concern like SetTrustedProxies) — so tryFollowRegistrarCall is
// only ever reached for calls that are not a tracked-receiver method call in
// the first place, such as a plain registrar function call.
func (d *discoverer) tryHandleGinMethodCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	obj := d.info.Uses[ident]
	if obj == nil {
		return false
	}
	entry, tracked := d.states[obj]
	if !tracked {
		d.diagnoseUntrackedRouterValue(ident, sel)
		return false
	}

	switch sel.Sel.Name {
	case "Use":
		scope := model.ScopeGroup
		if entry.isRoot {
			scope = model.ScopeGlobal
			d.globalMiddleware[obj] = struct{}{}
		}
		for _, arg := range call.Args {
			entry.middleware = append(entry.middleware, callableRef{
				callable: resolveMiddlewareCallable(d.info, arg),
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
		d.registerFallback(model.FallbackNoRoute, entry, obj, call)

	case "NoMethod":
		d.registerFallback(model.FallbackNoMethod, entry, obj, call)
	}
	return true
}

// routeRelevantMethodNames are the method names diagnoseUntrackedRouterValue
// watches for — restricting the check to these (rather than every method
// call on a router-typed value) avoids noise from calls this analyzer has no
// reason to care about, like Routes() or SetTrustedProxies().
var routeRelevantMethodNames = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true, "HEAD": true, "OPTIONS": true,
	"Handle": true, "Any": true, "Match": true, "Use": true, "Group": true,
	"Static": true, "StaticFile": true, "StaticFS": true, "StaticFileFS": true,
	"NoRoute": true, "NoMethod": true,
}

// diagnoseUntrackedRouterValue closes a visibility gap distinct from
// tryFollowRegistrarCall's: a *gin.Engine/*gin.RouterGroup value whose origin
// this analyzer never recognized is invisible to bind(), so route-
// registration calls on it would otherwise be silently skipped with no
// signal at all. A wrapping factory function like "func NewEngine() *gin.Engine
// { r := gin.New(); ...; return r }" is the most common such case, and
// handleAssign's resolveEngineFactoryCall now resolves it whenever every one
// of the factory's return statements agrees on which tracked value comes
// back — so this diagnostic path is reached only for what genuinely remains
// unresolvable: a factory whose returns disagree (this analyzer never
// guesses which of two different engines a caller actually receives), one
// whose source is unavailable, or any other origin resolveEngineFactoryCall
// does not cover. Either way, this makes the gap visible instead of silent,
// which is the minimum the threat model's "no silent route loss" principle
// requires.
func (d *discoverer) diagnoseUntrackedRouterValue(ident *ast.Ident, sel *ast.SelectorExpr) {
	if !routeRelevantMethodNames[sel.Sel.Name] {
		return
	}
	if isEngine, isGroup := d.api.IsRouterValue(d.info.TypeOf(ident)); !isEngine && !isGroup {
		return
	}
	d.diagnose("gin-untracked-router-value",
		sel.Sel.Name+"() called on a *gin.Engine/*gin.RouterGroup value whose origin this analyzer could not trace to gin.New()/gin.Default() (commonly a wrapping factory function); routes registered through it are not inventoried",
		sel.Sel.Pos())
}

// registrarBinding pairs one call argument position with the groupEntry it
// carries, for tryFollowRegistrarCall and its function-literal counterpart
// followFuncLitRegistrar — a package-level type only because Go has no way
// to declare a local type and reuse it across two separate function bodies.
type registrarBinding struct {
	argIndex int
	entry    *groupEntry
}

// tryFollowRegistrarCall handles a call that is not itself a tracked-router
// method call but passes one or more tracked router values as arguments —
// the "registerRoutes(r)" or "handler.RegisterRoutes(r)" pattern. It resolves
// the callee, binds each matching parameter to the same groupEntry as the
// caller's argument (so Use()/route calls inside the callee accumulate into
// the identical state), and recurses. Anything it cannot resolve — an
// external function with no available source, a call depth beyond
// maxRegistrarDepth, a recursive registrar cycle — produces a diagnostic
// instead of silently dropping whatever that call might have registered.
//
// The callee may be a named function/method value (resolveCalleeFunc) or a
// function literal (resolveCalleeFuncLit) — either an inline IIFE or a
// same-function local variable bound to one via recordFuncLiteral. Both are
// registrar-following in the same sense; only how the callee's own AST body
// is located differs.
func (d *discoverer) tryFollowRegistrarCall(call *ast.CallExpr) {
	var bindings []registrarBinding
	for i, arg := range call.Args {
		ident, ok := arg.(*ast.Ident)
		if !ok {
			continue
		}
		obj := d.info.Uses[ident]
		if obj == nil {
			continue
		}
		if entry, ok := d.states[obj]; ok {
			bindings = append(bindings, registrarBinding{argIndex: i, entry: entry})
		}
	}
	if len(bindings) == 0 {
		return // an ordinary call unrelated to any tracked router value.
	}

	// A struct composite-literal argument at this same call site (e.g. the
	// "registerRoute(group, Route{Type: PATCH, Path: "/x"}, ...)" shape) is
	// resolved to its string-constant field values now, against the
	// caller's own d.info — see structLiteralParams' doc comment for why
	// this cannot be deferred to when the callee's body is walked.
	var structArgs []structFieldBinding
	for i, arg := range call.Args {
		lit, ok := arg.(*ast.CompositeLit)
		if !ok {
			continue
		}
		if fields := d.resolveCompositeLitStringFields(lit); len(fields) > 0 {
			structArgs = append(structArgs, structFieldBinding{argIndex: i, fields: fields})
		}
	}

	if lit := d.resolveCalleeFuncLit(call.Fun); lit != nil {
		d.followFuncLitRegistrar(lit, bindings, call)
		return
	}

	calleeFunc := d.resolveCalleeFunc(call.Fun)
	if calleeFunc == nil {
		d.diagnose("gin-unresolved-registrar", "a router value was passed to a call this analyzer could not resolve to a function; routes it may register are not inventoried", call.Pos())
		return
	}
	if d.depth >= maxRegistrarDepth {
		d.diagnose("gin-registrar-depth-exceeded", "registrar call chain exceeds the analyzer's depth limit; routes registered beyond this point are not inventoried", call.Pos())
		return
	}
	if d.visiting[calleeFunc] {
		d.diagnose("gin-recursive-registrar", "recursive registrar call detected; not followed further to avoid infinite recursion", call.Pos())
		return
	}
	fi, ok := d.funcIndex[calleeFunc]
	if !ok || fi.Decl == nil || fi.Decl.Body == nil || fi.Decl.Type.Params == nil {
		d.diagnose("gin-unresolved-registrar", unresolvedRegistrarMessage(calleeFunc), call.Pos())
		return
	}

	boundAny := false
	for _, b := range bindings {
		paramIdent := paramIdentAt(fi.Decl.Type.Params, b.argIndex)
		if paramIdent == nil {
			continue
		}
		paramObj := fi.Info.Defs[paramIdent]
		if paramObj == nil {
			continue
		}
		d.states[paramObj] = b.entry
		boundAny = true
	}
	if !boundAny {
		d.diagnose("gin-unresolved-registrar", "could not match the passed router value to a parameter in the callee's signature; routes it may register are not inventoried", call.Pos())
		return
	}
	for _, sb := range structArgs {
		paramIdent := paramIdentAt(fi.Decl.Type.Params, sb.argIndex)
		if paramIdent == nil {
			continue
		}
		if paramObj := fi.Info.Defs[paramIdent]; paramObj != nil {
			d.structLiteralParams[paramObj] = sb.fields
		}
	}

	oldInfo, oldFset := d.info, d.fset
	d.info, d.fset = fi.Info, fi.Fset
	d.visiting[calleeFunc] = true
	d.depth++

	d.walkStmts(fi.Decl.Body.List)

	d.depth--
	d.visiting[calleeFunc] = false
	d.info, d.fset = oldInfo, oldFset
}

// resolveCalleeFuncLit resolves a call's callee to a function literal, when
// possible — either directly, an inline immediately-invoked function
// expression ("func(r *gin.Engine){...}(r)"), or through a same-function
// local variable previously bound to one via recordFuncLiteral
// ("registerRoutes := func(r *gin.Engine){...}; registerRoutes(r)"). This is
// checked before resolveCalleeFunc in tryFollowRegistrarCall because a
// function literal has no *types.Func of its own for resolveCalleeFunc to
// find — the two are mutually exclusive shapes for the same callee
// expression, never a fallback order that matters for correctness.
func (d *discoverer) resolveCalleeFuncLit(fun ast.Expr) *ast.FuncLit {
	switch f := fun.(type) {
	case *ast.FuncLit:
		return f
	case *ast.Ident:
		if obj := d.info.Uses[f]; obj != nil {
			return d.funcLiterals[obj]
		}
	}
	return nil
}

// followFuncLitRegistrar mirrors tryFollowRegistrarCall's named-function
// path (parameter binding, depth bound, cycle detection) for a callee
// resolved to a function literal instead of a *types.Func. It needs no
// funcIndex lookup or FileSet/Info swap: a function literal is type-checked
// as part of the exact same enclosing file this walk is already inside, so
// d.info/d.fset already apply to it directly, unlike a named function that
// may live in another file or package entirely.
func (d *discoverer) followFuncLitRegistrar(lit *ast.FuncLit, bindings []registrarBinding, call *ast.CallExpr) {
	if lit.Body == nil || lit.Type.Params == nil {
		d.diagnose("gin-unresolved-registrar", "registrar function literal has no resolvable body or parameter list; routes it may register are not inventoried", call.Pos())
		return
	}
	if d.depth >= maxRegistrarDepth {
		d.diagnose("gin-registrar-depth-exceeded", "registrar call chain exceeds the analyzer's depth limit; routes registered beyond this point are not inventoried", call.Pos())
		return
	}
	if d.visitingLit[lit] {
		d.diagnose("gin-recursive-registrar", "recursive registrar call detected; not followed further to avoid infinite recursion", call.Pos())
		return
	}

	boundAny := false
	for _, b := range bindings {
		paramIdent := paramIdentAt(lit.Type.Params, b.argIndex)
		if paramIdent == nil {
			continue
		}
		paramObj := d.info.Defs[paramIdent]
		if paramObj == nil {
			continue
		}
		d.states[paramObj] = b.entry
		boundAny = true
	}
	if !boundAny {
		d.diagnose("gin-unresolved-registrar", "could not match the passed router value to a parameter in the callee's signature; routes it may register are not inventoried", call.Pos())
		return
	}

	d.visitingLit[lit] = true
	d.depth++

	d.walkStmts(lit.Body.List)

	d.depth--
	d.visitingLit[lit] = false
}

// unresolvedRegistrarMessage names the specific external symbol a registrar
// call could not be followed into, when resolveCalleeFunc did resolve it to
// a real *types.Func just not one with source in this scan's own loaded
// packages — almost always a dependency module (even a same-organization
// one) rather than the scanned target's own code. Registrar-following is
// deliberately bounded to the target module's own source (see buildFuncIndex's
// doc comment in internal/analyzer): naming the symbol here, rather than a
// generic "external package" message, is what makes that boundary
// actionable — a reviewer can immediately tell which other repository, if
// any, also needs to be scanned to see the routes this call may register,
// without gin-recon itself ever having to load or trust that module's code.
func unresolvedRegistrarMessage(calleeFunc *types.Func) string {
	if isInterfaceMethod(calleeFunc) {
		// A call through an interface-typed value resolves to the
		// interface's own abstract method declaration, which has no
		// *ast.FuncDecl body anywhere — the concrete implementation (e.g.
		// via a factory returning the interface) cannot be statically
		// determined without a form of interface devirtualization this
		// analyzer does not perform. This is a fundamentally different
		// cause from a genuine cross-module dependency and must not be
		// described as one, even though both hit the same "not found in
		// funcIndex" code path. funcCanonicalSymbol does not format an
		// interface receiver at all (by design — see its own doc comment's
		// pointer/named-only cases), so the symbol is built directly here.
		name := calleeFunc.Name()
		if pkg := calleeFunc.Pkg(); pkg != nil {
			name = pkg.Path() + "." + name
		}
		return "registrar method " + name + " is declared on an interface; the concrete implementation actually used at this call site cannot be determined statically, so routes it may register are not inventoried"
	}
	sym := funcCanonicalSymbol(calleeFunc)
	if sym == "" {
		return "registrar function source is not available to this analysis (external package or missing syntax); routes it may register are not inventoried"
	}
	return "registrar function " + sym + " lives outside the packages loaded for this scan (likely a dependency module, even if same-organization, unless analysis.followModules names it) and was not followed; routes it may register are not inventoried here"
}

// isInterfaceMethod reports whether fn is an interface method declaration
// (as opposed to a concrete function or method with a real receiver type) —
// see unresolvedRegistrarMessage's doc comment for why this distinction
// changes what the diagnostic should say.
func isInterfaceMethod(fn *types.Func) bool {
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return false
	}
	_, isInterface := sig.Recv().Type().Underlying().(*types.Interface)
	return isInterface
}

// resolveCalleeFunc resolves a call expression's callee to the *types.Func
// it refers to, covering a bare function reference (registerRoutes(r)), a
// package-qualified function (routes.Register(r)), and a method value called
// directly (handler.RegisterRoutes(r)). It does not resolve a callee reached
// through a variable of function type bound to anything other than a
// literal it can see in full (resolveCalleeFuncLit covers that case
// separately) or any other indirection — that stays an unresolved registrar
// call, diagnosed rather than guessed at.
func (d *discoverer) resolveCalleeFunc(fun ast.Expr) *types.Func {
	return resolveCalleeFuncFromExpr(d.info, fun)
}

// ResolveCalleeFunc is the exported form of resolveCalleeFuncFromExpr, for
// callers outside this package (internal/analyzer's whole-module
// "is this function ever called anywhere in the scanned module" pass, which
// DetectLibraryEntryPoint's diagnostic depends on to avoid firing on a
// library entry point that registrar-following already resolves correctly
// via some other call site).
func ResolveCalleeFunc(info *types.Info, fun ast.Expr) *types.Func {
	return resolveCalleeFuncFromExpr(info, fun)
}

// resolveCalleeFuncFromExpr resolves a call expression's callee to the
// *types.Func it refers to — a bare function reference, a package-qualified
// function, or a method value called directly. Shared between Discover's
// registrar-following and enforcement.go's factory-closure resolution, which
// both need to answer exactly the same question against a plain
// *types.Info without any discoverer state.
func resolveCalleeFuncFromExpr(info *types.Info, fun ast.Expr) *types.Func {
	switch f := fun.(type) {
	case *ast.Ident:
		if fn, ok := info.Uses[f].(*types.Func); ok {
			return fn
		}
	case *ast.SelectorExpr:
		if fn, ok := info.Uses[f.Sel].(*types.Func); ok {
			return fn
		}
		if selection, ok := info.Selections[f]; ok {
			if fn, ok := selection.Obj().(*types.Func); ok {
				return fn
			}
		}
	}
	return nil
}

// paramIdentAt flattens a parameter list's grouped-name syntax
// ("func f(a, b int, c string)") and returns the identifier at the given
// zero-based argument position, or nil if unnamed (an underscore or omitted
// name) or out of range.
func paramIdentAt(params *ast.FieldList, argIndex int) *ast.Ident {
	i := 0
	for _, field := range params.List {
		names := field.Names
		if len(names) == 0 {
			// An unnamed parameter still occupies one position.
			if i == argIndex {
				return nil
			}
			i++
			continue
		}
		for _, name := range names {
			if i == argIndex {
				if name.Name == "_" {
					return nil
				}
				return name
			}
			i++
		}
	}
	return nil
}

// anyMethods mirrors gin-gonic/gin's own routergroup.go anyMethods exactly
// (verified against the vendored gin source, not assumed): Any() expands to
// all nine of these, including CONNECT and TRACE. The previous seven-method
// list here silently under-reported Any() routes — a route registered via
// Any() genuinely responds to CONNECT and TRACE at the Gin level, so
// omitting them was a real recall gap, not a deliberate scoping choice.
// format.OpenAPI already handles what happens to each of these once
// discovered: CONNECT has no OpenAPI 3.1 Path Item field and is diagnosed
// non-representable; TRACE does and is emitted normally.
var anyMethods = []string{
	"GET", "POST", "PUT", "PATCH", "HEAD", "OPTIONS", "DELETE", "CONNECT", "TRACE",
}

func (d *discoverer) registerRoute(entry *groupEntry, method string, call *ast.CallExpr, pathArgIndex int, kind model.RegistrationKind) {
	relPath, ok := d.stringConst(call.Args, pathArgIndex)
	if !ok {
		d.diagnose("gin-unresolved-path", method+" path is not a string literal; route not inventoried", call.Pos())
		return
	}
	absolutePath := JoinPaths(entry.basePath, relPath)

	handlerArgs := call.Args[pathArgIndex+1:]
	if call.Ellipsis != token.NoPos {
		resolved, ok := d.resolveHandlerSlice(handlerArgs)
		if !ok {
			d.diagnose("gin-unresolved-handlers", method+" "+absolutePath+" passes handlers via a spread slice that could not be resolved to a literal list; individual handlers not inventoried", call.Pos())
			return
		}
		handlerArgs = resolved
	}
	if len(handlerArgs) == 0 {
		d.diagnose("gin-no-handlers", method+" "+absolutePath+" has no handler arguments", call.Pos())
		return
	}

	chain := append([]callableRef{}, entry.middleware...)
	for _, arg := range handlerArgs {
		chain = append(chain, callableRef{callable: resolveMiddlewareCallable(d.info, arg), source: d.sourceOf(arg.Pos()), scope: model.ScopeRoute})
	}

	route := model.Route{
		Method:             method,
		GinPath:            absolutePath,
		NormalizedPath:     normalizePath(absolutePath),
		SurfaceKind:        model.SurfaceRoute,
		RegistrationKind:   &kind,
		PathConfidence:     model.ConfidenceHigh,
		AnalysisConfidence: model.ConfidenceHigh,
		EvidenceOrigins:    []string{"ast", "types"},
	}
	route.Source = d.sourceOf(call.Pos())
	route.Middleware, route.FinalHandler = buildChain(chain)
	d.routes = append(d.routes, route)
}

func (d *discoverer) registerStatic(entry *groupEntry, method string, call *ast.CallExpr) {
	relPath, ok := d.stringConst(call.Args, 0)
	if !ok {
		d.diagnose("gin-unresolved-path", method+" path is not a string literal; route not inventoried", call.Pos())
		return
	}

	// Mirrors gin-gonic/gin@v1.10.0's own StaticFS/StaticFile: StaticFile
	// registers relPath as-is; Static/StaticFS append a "/*filepath"
	// catch-all via path.Join (relative to relPath, not yet joined to the
	// group's base path), then that whole pattern is registered as an
	// ordinary route — which is what performs the group-relative join.
	relPattern := relPath
	methods := []string{"GET", "HEAD"}
	if method != "StaticFile" && method != "StaticFileFS" {
		relPattern = path.Join(relPath, "/*filepath")
	}
	urlPattern := JoinPaths(entry.basePath, relPattern)

	for _, m := range methods {
		chain := append([]callableRef{}, entry.middleware...)
		chain = append(chain, callableRef{
			callable: callable{DisplayName: "<static-handler>", CallableKind: model.CallableUnknown, ResolutionStatus: model.Resolved},
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
			AnalysisConfidence: model.ConfidenceHigh,
			EvidenceOrigins:    []string{"ast", "types"},
		}
		route.Source = d.sourceOf(call.Pos())
		route.Middleware, route.FinalHandler = buildChain(chain)
		d.routes = append(d.routes, route)
	}
}

func (d *discoverer) registerFallback(kind model.FallbackSurfaceKind, entry *groupEntry, engineObj types.Object, call *ast.CallExpr) {
	var handlers []callableRef
	for _, arg := range call.Args {
		handlers = append(handlers, callableRef{callable: resolveMiddlewareCallable(d.info, arg), source: d.sourceOf(arg.Pos()), scope: model.ScopeRoute})
	}
	d.fallbacks = append(d.fallbacks, pendingFallback{kind: kind, engine: engineObj, handlers: handlers, source: d.sourceOf(call.Pos())})
	_ = entry // fallback middleware is resolved from the engine's FINAL state in finish(), not entry's state at call time — see pendingFallback doc.
}

// finish resolves every pending fallback surface against each engine's final
// accumulated global middleware — required because gin-gonic/gin recomputes
// NoRoute/NoMethod's combined chain on every subsequent engine.Use() call
// (gin.go's rebuild404Handlers/rebuild405Handlers), so the correct evidence
// is "global middleware at the end of registration," not "at the point
// NoRoute was called."
func (d *discoverer) finish() *Registry {
	reg := &Registry{}

	for obj := range d.globalMiddleware {
		if entry, ok := d.states[obj]; ok {
			reg.GlobalMiddleware = append(reg.GlobalMiddleware, buildMiddlewareList(entry.middleware)...)
		}
	}

	for _, pf := range d.fallbacks {
		entry, ok := d.states[pf.engine]
		if !ok {
			continue
		}
		chain := append([]callableRef{}, entry.middleware...)
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

func (d *discoverer) diagnose(code, message string, pos token.Pos) {
	d.diagnostics = append(d.diagnostics, model.Diagnostic{
		Code:     code,
		Severity: model.DiagnosticWarning,
		Message:  message,
		Source:   d.sourceOf(pos),
	})
}

func (d *discoverer) sourceOf(pos token.Pos) *model.Source {
	if pos == token.NoPos {
		return nil
	}
	p := d.fset.Position(pos)
	line := p.Line
	return &model.Source{File: p.Filename, Line: &line}
}

// buildChain combines a callableRef slice into ordered Middleware entries
// plus the final handler, per docs/report-contract.md's "the uppercase
// method plus... final handler" split: the last entry in the resolved chain
// is always the final handler, everything before it is middleware.
func buildChain(chain []callableRef) ([]model.Middleware, model.Middleware) {
	list := buildMiddlewareList(chain)
	if len(list) == 0 {
		return nil, model.Middleware{}
	}
	return list[:len(list)-1], list[len(list)-1]
}

func buildMiddlewareList(refs []callableRef) []model.Middleware {
	list := make([]model.Middleware, len(refs))
	for i, ref := range refs {
		var canonical *string
		if ref.CanonicalSymbol != "" {
			s := ref.CanonicalSymbol
			canonical = &s
		}
		list[i] = model.Middleware{
			DisplayName:       ref.DisplayName,
			CanonicalSymbol:   canonical,
			CallableKind:      ref.CallableKind,
			Source:            ref.source,
			RegistrationScope: ref.scope,
			OrderingIndex:     i,
			ResolutionStatus:  ref.ResolutionStatus,
			WrappedSymbols:    ref.WrappedSymbols,
		}
	}
	return list
}

func registrationKindPtr(k model.RegistrationKind) *model.RegistrationKind { return &k }

// stringConst resolves args[index] to a compile-time constant string using
// go/types' own constant folding (info.Types[expr].Value), not ad hoc AST
// pattern matching. This handles a bare literal ("/health"), a named
// constant (const APIPrefix = "/api"), a qualified constant from another
// package (http.MethodPost), and constant string concatenation
// (APIPrefix+"/users") uniformly — anything the Go compiler itself would
// treat as a compile-time constant. A genuinely runtime-computed path
// expression (a function parameter, a variable built from request data)
// correctly yields ok=false, since go/types only populates Value for actual
// constant expressions.
func (d *discoverer) stringConst(args []ast.Expr, index int) (string, bool) {
	if index >= len(args) {
		return "", false
	}
	return d.resolveStringExpr(args[index])
}

// resolveStringExpr resolves expr to a compile-time constant string via
// go/types' own constant folding, or — when that fails because expr is a
// "route.Field"-shaped read of a parameter bound at its call site to a
// struct composite literal (see structLiteralParams) — through that
// call-site value instead. The second case is what lets a generic,
// data-driven registrar helper ("func registerRoute(g *gin.RouterGroup,
// route Route) { g.Handle(route.Type, route.Path, ...) }", called from many
// sites each with a literal Route{...}) resolve exactly as if its body had
// been inlined at each call site, without actually inlining anything.
func (d *discoverer) resolveStringExpr(expr ast.Expr) (string, bool) {
	if tv, ok := d.info.Types[expr]; ok && tv.Value != nil && tv.Value.Kind() == constant.String {
		return constant.StringVal(tv.Value), true
	}

	// String concatenation where at least one side is not itself a
	// go/types constant (the pure-constant case is already handled above)
	// but resolves through pseudoConsts/structLiteralParams below — e.g. a
	// struct-literal-bound "route.Path" concatenated with a literal
	// prefix. Both sides must resolve; a genuinely dynamic operand (a
	// runtime option field, a request-derived value) correctly leaves the
	// whole expression unresolved rather than silently guessing a partial
	// path — a route registered under an unknown prefix is not the same
	// route as one under an empty prefix, and reporting either as if it
	// were certain would be a fabrication this analyzer must not make.
	if bin, ok := expr.(*ast.BinaryExpr); ok && bin.Op == token.ADD {
		left, leftOK := d.resolveStringExpr(bin.X)
		if !leftOK {
			return "", false
		}
		right, rightOK := d.resolveStringExpr(bin.Y)
		if !rightOK {
			return "", false
		}
		return left + right, true
	}

	// A bare identifier referencing a package-level `var` (never a real
	// constant, or go/types would already have folded it above) that the
	// caller's pseudoConsts index has confirmed is never reassigned
	// anywhere in its own package — e.g. "var GET = \"GET\"" used as a
	// pre-generics or intentionally-mutable stand-in for a constant.
	if ident, ok := expr.(*ast.Ident); ok {
		if v, ok := d.info.Uses[ident].(*types.Var); ok && d.pseudoConsts != nil {
			if value, ok := d.pseudoConsts[v]; ok {
				return value, true
			}
		}
	}

	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return "", false
	}
	obj := d.info.Uses[ident]
	if obj == nil {
		return "", false
	}
	fields, ok := d.structLiteralParams[obj]
	if !ok {
		return "", false
	}
	v, ok := fields[sel.Sel.Name]
	return v, ok
}

// structFieldBinding pairs one registrar-call argument position with the
// string-constant field values resolveCompositeLitStringFields extracted
// from it, for tryFollowRegistrarCall to bind onto the matching callee
// parameter once its signature is known — see structLiteralParams' doc
// comment.
type structFieldBinding struct {
	argIndex int
	fields   map[string]string
}

// resolveCompositeLitStringFields resolves every string-constant field of a
// struct composite literal (keyed, e.g. "Route{Type: PATCH, Path: "/x"}",
// or positional, matched to the literal's own static field order) into a
// field-name-to-value map. A field whose value is not itself a compile-time
// string constant is simply absent from the result — never a guess — so a
// mixed literal (one literal field, one computed field) still yields
// whatever it safely can.
func (d *discoverer) resolveCompositeLitStringFields(lit *ast.CompositeLit) map[string]string {
	fields := map[string]string{}
	allKeyed := true
	for _, elt := range lit.Elts {
		if _, ok := elt.(*ast.KeyValueExpr); !ok {
			allKeyed = false
			break
		}
	}
	if allKeyed {
		for _, elt := range lit.Elts {
			kv := elt.(*ast.KeyValueExpr)
			key, ok := kv.Key.(*ast.Ident)
			if !ok {
				continue
			}
			if v, ok := d.resolveStringExpr(kv.Value); ok {
				fields[key.Name] = v
			}
		}
		return fields
	}

	// Positional (unkeyed) literal: match each element to its struct
	// field's name by index, via the literal's own static type.
	structType, ok := underlyingStruct(d.info.TypeOf(lit))
	if !ok {
		return fields
	}
	for i, elt := range lit.Elts {
		if i >= structType.NumFields() {
			break
		}
		if v, ok := d.resolveStringExpr(elt); ok {
			fields[structType.Field(i).Name()] = v
		}
	}
	return fields
}

// underlyingStruct unwraps t (which may itself be a *types.Named wrapping a
// struct) down to its *types.Struct, if it is one.
func underlyingStruct(t types.Type) (*types.Struct, bool) {
	if t == nil {
		return nil, false
	}
	s, ok := t.Underlying().(*types.Struct)
	return s, ok
}

func (d *discoverer) stringSliceLiteral(args []ast.Expr, index int) ([]string, bool) {
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

// normalizePath collapses duplicate slashes and strips a trailing slash
// (except for the root path itself), giving routes a single stable
// comparison form independent of incidental differences in how a path was
// written (e.g. a group joined path ending up with "//" is not possible
// through JoinPaths today, but this keeps normalization robust if a future
// registration kind constructs a path a different way).
func normalizePath(p string) string {
	if p == "" {
		return "/"
	}
	segments := strings.Split(p, "/")
	kept := make([]string, 0, len(segments))
	for _, seg := range segments {
		if seg == "" {
			continue
		}
		kept = append(kept, seg)
	}
	normalized := "/" + strings.Join(kept, "/")
	if strings.HasSuffix(p, "/") && normalized != "/" {
		normalized += "/"
	}
	return normalized
}
