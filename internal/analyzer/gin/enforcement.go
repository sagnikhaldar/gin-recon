package gin

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/sagnikhaldar/gin-recon/internal/model"
)

// abortMethodNames are gin.Context's exact chain-terminating methods
// (verified against gin-gonic/gin@v1.10.0's context.go). Any other method —
// including Next(), Set(), Get(), and the various binding/render helpers —
// does not terminate the chain and is irrelevant to enforcement-shape
// analysis.
var abortMethodNames = map[string]bool{
	"Abort":               true,
	"AbortWithStatus":     true,
	"AbortWithStatusJSON": true,
	"AbortWithError":      true,
}

// maxFactoryHops bounds ADR 0008's factory-closure resolution (see
// resolveBody): a configured symbol that is a factory function — the
// dominant real-world pattern for parameterized Gin middleware
// ("func RequireRole(role string) gin.HandlerFunc { return func(c
// *gin.Context) {...} }") — is unwound at most this many same-package
// delegation hops before giving up and returning unresolved. One hop
// already covers the common two-layer factory idiom (an exported factory
// that immediately delegates to an unexported implementation which returns
// the literal); anything deeper is unresolved by design, the same bounded
// philosophy as the middleware-delegation case below.
const maxFactoryHops = 1

// analysisBody is the function-shaped thing enforcement analysis actually
// inspects: either a matched middleware's own *ast.FuncDecl body, or — after
// resolveBody unwinds a factory function — the *ast.FuncLit body it
// returns. pkg is whichever package body was declared in, used by
// hasOneLevelDelegatedAbortShape's same-package check; it is not always
// fn's own package once factory resolution has crossed into a literal
// defined inside a different (same-package, per maxFactoryHops) function.
type analysisBody struct {
	stmts    *ast.BlockStmt
	info     *types.Info
	ctxParam *types.Var
	pkg      *types.Package
}

// AnalyzeEnforcement implements the exact, fixed boundary from
// docs/adr/0008-bounded-enforcement-shape-analysis.md, including the
// factory-closure resolution that ADR extends to. It must not be widened
// further without a new ADR, a fixture proving the new positive case, and a
// fixture proving the boundary still excludes the next case out.
//
// fn is the canonical *types.Func a route's middleware matched against
// configuration (see internal/classify, which calls this). funcIndex is the
// whole-module function index built by internal/analyzer, the same one
// Discover uses for registrar-following.
func AnalyzeEnforcement(funcIndex map[*types.Func]FuncInfo, api *API, fn *types.Func) model.EnforcementAnalysis {
	body, ok := resolveBody(funcIndex, api, fn, 0)
	if !ok {
		return model.EnforcementUnresolved
	}

	if hasDirectAbortShape(body) {
		return model.EnforcementConfirmedShape
	}
	if hasOneLevelDelegatedAbortShape(funcIndex, body, api) {
		return model.EnforcementConfirmedShape
	}
	if isProvablyAbortFree(body) {
		return model.EnforcementContradicted
	}
	return model.EnforcementUnresolved
}

// resolveBody finds the actual per-request analysisBody for fn: either fn's
// own body directly (if it takes *gin.Context itself), or — if fn instead
// returns a gin.HandlerFunc-compatible value — the literal closure its
// single resolvable return statement produces, following at most
// maxFactoryHops same-package delegation hops to get there.
func resolveBody(funcIndex map[*types.Func]FuncInfo, api *API, fn *types.Func, hops int) (analysisBody, bool) {
	fi, ok := funcIndex[fn]
	if !ok || fi.Decl == nil || fi.Decl.Body == nil {
		return analysisBody{}, false
	}

	if ctxParam := contextParamOf(fi.Decl.Type.Params, fi.Info, api); ctxParam != nil {
		return analysisBody{stmts: fi.Decl.Body, info: fi.Info, ctxParam: ctxParam, pkg: fn.Pkg()}, true
	}

	if hops >= maxFactoryHops+1 {
		return analysisBody{}, false
	}
	if !returnsHandlerFuncType(fi.Decl.Type, fi.Info, api) {
		return analysisBody{}, false
	}
	ret, ok := singleOwnReturn(fi.Decl.Body)
	if !ok || len(ret.Results) != 1 {
		return analysisBody{}, false
	}

	switch result := ret.Results[0].(type) {
	case *ast.FuncLit:
		ctxParam := contextParamOf(result.Type.Params, fi.Info, api)
		if ctxParam == nil {
			return analysisBody{}, false
		}
		return analysisBody{stmts: result.Body, info: fi.Info, ctxParam: ctxParam, pkg: fn.Pkg()}, true
	case *ast.CallExpr:
		delegate := resolveCalleeFuncFromExpr(fi.Info, result.Fun)
		if delegate == nil || delegate.Pkg() == nil || delegate.Pkg() != fn.Pkg() {
			return analysisBody{}, false // cross-package factory delegation: unresolved by design
		}
		return resolveBody(funcIndex, api, delegate, hops+1)
	default:
		return analysisBody{}, false
	}
}

// returnsHandlerFuncType reports whether a function type's result list is
// exactly one gin.HandlerFunc-compatible value — the shape a middleware
// factory must have for resolveBody to attempt unwinding it at all.
func returnsHandlerFuncType(sig *ast.FuncType, info *types.Info, api *API) bool {
	if sig.Results == nil || len(sig.Results.List) != 1 {
		return false
	}
	t := info.TypeOf(sig.Results.List[0].Type)
	return t != nil && api.IsHandlerFuncType(t)
}

// singleOwnReturn finds the one return statement belonging directly to
// body — not one belonging to a nested function literal, which would be a
// different function's return entirely. Requiring exactly one keeps
// resolution unambiguous: a factory with multiple return paths producing
// different closures is not a case ADR 0008 attempts to resolve.
func singleOwnReturn(body *ast.BlockStmt) (*ast.ReturnStmt, bool) {
	var found []*ast.ReturnStmt
	ast.Inspect(body, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.ReturnStmt:
			found = append(found, v)
		}
		return true
	})
	if len(found) != 1 {
		return nil, false
	}
	return found[0], true
}

// contextParamOf finds a *gin.Context parameter by type identity within a
// parameter list — a function declaration's or a func literal's. A matched
// middleware should always have exactly the gin.HandlerFunc shape
// (func(*gin.Context)), but this checks every parameter rather than
// assuming position 0.
func contextParamOf(params *ast.FieldList, info *types.Info, api *API) *types.Var {
	if params == nil {
		return nil
	}
	for _, field := range params.List {
		t := info.TypeOf(field.Type)
		if t == nil {
			continue
		}
		if named := namedOf(t); named == nil || !types.Identical(named, api.Context) {
			continue
		}
		for _, name := range field.Names {
			if obj, ok := info.Defs[name].(*types.Var); ok {
				return obj
			}
		}
	}
	return nil
}

// hasDirectAbortShape implements ADR 0008's baseline positive case: a
// top-level if-statement whose body ends with an abort call immediately
// followed by a return, with nothing reachable after within that branch.
// Statements before the abort call within the same if-body are permitted
// (e.g. logging) — only what comes after is restricted.
func hasDirectAbortShape(b analysisBody) bool {
	for _, stmt := range b.stmts.List {
		ifStmt, ok := stmt.(*ast.IfStmt)
		if !ok {
			continue
		}
		// A condition built from a channel receive means this branch's
		// outcome depends on concurrent execution (typically a goroutine
		// signaling a result back), not straight-line control flow — exactly
		// the case ADR 0008 excludes, even though the branch's consequence
		// alone would otherwise match the direct-abort shape byte for byte.
		if containsChannelReceive(ifStmt.Cond) {
			continue
		}
		if ifBranchEndsInAbortReturn(b.info, ifStmt.Body, b.ctxParam) {
			return true
		}
	}
	return false
}

func containsChannelReceive(expr ast.Expr) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if unary, ok := n.(*ast.UnaryExpr); ok && unary.Op == token.ARROW {
			found = true
			return false
		}
		return true
	})
	return found
}

func ifBranchEndsInAbortReturn(info *types.Info, body *ast.BlockStmt, ctxParam *types.Var) bool {
	n := len(body.List)
	if n < 2 {
		return false
	}
	exprStmt, ok := body.List[n-2].(*ast.ExprStmt)
	if !ok {
		return false
	}
	if !isAbortCall(info, exprStmt.X, ctxParam) {
		return false
	}
	_, isReturn := body.List[n-1].(*ast.ReturnStmt)
	return isReturn
}

// isAbortCall reports whether expr is exactly "ctxParam.Abort*(...)" — a
// method call on the function's own *gin.Context parameter (by object
// identity, not by name) whose method is one of abortMethodNames.
func isAbortCall(info *types.Info, expr ast.Expr, ctxParam *types.Var) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || !abortMethodNames[sel.Sel.Name] {
		return false
	}
	recv, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	obj := info.Uses[recv]
	return obj != nil && obj == ctxParam
}

// hasOneLevelDelegatedAbortShape implements ADR 0008's second positive case:
// a top-level "if !helper(c) { return }" (or an equivalent single-hop
// delegation) where helper is a function or method declared in the exact
// same package as b (the analysisBody currently being examined — see
// resolveBody's doc comment on why this is not always the originally
// matched symbol's own package once factory resolution is involved) and
// itself satisfies hasDirectAbortShape. Crossing a package boundary, going
// through a second hop, or delegating through anything other than a
// directly-named same-package function/method all fall through to
// unresolved by design.
func hasOneLevelDelegatedAbortShape(funcIndex map[*types.Func]FuncInfo, b analysisBody, api *API) bool {
	for _, stmt := range b.stmts.List {
		ifStmt, ok := stmt.(*ast.IfStmt)
		if !ok {
			continue
		}
		if !isBareReturn(ifStmt.Body) {
			continue
		}
		delegate := delegatedCall(b.info, ifStmt.Cond, b.ctxParam)
		if delegate == nil || delegate.Pkg() == nil || b.pkg == nil || delegate.Pkg() != b.pkg {
			continue
		}
		delegateInfo, ok := funcIndex[delegate]
		if !ok || delegateInfo.Decl == nil || delegateInfo.Decl.Body == nil {
			continue
		}
		delegateCtxParam := contextParamOf(delegateInfo.Decl.Type.Params, delegateInfo.Info, api)
		if delegateCtxParam == nil {
			continue
		}
		delegateBody := analysisBody{stmts: delegateInfo.Decl.Body, info: delegateInfo.Info, ctxParam: delegateCtxParam, pkg: delegate.Pkg()}
		if hasDirectAbortShape(delegateBody) {
			return true
		}
	}
	return false
}

func isBareReturn(body *ast.BlockStmt) bool {
	if len(body.List) != 1 {
		return false
	}
	_, ok := body.List[0].(*ast.ReturnStmt)
	return ok
}

// delegatedCall recognizes "helper(c)" or "!helper(c)" as an if-condition,
// where helper is a named function or method value taking ctxParam as an
// argument, and returns the resolved *types.Func — or nil if the condition
// does not have this shape (e.g. it is a plain boolean expression, or the
// callee is reached through a variable rather than a direct name).
func delegatedCall(info *types.Info, cond ast.Expr, ctxParam *types.Var) *types.Func {
	if unary, ok := cond.(*ast.UnaryExpr); ok {
		cond = unary.X
		if unary.Op.String() != "!" {
			return nil
		}
	}
	call, ok := cond.(*ast.CallExpr)
	if !ok || len(call.Args) == 0 {
		return nil
	}
	argIdent, ok := call.Args[0].(*ast.Ident)
	if !ok || info.Uses[argIdent] != ctxParam {
		return nil
	}
	return resolveCalleeFuncFromExpr(info, call.Fun)
}

// isProvablyAbortFree implements ADR 0008's contradiction case as narrowly
// as the ADR requires: the body must be fully visible (every call in it is a
// method on its own Context parameter — nothing delegated, nothing opaque)
// and contain no abort call anywhere. Any call to something other than the
// Context parameter's own methods means part of the behavior is not
// accounted for, so it cannot be safely declared abort-free — that case
// falls through to unresolved, matching ADR 0008's "anything not resolvable
// one way or the other is unresolved."
func isProvablyAbortFree(b analysisBody) bool {
	provenFree := true
	ast.Inspect(b.stmts, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			provenFree = false
			return false
		}
		recv, ok := sel.X.(*ast.Ident)
		if !ok || b.info.Uses[recv] != b.ctxParam {
			provenFree = false
			return false
		}
		if abortMethodNames[sel.Sel.Name] {
			provenFree = false
			return false
		}
		return true
	})
	return provenFree
}
