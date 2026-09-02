package gin

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"

	"github.com/sagnikhaldar/gin-recon/internal/model"
)

// DetectLibraryEntryPoint closes a distinct visibility gap from
// diagnoseUntrackedRouterValue's: a function that receives an already-built
// *gin.Engine/*gin.RouterGroup as a PARAMETER (rather than constructing one
// itself or being reached via registrar-following from a real entry point)
// and registers routes directly on it — the "library module" shape, e.g.
// "func Init(router *gin.RouterGroup, ...) error { g := router.Group("/x");
// g.POST("/webhook", h) }" in a module that never calls gin.New()/Default()
// anywhere at all. Discover has no entry point to start from for this
// function (HasEngineConstruction is false for it, by definition), so
// without this check its real route registrations would be entirely
// invisible with no signal at all — a materially different, and in practice
// common, case from a single untracked value inside an otherwise-legitimate
// entry point.
//
// The routes such a function registers are genuinely unresolvable from this
// module alone: the actual engine only exists in whatever host application
// calls this function, which may live in a different repository this
// analyzer was never asked to scan. This returns a diagnostic making that
// gap explicit rather than a route — it must never be treated as a
// "resolved" registrar the way tryFollowRegistrarCall's callee-with-an-
// existing-tracked-argument case is, since there is no tracked argument
// here for it to bind to.
func DetectLibraryEntryPoint(fset *token.FileSet, info *types.Info, api *API, fn *ast.FuncDecl) *model.Diagnostic {
	if fn.Body == nil || fn.Type.Params == nil {
		return nil
	}
	for _, field := range fn.Type.Params.List {
		t := info.TypeOf(field.Type)
		if t == nil {
			continue
		}
		isEngine, isGroup := api.IsRouterValue(t)
		if !isEngine && !isGroup {
			continue
		}
		for _, name := range field.Names {
			if name.Name == "_" {
				continue
			}
			paramObj := info.Defs[name]
			if paramObj == nil {
				continue
			}
			if !bodyCallsRouteRelevantMethodOn(info, fn.Body, paramObj) {
				continue
			}
			label := "*gin.RouterGroup"
			if isEngine {
				label = "*gin.Engine"
			}
			return &model.Diagnostic{
				Code:     "gin-library-entry-point",
				Severity: model.DiagnosticWarning,
				Message: fmt.Sprintf(
					"%s receives a %s parameter and registers routes on it directly, but this module never constructs its own gin.Engine anywhere — the routes it registers are only visible when the host application that calls %s is itself scanned",
					fn.Name.Name, label, fn.Name.Name,
				),
				Source: sourceOfPos(fset, fn.Pos()),
			}
		}
	}
	return nil
}

// bodyCallsRouteRelevantMethodOn reports whether body calls a route-
// registration-relevant method (see routeRelevantMethodNames) on obj,
// directly or through a same-function Group() derivative of it — a
// parameter used only to read state, log, or pass through unchanged does
// not itself indicate route registration and is not flagged.
func bodyCallsRouteRelevantMethodOn(info *types.Info, body *ast.BlockStmt, obj types.Object) bool {
	tracked := map[types.Object]bool{obj: true}
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		// Propagate through "child := parent.Group(...)" so a route call on
		// a derived group still counts as using the original parameter —
		// the common shape ("heroGroup := router.Group("/hero")") this
		// diagnostic exists to catch in the first place.
		if assign, ok := n.(*ast.AssignStmt); ok {
			for i, rhs := range assign.Rhs {
				call, ok := rhs.(*ast.CallExpr)
				if !ok {
					continue
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Group" {
					continue
				}
				recvIdent, ok := sel.X.(*ast.Ident)
				if !ok || !tracked[info.Uses[recvIdent]] {
					continue
				}
				if i < len(assign.Lhs) {
					if lhsIdent, ok := assign.Lhs[i].(*ast.Ident); ok && lhsIdent.Name != "_" {
						if lhsObj := info.Defs[lhsIdent]; lhsObj != nil {
							tracked[lhsObj] = true
						}
					}
				}
			}
			return true
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !routeRelevantMethodNames[sel.Sel.Name] {
			return true
		}
		recvIdent, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		if tracked[info.Uses[recvIdent]] {
			found = true
			return false
		}
		return true
	})
	return found
}

func sourceOfPos(fset *token.FileSet, pos token.Pos) *model.Source {
	if pos == token.NoPos {
		return nil
	}
	p := fset.Position(pos)
	line := p.Line
	return &model.Source{File: p.Filename, Line: &line}
}
