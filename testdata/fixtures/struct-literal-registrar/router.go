// Package structliteralregistrar exercises three related resolution
// capabilities together, all found while scanning real production
// services and all resolved through resolveStringExpr's fallback chain:
//
//   - structLiteralParams: a generic, data-driven registrar helper called
//     from many sites, each with a literal Route{...} argument whose type
//     parameter is inferred from another argument (never explicitly
//     instantiated).
//   - pseudoConsts: a package-level `var` (not a real `const`, so
//     go/types never constant-folds it) assigned a literal string and
//     never reassigned anywhere in its package — a common pre-generics or
//     intentionally-mutable stand-in for HTTP method constants.
//   - String concatenation (resolveStringExpr's *ast.BinaryExpr case)
//     combining a struct-literal-bound field with a literal prefix.
//
// MutableMethod is the deliberate negative case: it looks identical to
// the pseudo-const vars, but IS reassigned elsewhere in this same package
// (in Reassign, below), so it must never be trusted — resolveStringExpr's
// pseudoConsts index is built by internal/analyzer's buildPseudoConstIndex,
// which removes any candidate on the first hint of reassignment.
package structliteralregistrar

import "github.com/gin-gonic/gin"

var (
	GET     = "GET"
	POST    = "POST"
	Mutable = "INITIAL"
)

// Reassign gives Mutable a second value elsewhere in the package —
// buildPseudoConstIndex must see this and refuse to trust Mutable's
// declaration-time value anywhere it is read.
func Reassign() {
	Mutable = "CHANGED"
}

type Route struct {
	Method string
	Path   string
}

func Handler(c *gin.Context) {}

func registerRoute[T any](router *gin.RouterGroup, route Route, handler T) {
	router.Handle(route.Method, route.Path, any(handler).(func(*gin.Context)))
}

func NewRouter() *gin.Engine {
	r := gin.New()
	api := r.Group("/api")

	registerRoute(api, Route{Method: "GET", Path: "/keyed"}, func(c *gin.Context) {})
	registerRoute(api, Route{"POST", "/positional"}, func(c *gin.Context) {})
	registerRoute(api, Route{Method: GET, Path: "/pseudo-const"}, func(c *gin.Context) {})
	// Path's value concatenates a literal prefix with the GET pseudo-const
	// var — go/types cannot constant-fold this (GET is a var, not a real
	// constant), so it only resolves through resolveStringExpr's
	// *ast.BinaryExpr fallback recursing into both operands.
	registerRoute(api, Route{Method: POST, Path: "/concat/" + GET}, func(c *gin.Context) {})

	// Mutable is never trusted, so this route stays unresolved rather than
	// silently registering under its (possibly stale) declaration-time
	// value "INITIAL".
	registerRoute(api, Route{Method: Mutable, Path: "/never-inventoried"}, func(c *gin.Context) {})

	return r
}
