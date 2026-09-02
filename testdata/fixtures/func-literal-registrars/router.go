// Package funcliteralregistrars exercises resolveCalleeFuncLit/
// followFuncLitRegistrar: registrar-following through a function literal —
// bound to a local variable, or called inline as an IIFE — not just through
// a named function/method value.
package funcliteralregistrars

import "github.com/gin-gonic/gin"

func A(c *gin.Context) {}

func NewRouter() *gin.Engine {
	r := gin.New()

	// Named local variable bound to a function literal, then called by
	// name — the primary "callback registrar" pattern this feature exists
	// for.
	registerNamed := func(engine *gin.Engine) {
		engine.GET("/named", A)
	}
	registerNamed(r)

	// An inline immediately-invoked function expression: the callee is a
	// *ast.FuncLit directly at the call site, no variable indirection at
	// all.
	func(engine *gin.Engine) {
		engine.GET("/inline", A)
	}(r)

	// A two-level chain: registerOuter (a function-literal registrar)
	// itself calls registerInner (also a function-literal registrar) with
	// the same tracked engine, proving depth/state propagate correctly
	// through more than one hop of function-literal following.
	registerInner := func(engine *gin.Engine) {
		engine.GET("/chained", A)
	}
	registerOuter := func(engine *gin.Engine) {
		registerInner(engine)
	}
	registerOuter(r)

	return r
}
