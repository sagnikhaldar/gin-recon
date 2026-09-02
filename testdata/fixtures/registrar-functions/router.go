// Package registrarfunctions proves bounded interprocedural registrar
// following: a same-package function, a cross-package function, a
// method-value registrar, and one genuinely unresolvable case (a route
// registered from inside a callback held in a function-typed parameter,
// which is not followed and must produce a diagnostic instead of being
// silently dropped).
package registrarfunctions

import (
	"net/http"

	"gin-recon-fixtures/registrar-functions/routes"

	"github.com/gin-gonic/gin"
)

func Handler(c *gin.Context) { c.Status(http.StatusOK) }

func registerHealthRoutes(r *gin.Engine) {
	r.GET("/health", Handler)
}

type UserHandler struct{}

func (h *UserHandler) RegisterRoutes(r *gin.Engine) {
	r.GET("/users/:id", Handler)
}

func registerViaCallback(r *gin.Engine, cb func(*gin.Engine)) {
	cb(r)
}

func NewRouter() *gin.Engine {
	r := gin.New()

	registerHealthRoutes(r)
	routes.RegisterAPIRoutes(r)

	handler := &UserHandler{}
	handler.RegisterRoutes(r)

	registerViaCallback(r, func(e *gin.Engine) {
		e.GET("/never-inventoried", Handler)
	})

	return r
}

// registerViaIfErr, registerViaPlainAssign, registerViaReturn, and
// wrapReturnedRegistrar are the idiomatic error-returning registrar shapes
// that real-world testing against a production Gin service found silently
// invisible: "if err := initializeRouter(r, ...); err != nil { ... }" hid an
// entire 120-route API surface because walkStmt never visited an *ast.IfStmt's
// Init clause, and handleAssign never followed a registrar call whose result
// was merely assigned rather than a fresh engine/group value.
func registerViaIfErr(r *gin.Engine) error {
	r.GET("/if-err-registrar", Handler)
	return nil
}

func registerViaPlainAssign(r *gin.Engine) error {
	r.GET("/plain-assign-registrar", Handler)
	return nil
}

func registerViaReturn(r *gin.Engine) error {
	r.GET("/return-registrar", Handler)
	return nil
}

func wrapReturnedRegistrar(r *gin.Engine) error {
	return registerViaReturn(r)
}

// NewRouterWithControlFlowRegistrars proves registrar-following also works
// through the if-err, plain-assignment, and return-delegation control-flow
// shapes exercised above, each via one representative entry point.
func NewRouterWithControlFlowRegistrars() *gin.Engine {
	r := gin.New()

	if err := registerViaIfErr(r); err != nil {
		panic(err)
	}

	err := registerViaPlainAssign(r)
	_ = err

	if err := wrapReturnedRegistrar(r); err != nil {
		panic(err)
	}

	return r
}
