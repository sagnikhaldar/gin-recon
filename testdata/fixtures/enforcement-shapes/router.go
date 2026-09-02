package enforcementshapes

import (
	"net/http"

	"gin-recon-fixtures/enforcement-shapes/shapes"

	"github.com/gin-gonic/gin"
)

// NewRouter registers one route per ADR-0008 enforcement-shape case. This
// module is a static-analysis fixture, not a runnable service: routes share a
// trivial 200 handler because the fixture is about the middleware's
// classification, not its business logic.
func NewRouter() *gin.Engine {
	r := gin.New()

	ok := func(c *gin.Context) { c.Status(http.StatusOK) }

	r.GET("/confirmed/direct", shapes.RequireAuthDirect, ok)
	r.GET("/confirmed/delegated-one-level", shapes.RequireAuthOneLevel, ok)
	r.GET("/unresolved/delegated-two-level", shapes.RequireAuthTwoLevel, ok)
	r.GET("/unresolved/cross-package", shapes.RequireAuthCrossPackage, ok)
	r.GET("/unresolved/defer-recover", shapes.RequireAuthDeferRecover, ok)
	r.GET("/unresolved/goroutine", shapes.RequireAuthGoroutine, ok)
	r.GET("/contradicted/passthrough", shapes.RequireAuthAlwaysPasses, ok)

	r.GET("/factory/direct", shapes.RequireRoleFactory("admin"), ok)
	r.GET("/factory/one-hop", shapes.RequireAuthFactory("user"), ok)
	r.GET("/factory/too-deep", shapes.RequireAuthFactoryTooDeep("user"), ok)
	r.GET("/factory/cross-package", shapes.RequireAuthFactoryCrossPackage("user"), ok)

	return r
}
