package shapes

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// RequireRoleFactory is the ADR-0008 factory-resolution baseline case: a
// factory function (does not itself take *gin.Context) that directly
// returns a literal closure matching the direct-abort shape, zero
// delegation hops needed. This mirrors the extremely common real-world
// pattern of parameterized Gin middleware
// ("func RequireRole(role string) gin.HandlerFunc"). Expected
// enforcementAnalysis: confirmed-shape.
func RequireRoleFactory(role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetHeader("X-Role") != role {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		c.Next()
	}
}
