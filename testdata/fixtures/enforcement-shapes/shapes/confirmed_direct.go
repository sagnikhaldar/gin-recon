package shapes

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// RequireAuthDirect is the ADR-0008 baseline positive case: the deny path is a
// direct if-branch in the middleware's own body that calls AbortWithStatus and
// returns, with nothing reachable after it on that branch. Expected
// enforcementAnalysis: confirmed-shape.
func RequireAuthDirect(c *gin.Context) {
	token := c.GetHeader("Authorization")
	if token == "" {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	c.Next()
}
