package shapes

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// RequireAuthOneLevel delegates the deny decision to exactly one same-package
// helper that itself matches the direct-abort shape. ADR-0008 permits this one
// level of same-package delegation. Expected enforcementAnalysis:
// confirmed-shape.
func RequireAuthOneLevel(c *gin.Context) {
	if !denyUnlessAuthorized(c) {
		return
	}
	c.Next()
}

// denyUnlessAuthorized aborts and returns false when unauthorized, otherwise
// returns true. It is the single resolvable hop RequireAuthOneLevel delegates
// to; it must not itself delegate further, or this fixture would exercise the
// two-level case instead.
func denyUnlessAuthorized(c *gin.Context) bool {
	if c.GetHeader("Authorization") == "" {
		c.AbortWithStatus(http.StatusUnauthorized)
		return false
	}
	return true
}
