// Package helper simulates a shared "internal/auth"-style package that the
// scanned target's own middleware delegates to. It exists to prove ADR-0008's
// cross-package boundary case: even a trivially resolvable abort is
// unresolved once it crosses a package boundary from the configured
// middleware's own package.
package helper

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// DenyUnlessAuthorized has the same direct-abort shape as
// shapes.denyUnlessAuthorized, but lives in a different package than the
// configured middleware that calls it.
func DenyUnlessAuthorized(c *gin.Context) bool {
	if c.GetHeader("Authorization") == "" {
		c.AbortWithStatus(http.StatusUnauthorized)
		return false
	}
	return true
}

// MakeGuardFactory has the same direct-abort factory shape as
// shapes.RequireRoleFactory, but lives in a different package than the
// configured middleware that delegates to it — proving ADR-0008's
// factory-closure resolution is also same-package-only, not just the plain
// middleware-delegation case.
func MakeGuardFactory(tokenType string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetHeader("Authorization") == "" {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.Next()
	}
}
