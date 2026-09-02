package shapes

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// RequireAuthTwoLevel is the boundary-proving negative case: the deny path is
// resolvable in principle, but only by following two same-package call hops
// (RequireAuthTwoLevel -> checkAuthorization -> denyIfMissingToken). ADR-0008
// fixes the boundary at exactly one hop, so this must NOT be confirmed even
// though a deeper analysis could resolve it. Expected enforcementAnalysis:
// unresolved.
func RequireAuthTwoLevel(c *gin.Context) {
	if !checkAuthorization(c) {
		return
	}
	c.Next()
}

func checkAuthorization(c *gin.Context) bool {
	return denyIfMissingToken(c)
}

func denyIfMissingToken(c *gin.Context) bool {
	if c.GetHeader("Authorization") == "" {
		c.AbortWithStatus(http.StatusUnauthorized)
		return false
	}
	return true
}
