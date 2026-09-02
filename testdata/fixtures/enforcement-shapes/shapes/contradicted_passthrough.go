package shapes

import "github.com/gin-gonic/gin"

// RequireAuthAlwaysPasses matches an authMiddleware canonical symbol by name
// but its entire body is self-contained (only calls its own *gin.Context
// parameter's methods) and never calls Abort/AbortWithStatus*/AbortWithError
// anywhere. ADR-0008 permits proving contradiction only within the same
// bounded, fully-visible scope confirmed-shape uses — this function's body
// is fully visible and provably abort-free. Expected enforcementAnalysis:
// contradicted.
func RequireAuthAlwaysPasses(c *gin.Context) {
	c.Set("checked", true)
	c.Next()
}
