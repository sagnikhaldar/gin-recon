package shapes

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// authFailure is a sentinel panic value used only to prove the
// defer/recover-based abort shape below; it is not a general-purpose error type.
type authFailure struct{}

// RequireAuthDeferRecover terminates the chain by panicking and recovering in
// a deferred function rather than a direct if-branch abort. ADR-0008 excludes
// defer/recover-based termination from confirmed-shape because proving it
// requires reasoning about panic propagation and recover scope, not just
// straight-line control flow. Expected enforcementAnalysis: unresolved.
func RequireAuthDeferRecover(c *gin.Context) {
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(authFailure); ok {
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}
			panic(r)
		}
	}()
	if c.GetHeader("Authorization") == "" {
		panic(authFailure{})
	}
	c.Next()
}
