package shapes

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// RequireAuthGoroutine performs the authorization check on a separate
// goroutine and signals the result over a channel. ADR-0008 excludes
// goroutine/channel-based termination from confirmed-shape because proving
// the deny path is reached requires reasoning about concurrent execution and
// channel communication, not just straight-line control flow. Expected
// enforcementAnalysis: unresolved.
func RequireAuthGoroutine(c *gin.Context) {
	authorized := make(chan bool, 1)
	go func() {
		authorized <- c.GetHeader("Authorization") != ""
	}()
	if !<-authorized {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	c.Next()
}
