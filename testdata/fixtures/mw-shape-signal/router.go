// Package mwshapesignal proves internal/analyzer.SuggestAuth's
// EnforcementShape ranking signal: a middleware whose own name gives no
// hint at all, but whose code has a real, independently-verified
// direct-abort shape, must still rank ahead of a name-hinted middleware
// whose code is provably a no-op — code-shape evidence outranks a name
// pattern alone, per suggest.go's own doc comment.
package mwshapesignal

import "github.com/gin-gonic/gin"

func Handler(c *gin.Context) { c.Status(200) }

// CheckHeaderPresence's own name matches none of authNameHint's patterns,
// but its body is a genuine direct-abort shape (confirmed-shape) — a real
// guard a name-only heuristic would miss entirely.
func CheckHeaderPresence(c *gin.Context) {
	if c.GetHeader("X-Internal") == "" {
		c.AbortWithStatus(403)
		return
	}
	c.Next()
}

// AuthLogger's name matches authNameHint ("Auth"), but its body only ever
// touches its own *gin.Context parameter's methods and never aborts —
// provably abort-free (contradicted), the same bounded proof
// auth-wrappers/router.go's RequireAuthContradicted uses.
func AuthLogger(c *gin.Context) {
	c.Set("logged", true)
	c.Next()
}

func NewRouter() *gin.Engine {
	r := gin.New()
	r.Use(AuthLogger)
	admin := r.Group("/admin", CheckHeaderPresence)
	admin.GET("/ping", Handler)
	return r
}
