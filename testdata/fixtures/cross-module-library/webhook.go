// Package webhook is the "library module" side of the cross-module
// registrar-following fixture: it never constructs its own gin.Engine
// anywhere, and instead exposes Init to be called from a separate host
// module's own source — the exact real-world shape found scanning several
// production services (see docs/adr/0010-opt-in-cross-module-registrar-following.md).
package webhook

import "github.com/gin-gonic/gin"

func Handler(c *gin.Context) {}

// Init registers routes on a router received from the caller. Scanned
// standalone, this module correctly produces gin-library-entry-point (see
// gin.DetectLibraryEntryPoint) since nothing here ever calls Init.
func Init(router *gin.RouterGroup) error {
	router.Use(LogMiddleware())
	router.POST("/webhook", Handler)
	return nil
}

func LogMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) { c.Next() }
}
