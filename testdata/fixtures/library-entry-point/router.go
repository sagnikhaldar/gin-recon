// Package libraryentrypoint exercises gin.DetectLibraryEntryPoint against
// the real-world "SDK module" shape found scanning several actual services:
// a module that never calls gin.New()/gin.Default() anywhere, and instead
// exposes an Init(router *gin.RouterGroup, ...) function meant to be called
// from a host application's own source, which this analyzer cannot see.
//
// UncalledInit is never called anywhere in this module at all — that is the
// exact condition DetectLibraryEntryPoint requires before firing, so it
// must produce a gin-library-entry-point diagnostic. CalledInit has the
// identical shape but IS called from WiredUp within this same module, so it
// must NOT fire the diagnostic — existing registrar-following (or, if that
// call site's argument isn't itself a tracked value, the pre-existing
// gin-unresolved-registrar/gin-untracked-router-value diagnostics) already
// covers that case, and this diagnostic would be a confusing, redundant
// duplicate if it also fired here.
package libraryentrypoint

import "github.com/gin-gonic/gin"

func Handler(c *gin.Context) {}

// UncalledInit registers real routes on a *gin.RouterGroup parameter but is
// never invoked anywhere in this module — genuinely unresolvable from here.
func UncalledInit(router *gin.RouterGroup) {
	webhooks := router.Group("/webhooks")
	webhooks.POST("/uncalled", Handler)
}

// CalledInit has the identical shape, but is called below from WiredUp,
// itself reached via a real gin.New() in the same module — the routes it
// registers ARE resolvable, so no library-entry-point diagnostic should
// fire for it.
func CalledInit(router *gin.RouterGroup) {
	router.POST("/called", Handler)
}

func WiredUp() *gin.Engine {
	r := gin.New()
	api := r.Group("/api")
	CalledInit(api)
	return r
}
