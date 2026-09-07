package includetests

import "github.com/gin-gonic/gin"

// newTestRouter mirrors a common httptest-setup idiom: a route wired up
// only for use by this package's own tests, never reachable from the real
// application binary at all. See router.go's package doc comment.
func newTestRouter() *gin.Engine {
	r := gin.New()
	r.GET("/test-only-route", Handler)
	return r
}
