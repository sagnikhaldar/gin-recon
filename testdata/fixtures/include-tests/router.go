// Package includetests proves --include-tests (docs/reference.md):
// /always-visible is registered in ordinary, always-scanned source;
// /test-only-route (router_test.go) is registered only inside a _test.go
// file and must appear in the inventory only when --include-tests is set.
// Deliberately has no manifest.json — its expected route count depends on a
// flag, unlike every other fixture's fixed expectation, so the accuracy
// harness (cmd/gin-recon/accuracy_test.go) correctly skips it rather than
// asserting a single fixed answer.
package includetests

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func Handler(c *gin.Context) { c.Status(http.StatusOK) }

func NewRouter() *gin.Engine {
	r := gin.New()
	r.GET("/always-visible", Handler)
	return r
}
