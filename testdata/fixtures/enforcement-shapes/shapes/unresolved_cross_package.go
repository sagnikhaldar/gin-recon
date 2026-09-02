package shapes

import (
	"gin-recon-fixtures/enforcement-shapes/helper"

	"github.com/gin-gonic/gin"
)

// RequireAuthCrossPackage delegates the deny decision to another package.
// ADR-0008 permits only same-package delegation for confirmed-shape, so
// crossing a package boundary always yields unresolved regardless of hop
// count. Expected enforcementAnalysis: unresolved.
func RequireAuthCrossPackage(c *gin.Context) {
	if !helper.DenyUnlessAuthorized(c) {
		return
	}
	c.Next()
}
