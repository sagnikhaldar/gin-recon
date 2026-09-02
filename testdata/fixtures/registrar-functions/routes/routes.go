// Package routes is a separate package from the fixture's root, proving
// registrar-following works across a package boundary, not just within one
// file or package.
package routes

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func apiHandler(c *gin.Context) { c.Status(http.StatusOK) }

func RegisterAPIRoutes(r *gin.Engine) {
	r.GET("/api/users", apiHandler)
}
