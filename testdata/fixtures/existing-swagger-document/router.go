// Package existingswaggerdocument mirrors testdata/fixtures/existing-openapi-document
// but pairs the discovered routes with a genuinely Swagger 2.0 document
// (swagger.yaml — top-level "swagger: 2.0", not "openapi: 3.x") instead of an
// OpenAPI 3.x one, exercising this analyzer's BuildV2Model() fallback: GetUser's
// route fully agrees with the document (same path parameter name), GetOrder's
// route names its path parameter differently than the document does (a
// structural conflict), and PlainHandler has no corresponding document
// operation at all. The document also names one operation, DELETE
// /legacy/{id}, that exists in neither this file nor anywhere else in this
// fixture — the orphan case.
package existingswaggerdocument

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func GetUser(c *gin.Context) { c.Status(http.StatusOK) }

func GetOrder(c *gin.Context) { c.Status(http.StatusOK) }

func PlainHandler(c *gin.Context) { c.Status(http.StatusOK) }

func NewRouter() *gin.Engine {
	r := gin.New()
	r.GET("/users/:id", GetUser)
	r.GET("/orders/:orderId", GetOrder)
	r.GET("/plain", PlainHandler)
	return r
}
