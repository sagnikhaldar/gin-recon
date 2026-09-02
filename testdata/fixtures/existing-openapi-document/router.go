// Package existingopenapidocument exercises full discovery-through-OpenAPI
// reconciliation against a companion pre-existing OpenAPI document
// (openapi.yaml in this same directory), per
// docs/adr/0013-existing-openapi-document-reconciliation.md: GetUser's route
// fully agrees with the document (same path parameter name), GetOrder's
// route names its path parameter differently than the document does (a
// structural conflict), and PlainHandler has no corresponding document
// operation at all. The document also names one operation, DELETE
// /legacy/{id}, that exists in neither this file nor anywhere else in this
// fixture — the orphan case.
package existingopenapidocument

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
