// Package swagannotations exercises swaggo/swag-style doc-comment
// annotations above Gin handler functions, per
// docs/adr/0012-swag-annotation-evidence.md: GetUser carries a full,
// accurate set of directives; ListUsers carries a deliberately stale
// @Router line to confirm a mismatch is diagnosed without suppressing the
// rest of its annotation's evidence; PlainHandler has an ordinary Go doc
// comment with no swag directive at all, and must be left completely
// unaffected.
package swagannotations

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// GetUser returns a single user by ID.
//
// @Summary Get a user by ID
// @Description Returns the user record matching the given ID.
// @Description Requires no authentication in this fixture.
// @Tags users, public
// @Router /users/{id} [get]
// @Deprecated
func GetUser(c *gin.Context) { c.Status(http.StatusOK) }

// ListUsers returns every user.
//
// @Summary List all users
// @Router /users [post]
func ListUsers(c *gin.Context) { c.Status(http.StatusOK) }

// PlainHandler has an ordinary doc comment describing what it does, with no
// swag annotation of any kind — the common case this feature must not
// misfire on.
func PlainHandler(c *gin.Context) { c.Status(http.StatusOK) }

func NewRouter() *gin.Engine {
	r := gin.New()
	r.GET("/users/:id", GetUser)
	r.GET("/users", ListUsers)
	r.GET("/plain", PlainHandler)
	return r
}
