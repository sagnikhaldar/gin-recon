// Package middlewareorder is a static-analysis fixture proving middleware
// ordering and registration-scope attribution: global (engine.Use) before
// group (Group's inline handlers or group.Use) before route-level (extra
// handler args at the registration call itself), and that a nested group
// correctly combines every ancestor's middleware in registration order.
package middlewareorder

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func RequestID(c *gin.Context)    { c.Next() }
func RequireAuth(c *gin.Context)  { c.Next() }
func RequireAdmin(c *gin.Context) { c.Next() }
func RateLimit(c *gin.Context)    { c.Next() }

func Health(c *gin.Context)     { c.Status(http.StatusOK) }
func ListUsers(c *gin.Context)  { c.Status(http.StatusOK) }
func DeleteUser(c *gin.Context) { c.Status(http.StatusOK) }

// NewRouter registers:
//   - GET /health with no middleware at all (global Use happens after this
//     line, proving middleware registered later is not attributed
//     retroactively).
//   - GET /admin/users under a group with one inline group-middleware arg,
//     inheriting the (by-then-registered) global RequestID middleware.
//   - DELETE /admin/users/:id with an additional route-level middleware
//     (RateLimit) on top of everything the group already carries, and a
//     nested group (RequireAdmin) two levels deep from the engine.
func NewRouter() *gin.Engine {
	r := gin.New()

	r.GET("/health", Health)

	r.Use(RequestID)

	admin := r.Group("/admin", RequireAuth)
	admin.GET("/users", ListUsers)

	superAdmin := admin.Group("/users", RequireAdmin)
	superAdmin.DELETE("/:id", RateLimit, DeleteUser)

	return r
}
