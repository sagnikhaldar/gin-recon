// Package routekinds exercises every non-plain-verb registration kind:
// Handle, Any, Match, Static/StaticFile/StaticFS/StaticFileFS, NoRoute,
// NoMethod, and a dynamic (non-literal) path that must produce a coverage
// diagnostic rather than a silently dropped route.
package routekinds

import (
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

func Handler(c *gin.Context)  { c.Status(http.StatusOK) }
func Logger(c *gin.Context)   { c.Next() }
func NotFound(c *gin.Context) { c.Status(http.StatusNotFound) }

// BindAndValidate is a generic middleware factory — the common real-world
// pattern for a validation/binding helper parameterized by request DTO type
// (e.g. "middlewares.BindAndValidate[dtos.Foo](\"body\")"). Its canonical
// symbol must resolve to the base function, discarding the type argument,
// per docs/configuration-contract.md: "Generic instantiation arguments...
// are not part of identity."
func BindAndValidate[T any](source string) gin.HandlerFunc {
	return func(c *gin.Context) { c.Next() }
}

type ExampleDTO struct{}

func NewRouter(dynamicPrefix string) *gin.Engine {
	r := gin.New()
	r.Use(Logger)

	r.POST("/generic", BindAndValidate[ExampleDTO]("body"), Handler)

	r.Handle(http.MethodPost, "/webhook", Handler)
	r.Any("/wildcard", Handler)
	r.Match([]string{"GET", "POST"}, "/matched", Handler)

	r.Static("/assets", "./public")
	r.StaticFile("/favicon.ico", "./public/favicon.ico")
	r.StaticFS("/files", http.Dir(os.TempDir()))

	r.NoRoute(NotFound)
	r.NoMethod(NotFound)

	// Non-literal path: dynamicPrefix is a runtime value, not statically
	// resolvable. This must produce a diagnostic, not a silently
	// omitted route.
	r.GET(dynamicPrefix+"/dynamic", Handler)

	return r
}
