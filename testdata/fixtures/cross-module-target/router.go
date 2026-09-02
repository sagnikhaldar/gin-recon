// Package main is the "host application" side of the cross-module
// registrar-following fixture: it constructs a real engine and calls into
// a separate library module's Init function, which registers a route on
// the group it receives — a route this analysis cannot see at all unless
// analysis.followModules explicitly names the library module.
package main

import (
	lib "gin-recon-fixtures/cross-module-library"
	"github.com/gin-gonic/gin"
)

func Handler(c *gin.Context) {}

func NewRouter() *gin.Engine {
	r := gin.New()
	r.GET("/health", Handler)

	api := r.Group("/api")
	if err := lib.Init(api); err != nil {
		panic(err)
	}
	return r
}

func main() {}
