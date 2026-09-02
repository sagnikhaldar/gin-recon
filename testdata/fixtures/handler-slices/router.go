// Package handlerslices exercises resolving a "...handlers" spread argument
// to its individual elements when — and only when — it originates from a
// literal slice composite this analyzer can see in full, per
// internal/analyzer/gin/discover.go's resolveHandlerSlice.
package handlerslices

import "github.com/gin-gonic/gin"

func A(c *gin.Context) {}
func B(c *gin.Context) {}

// dynamicHandlers is deliberately opaque to resolveHandlerSlice — it is a
// function call result, not a literal, so a route spreading it must stay
// unresolved rather than guessed at.
func dynamicHandlers() []gin.HandlerFunc {
	return []gin.HandlerFunc{A, B}
}

func NewRouter() *gin.Engine {
	r := gin.New()

	// Inline composite literal spread: resolves both A and B in order.
	r.GET("/inline", []gin.HandlerFunc{A, B}...)

	// Named local variable bound to a literal slice, then spread: resolves
	// both A and B in order, exactly like the inline case.
	named := []gin.HandlerFunc{A, B}
	r.GET("/named", named...)

	// A function-call result spread: not a literal this analyzer can see in
	// full, so it must stay unresolved (route not inventoried) rather than
	// being silently dropped with no signal, or fabricated.
	dynamic := dynamicHandlers()
	r.GET("/dynamic", dynamic...)

	// A keyed composite literal: positional meaning is not guaranteed the
	// same way an ordinary unkeyed literal's is, so this must also stay
	// unresolved.
	keyed := []gin.HandlerFunc{0: A, 1: B}
	r.GET("/keyed", keyed...)

	return r
}
