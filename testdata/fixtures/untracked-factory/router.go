// Package untrackedfactory proves the boundary of resolveEngineFactoryCall:
// a wrapping factory function whose every return statement agrees on which
// tracked engine it returns is now resolved as if inlined (including any
// middleware it applied via Use() before returning, and any routes it
// registered on the engine itself), while a factory whose return statements
// disagree about which engine comes back is still, correctly, left
// untracked — this analyzer never guesses which of two different engines a
// caller actually receives.
package untrackedfactory

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func Handler(c *gin.Context)       { c.Status(http.StatusOK) }
func RequestLogger(c *gin.Context) { c.Next() }

// newEngine wraps gin.New() as a single, unconditional return — resolvable.
func newEngine() *gin.Engine {
	return gin.New()
}

// newLoggedEngine wraps gin.New(), calls Use() on it, and registers a route
// directly on it, all before returning — every one of those effects must
// still be visible at the caller once the factory call resolves.
func newLoggedEngine() *gin.Engine {
	r := gin.New()
	r.Use(RequestLogger)
	r.GET("/factory-internal", Handler)
	return r
}

// newAmbiguousEngine's two return statements return two DIFFERENT engines —
// genuinely ambiguous without runtime information, so this must stay
// untracked rather than this analyzer arbitrarily picking one.
func newAmbiguousEngine(useSecondary bool) *gin.Engine {
	primary := gin.New()
	if useSecondary {
		secondary := gin.New()
		return secondary
	}
	return primary
}

func NewRouter() *gin.Engine {
	r := newEngine()
	r.GET("/resolved-factory", Handler)

	logged := newLoggedEngine()
	logged.GET("/via-logged-factory", Handler)

	ambiguous := newAmbiguousEngine(true)
	ambiguous.GET("/never-inventoried", Handler)

	return r
}
