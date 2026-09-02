// Package authwrappers exercises authWrappers classification per
// docs/configuration-contract.md: "authWrappers contains canonical factories
// proven by review to preserve and always invoke a nested middleware
// argument." Only an explicitly configured canonical wrapper may expose its
// wrapped argument as authentication evidence — an arbitrary, unconfigured
// call must never become transparent, and wrapping never changes what is
// required of the guard once found (confirmed-shape/unresolved/contradicted,
// assurance modes apply identically to a wrapper-discovered guard).
package authwrappers

import "github.com/gin-gonic/gin"

func Handler(c *gin.Context) { c.Status(200) }

func authenticated(c *gin.Context) bool { return c.GetHeader("Authorization") != "" }

// RequireAuth is a direct-abort guard — confirmed-shape under default assurance.
func RequireAuth(c *gin.Context) {
	if !authenticated(c) {
		c.AbortWithStatus(401)
		return
	}
	c.Next()
}

// RequireAuthContradicted matches enforcement-shapes/shapes/
// contradicted_passthrough.go's RequireAuthAlwaysPasses exactly: its body
// only ever calls its own *gin.Context parameter's methods (never an
// unrelated helper, which ADR 0008's bounded contradiction proof requires
// to keep the body fully self-contained and visible) and never calls
// Abort/AbortWithStatus*/AbortWithError anywhere — provably abort-free.
func RequireAuthContradicted(c *gin.Context) {
	c.Set("checked", true)
	c.Next()
}

// RequireRoleFactory is a factory-shaped guard: the returned closure is what
// gets registered/wrapped, and "role" (its argument) is never part of its
// canonical identity, per docs/configuration-contract.md — matching the
// enforcement-shapes fixture's own factory pattern, reused here wrapped.
func RequireRoleFactory(role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetHeader("X-Role") != role {
			c.AbortWithStatus(403)
			return
		}
		c.Next()
	}
}

// LoggedAuth is a positive wrapper: it unconditionally invokes its argument,
// nothing conditional around the call.
func LoggedAuth(inner gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		inner(c)
	}
}

// ConditionalWrapper only invokes its argument for GET requests. It is
// deliberately NOT configured as an authWrapper anywhere in this fixture's
// tests, proving an arbitrary call's wrapped argument never becomes
// evidence just because it happens to be named/resolved — only an
// explicitly reviewed, configured wrapper may expose one.
func ConditionalWrapper(inner gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method == "GET" {
			inner(c)
		}
	}
}

func NewRouter() *gin.Engine {
	r := gin.New()

	// Positive: LoggedAuth (configured authWrapper) wraps RequireAuth (a
	// real, confirmed-shape guard) — must classify proven.
	r.GET("/wrapped/positive", LoggedAuth(RequireAuth), Handler)

	// Negative: LoggedAuth wraps a plain, non-guard function. No configured
	// authMiddleware entry matches the wrapped symbol, so this stays public,
	// exactly as if unwrapped.
	r.GET("/wrapped/negative", LoggedAuth(Handler), Handler)

	// Opaque wrapper: ConditionalWrapper (NOT a configured authWrapper)
	// wraps RequireAuth. Because the wrapper itself is not on the
	// reviewer-configured list, RequireAuth must not be exposed as
	// evidence — the route must stay public, never silently proven, no
	// matter what the unconfigured wrapper's own runtime behavior is.
	r.GET("/wrapped/opaque", ConditionalWrapper(RequireAuth), Handler)

	// Nested: two literal hops of the same configured wrapper
	// (LoggedAuth(LoggedAuth(RequireAuth))) written directly at the
	// registration call site — proves the bounded chain walk resolves past
	// one level of wrapping, not just a single hop.
	r.GET("/wrapped/nested", LoggedAuth(LoggedAuth(RequireAuth)), Handler)

	// Factory: LoggedAuth wraps a factory-produced closure
	// (RequireRoleFactory("admin")). The factory's own canonical symbol
	// (RequireRoleFactory) is what resolves — "admin" is discarded, per
	// docs/configuration-contract.md — proving wrapper-unwrapping composes
	// correctly with the existing factory-closure handling.
	r.GET("/wrapped/factory", LoggedAuth(RequireRoleFactory("admin")), Handler)

	// Contradicted wrapper: LoggedAuth (configured wrapper) wraps
	// RequireAuthContradicted (configured authMiddleware, but its own
	// enforcement is provably a no-op). Must stay unknown with a
	// matched-but-unenforced finding — wrapping never promotes a
	// contradicted guard to proven, under any assurance mode.
	r.GET("/wrapped/contradicted", LoggedAuth(RequireAuthContradicted), Handler)

	return r
}
