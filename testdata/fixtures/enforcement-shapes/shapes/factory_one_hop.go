package shapes

import (
	"net/http"

	"gin-recon-fixtures/enforcement-shapes/helper"

	"github.com/gin-gonic/gin"
)

// RequireAuthFactory mirrors the real-world JWTMiddleware/jwtMiddleware
// pattern exactly: an exported factory that immediately delegates to an
// unexported, same-package implementation, which is the one that actually
// returns the literal closure. This is ADR-0008's factory resolution at its
// one-hop boundary. Expected enforcementAnalysis: confirmed-shape.
func RequireAuthFactory(tokenType string) gin.HandlerFunc {
	return requireAuthImpl(tokenType)
}

func requireAuthImpl(tokenType string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetHeader("Authorization") == "" {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.Next()
	}
}

// RequireAuthFactoryTooDeep deleg through two function hops
// (RequireAuthFactoryTooDeep -> midLayer -> innerLayer) before reaching the
// literal, exceeding maxFactoryHops=1. Proves the boundary does not silently
// widen for factories the same way ADR-0008 already proves it for direct
// middleware delegation. Expected enforcementAnalysis: unresolved.
func RequireAuthFactoryTooDeep(tokenType string) gin.HandlerFunc {
	return midLayer(tokenType)
}

func midLayer(tokenType string) gin.HandlerFunc {
	return innerLayer(tokenType)
}

func innerLayer(tokenType string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetHeader("Authorization") == "" {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.Next()
	}
}

// RequireAuthFactoryCrossPackage delegates to a factory in another package.
// ADR-0008 permits only same-package delegation. Expected
// enforcementAnalysis: unresolved.
func RequireAuthFactoryCrossPackage(tokenType string) gin.HandlerFunc {
	return helper.MakeGuardFactory(tokenType)
}
