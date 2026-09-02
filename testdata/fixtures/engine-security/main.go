// Package enginesecurity exercises both docs/gin-security-rules.md rules and
// their negative/unresolved counterparts.
package enginesecurity

import (
	"os"

	"github.com/gin-gonic/gin"
)

// TrustAllProxiesIPv4 registers an all-address IPv4 CIDR. Expected finding:
// gin-explicit-trust-all-proxies.
func TrustAllProxiesIPv4() *gin.Engine {
	r := gin.New()
	_ = r.SetTrustedProxies([]string{"0.0.0.0/0"})
	return r
}

// TrustAllProxiesIPv6 registers an all-address IPv6 CIDR. Expected finding:
// gin-explicit-trust-all-proxies.
func TrustAllProxiesIPv6() *gin.Engine {
	r := gin.New()
	_ = r.SetTrustedProxies([]string{"::/0"})
	return r
}

// TrustSafeProxies registers only a specific, non-all-address CIDR.
// Expected: no finding.
func TrustSafeProxies() *gin.Engine {
	r := gin.New()
	_ = r.SetTrustedProxies([]string{"10.0.0.0/8"})
	return r
}

// TrustUnresolvedProxies passes a runtime-computed slice. This analyzer
// must not guess at its contents. Expected: diagnostic, no finding.
func TrustUnresolvedProxies(proxies []string) *gin.Engine {
	r := gin.New()
	_ = r.SetTrustedProxies(proxies)
	return r
}

// ExplicitDebugModeConst uses the named constant. Expected finding:
// gin-explicit-debug-mode.
func ExplicitDebugModeConst() {
	gin.SetMode(gin.DebugMode)
}

// ExplicitDebugModeLiteral uses the equivalent string literal directly.
// Expected finding: gin-explicit-debug-mode (same resolved constant value).
func ExplicitDebugModeLiteral() {
	gin.SetMode("debug")
}

// ExplicitReleaseMode selects release mode. Expected: no finding.
func ExplicitReleaseMode() {
	gin.SetMode(gin.ReleaseMode)
}

// UnresolvedMode reads the mode from the environment at runtime. This
// analyzer must not infer an environment value. Expected: diagnostic, no
// finding — and no finding for "absence of an explicit release-mode call"
// either, since none of these functions calling SetMode affects this one.
func UnresolvedMode() {
	gin.SetMode(os.Getenv("GIN_MODE"))
}
