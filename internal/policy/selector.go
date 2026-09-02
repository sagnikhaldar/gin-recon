package policy

import (
	"strings"

	"github.com/sagnikhaldar/gin-recon/internal/config"
	"github.com/sagnikhaldar/gin-recon/internal/globmatch"
	"github.com/sagnikhaldar/gin-recon/internal/model"
)

// matchesSelector reports whether route matches every populated field of
// sel. An empty/omitted field always matches (it narrows nothing); a
// populated field matches if the route satisfies at least one of its listed
// values — fields AND together, values within a field OR together, matching
// docs/configuration-contract.md's "Policy selectors may use methods, path
// globs, auth statuses, tags, roles, scopes, canonical package prefixes, and
// surface kinds."
func matchesSelector(route model.Route, sel config.PolicySelector) bool {
	if len(sel.Method) > 0 && !containsFold(sel.Method, route.Method) {
		return false
	}
	if len(sel.Path) > 0 && !globmatch.Any(sel.Path, route.NormalizedPath) {
		return false
	}
	if len(sel.Status) > 0 {
		if route.Auth == nil || !contains(sel.Status, string(route.Auth.AuthStatus)) {
			return false
		}
	}
	if len(sel.Tag) > 0 && !hasAny(routeTags(route), sel.Tag) {
		return false
	}
	if len(sel.Role) > 0 && !hasAny(routeRoles(route), sel.Role) {
		return false
	}
	if len(sel.Scope) > 0 && !hasAny(routeScopes(route), sel.Scope) {
		return false
	}
	if len(sel.Package) > 0 && !anyPackagePrefixMatch(sel.Package, route) {
		return false
	}
	if len(sel.SurfaceKind) > 0 && !contains(sel.SurfaceKind, string(route.SurfaceKind)) {
		return false
	}
	return true
}

func routeTags(route model.Route) []string {
	if route.Auth == nil {
		return nil
	}
	return route.Auth.Tags
}

func routeRoles(route model.Route) []string {
	if route.Auth == nil {
		return nil
	}
	return route.Auth.Roles
}

func routeScopes(route model.Route) []string {
	if route.Auth == nil {
		return nil
	}
	return route.Auth.Scopes
}

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func containsFold(values []string, want string) bool {
	for _, v := range values {
		if strings.EqualFold(v, want) {
			return true
		}
	}
	return false
}

func hasAny(have, want []string) bool {
	for _, w := range want {
		if contains(have, w) {
			return true
		}
	}
	return false
}

// anyPackagePrefixMatch checks the route's final handler canonical symbol's
// package path (falling back to any middleware's, in registration order)
// against each pattern as a prefix — "canonical package prefixes" per
// docs/configuration-contract.md.
func anyPackagePrefixMatch(patterns []string, route model.Route) bool {
	symbols := make([]string, 0, len(route.Middleware)+1)
	if route.FinalHandler.CanonicalSymbol != nil {
		symbols = append(symbols, *route.FinalHandler.CanonicalSymbol)
	}
	for _, mw := range route.Middleware {
		if mw.CanonicalSymbol != nil {
			symbols = append(symbols, *mw.CanonicalSymbol)
		}
	}
	for _, sym := range symbols {
		pkg := packageOf(sym)
		for _, pattern := range patterns {
			if strings.HasPrefix(pkg, pattern) {
				return true
			}
		}
	}
	return false
}

// packageOf extracts the package path portion of a canonical symbol
// ("pkg/path.Func" or "pkg/path.(*Type).Method"), matching the two formats
// internal/analyzer/gin.FuncCanonicalSymbol produces.
func packageOf(symbol string) string {
	if i := strings.Index(symbol, ".("); i >= 0 {
		return symbol[:i]
	}
	if i := strings.LastIndex(symbol, "."); i >= 0 {
		return symbol[:i]
	}
	return symbol
}
