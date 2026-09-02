package policy

import (
	"github.com/sagnikhaldar/gin-recon/internal/config"
	"github.com/sagnikhaldar/gin-recon/internal/model"
)

// evaluateRequirement reports whether route satisfies req. Every populated
// field must pass (fields AND together); All/Any/Not recurse. Config
// decoding already bounds recursion depth (internal/config's Validate), so
// this does not re-check depth — a Requirement that reached here already
// passed that bound.
func evaluateRequirement(route model.Route, req config.PolicyRequirement) bool {
	if req.Auth != "" && (route.Auth == nil || string(route.Auth.AuthStatus) != req.Auth) {
		return false
	}
	if len(req.MiddlewareAny) > 0 && !hasAny(routeMiddlewareSymbols(route), req.MiddlewareAny) {
		return false
	}
	if len(req.MiddlewarePresent) > 0 && !hasAll(routeMiddlewareSymbols(route), req.MiddlewarePresent) {
		return false
	}
	if len(req.MiddlewareAbsent) > 0 && hasAny(routeMiddlewareSymbols(route), req.MiddlewareAbsent) {
		return false
	}
	if len(req.MiddlewareOrder) > 0 && !middlewareInOrder(route, req.MiddlewareOrder) {
		return false
	}
	if len(req.AnyTag) > 0 && !hasAny(routeTags(route), req.AnyTag) {
		return false
	}
	if len(req.AllTags) > 0 && !hasAll(routeTags(route), req.AllTags) {
		return false
	}
	if len(req.AnyRole) > 0 && !hasAny(routeRoles(route), req.AnyRole) {
		return false
	}
	if len(req.AnyScope) > 0 && !hasAny(routeScopes(route), req.AnyScope) {
		return false
	}
	for _, sub := range req.All {
		if !evaluateRequirement(route, sub) {
			return false
		}
	}
	if len(req.Any) > 0 {
		anyPassed := false
		for _, sub := range req.Any {
			if evaluateRequirement(route, sub) {
				anyPassed = true
				break
			}
		}
		if !anyPassed {
			return false
		}
	}
	if req.Not != nil && evaluateRequirement(route, *req.Not) {
		return false
	}
	return true
}

func hasAll(have, want []string) bool {
	for _, w := range want {
		if !contains(have, w) {
			return false
		}
	}
	return true
}

func routeMiddlewareSymbols(route model.Route) []string {
	symbols := make([]string, 0, len(route.Middleware))
	for _, mw := range route.Middleware {
		if mw.CanonicalSymbol != nil {
			symbols = append(symbols, *mw.CanonicalSymbol)
		}
	}
	return symbols
}

// middlewareInOrder reports whether the canonical symbols in want each
// appear in route.Middleware and in that relative order (not necessarily
// adjacent — other middleware may appear between them).
func middlewareInOrder(route model.Route, want []string) bool {
	positions := map[string]int{}
	for _, mw := range route.Middleware {
		if mw.CanonicalSymbol != nil {
			positions[*mw.CanonicalSymbol] = mw.OrderingIndex
		}
	}
	last := -1
	for _, w := range want {
		pos, ok := positions[w]
		if !ok || pos <= last {
			return false
		}
		last = pos
	}
	return true
}
