package policy

import (
	"testing"
	"time"

	"github.com/sagnikhaldar/gin-recon/internal/config"
	"github.com/sagnikhaldar/gin-recon/internal/model"
)

func TestPackageOf(t *testing.T) {
	for _, tc := range []struct{ symbol, want string }{
		{"example.com/project/internal/auth.RequireUser", "example.com/project/internal/auth"},
		{"example.com/project/internal/auth.(*Guard).RequireUser", "example.com/project/internal/auth"},
	} {
		if got := packageOf(tc.symbol); got != tc.want {
			t.Errorf("packageOf(%q) = %q, want %q", tc.symbol, got, tc.want)
		}
	}
}

func routeWithAuth(method, path string, status model.AuthStatus, tags, roles, scopes []string) model.Route {
	return model.Route{
		Method:         method,
		NormalizedPath: path,
		SurfaceKind:    model.SurfaceRoute,
		Auth: &model.AuthClassification{
			AuthStatus: status,
			Tags:       tags,
			Roles:      roles,
			Scopes:     scopes,
		},
	}
}

func TestMatchesSelectorANDsAcrossFields(t *testing.T) {
	route := routeWithAuth("GET", "/admin/users", model.AuthUnknown, []string{"internal"}, nil, nil)

	if !matchesSelector(route, config.PolicySelector{Method: []string{"GET"}, Path: []string{"/admin/**"}}) {
		t.Error("expected match on method+path")
	}
	if matchesSelector(route, config.PolicySelector{Method: []string{"POST"}, Path: []string{"/admin/**"}}) {
		t.Error("method mismatch should fail the whole selector")
	}
	if matchesSelector(route, config.PolicySelector{Method: []string{"GET"}, Tag: []string{"external"}}) {
		t.Error("tag mismatch should fail the whole selector")
	}
	if !matchesSelector(route, config.PolicySelector{Tag: []string{"internal", "external"}}) {
		t.Error("expected match: route has one of the OR'd tag values")
	}
}

func TestEvaluateRequirementAuthAndMiddleware(t *testing.T) {
	sym := "pkg.RequireAuth"
	route := model.Route{
		Auth:       &model.AuthClassification{AuthStatus: model.AuthProven},
		Middleware: []model.Middleware{{CanonicalSymbol: &sym, OrderingIndex: 0}},
	}

	if !evaluateRequirement(route, config.PolicyRequirement{Auth: "proven"}) {
		t.Error("expected auth requirement to pass")
	}
	if evaluateRequirement(route, config.PolicyRequirement{Auth: "public"}) {
		t.Error("expected auth requirement to fail")
	}
	if !evaluateRequirement(route, config.PolicyRequirement{MiddlewarePresent: []string{"pkg.RequireAuth"}}) {
		t.Error("expected middlewarePresent to pass")
	}
	if evaluateRequirement(route, config.PolicyRequirement{MiddlewarePresent: []string{"pkg.Other"}}) {
		t.Error("expected middlewarePresent to fail for an absent symbol")
	}
	if !evaluateRequirement(route, config.PolicyRequirement{MiddlewareAbsent: []string{"pkg.Other"}}) {
		t.Error("expected middlewareAbsent to pass")
	}
	if evaluateRequirement(route, config.PolicyRequirement{MiddlewareAbsent: []string{"pkg.RequireAuth"}}) {
		t.Error("expected middlewareAbsent to fail for a present symbol")
	}
	if !evaluateRequirement(route, config.PolicyRequirement{MiddlewareAny: []string{"pkg.RequireAuth", "pkg.Other"}}) {
		t.Error("expected middlewareAny to pass with one of two matching")
	}
}

func TestEvaluateRequirementMiddlewareOrder(t *testing.T) {
	symA, symB, symC := "pkg.A", "pkg.B", "pkg.C"
	route := model.Route{
		Middleware: []model.Middleware{
			{CanonicalSymbol: &symA, OrderingIndex: 0},
			{CanonicalSymbol: &symB, OrderingIndex: 1},
			{CanonicalSymbol: &symC, OrderingIndex: 2},
		},
	}
	if !evaluateRequirement(route, config.PolicyRequirement{MiddlewareOrder: []string{"pkg.A", "pkg.C"}}) {
		t.Error("expected order A before C to pass even with B between them")
	}
	if evaluateRequirement(route, config.PolicyRequirement{MiddlewareOrder: []string{"pkg.C", "pkg.A"}}) {
		t.Error("expected reversed order to fail")
	}
}

func TestEvaluateRequirementBooleanComposition(t *testing.T) {
	route := model.Route{Auth: &model.AuthClassification{AuthStatus: model.AuthProven, Roles: []string{"admin"}}}

	// all: both sub-requirements must pass
	all := config.PolicyRequirement{All: []config.PolicyRequirement{
		{Auth: "proven"}, {AnyRole: []string{"admin"}},
	}}
	if !evaluateRequirement(route, all) {
		t.Error("expected all[] to pass when both sub-requirements pass")
	}

	// any: at least one must pass
	any := config.PolicyRequirement{Any: []config.PolicyRequirement{
		{Auth: "public"}, {AnyRole: []string{"admin"}},
	}}
	if !evaluateRequirement(route, any) {
		t.Error("expected any[] to pass when one sub-requirement passes")
	}

	// not: negates
	not := config.PolicyRequirement{Not: &config.PolicyRequirement{Auth: "public"}}
	if !evaluateRequirement(route, not) {
		t.Error("expected not{auth:public} to pass for a proven route")
	}
}

func TestExceptionAppliesRespectsExpiryAndSelector(t *testing.T) {
	route := routeWithAuth("GET", "/legacy/endpoint", model.AuthUnknown, nil, nil, nil)
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)

	notExpired := []config.Exception{{
		ID: "e1", Reason: "reviewed",
		Selector: config.PolicySelector{Path: []string{"/legacy/**"}},
		Expires:  "2026-12-31",
	}}
	if !exceptionApplies(route, notExpired, now) {
		t.Error("expected a not-yet-expired, selector-matching exception to apply")
	}

	expired := []config.Exception{{
		ID: "e2", Reason: "reviewed",
		Selector: config.PolicySelector{Path: []string{"/legacy/**"}},
		Expires:  "2026-01-01",
	}}
	if exceptionApplies(route, expired, now) {
		t.Error("expected an expired exception to not apply")
	}

	wrongSelector := []config.Exception{{
		ID: "e3", Reason: "reviewed",
		Selector: config.PolicySelector{Path: []string{"/other/**"}},
		Expires:  "2026-12-31",
	}}
	if exceptionApplies(route, wrongSelector, now) {
		t.Error("expected a non-matching selector to not apply even though unexpired")
	}
}

func TestExceptionCoversThroughEndOfExpiryDayUTC(t *testing.T) {
	route := routeWithAuth("GET", "/legacy/endpoint", model.AuthUnknown, nil, nil, nil)
	exceptions := []config.Exception{{
		ID: "e1", Reason: "reviewed",
		Selector: config.PolicySelector{Path: []string{"/legacy/**"}},
		Expires:  "2026-06-15",
	}}
	lastMomentOfDay := time.Date(2026, 6, 15, 23, 59, 59, 0, time.UTC)
	if !exceptionApplies(route, exceptions, lastMomentOfDay) {
		t.Error("expected exception to still apply at 23:59:59 UTC on its expiry date")
	}
	nextDay := time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC)
	if exceptionApplies(route, exceptions, nextDay) {
		t.Error("expected exception to no longer apply the day after expiry")
	}
}

func TestEvaluateEndToEnd(t *testing.T) {
	routes := []model.Route{
		routeWithAuth("GET", "/admin/users", model.AuthUnknown, nil, nil, nil),
		routeWithAuth("GET", "/admin/settings", model.AuthProven, nil, nil, nil),
		routeWithAuth("GET", "/public/health", model.AuthPublic, nil, nil, nil),
	}
	cfg := &config.Config{
		Policies: []config.Policy{{
			ID:       "admin-requires-auth",
			Selector: config.PolicySelector{Path: []string{"/admin/**"}},
			Require:  config.PolicyRequirement{Auth: "proven"},
		}},
	}
	now := time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC)

	result := Evaluate(routes, cfg, now)
	if len(result.EvaluatedPolicies) != 1 || result.EvaluatedPolicies[0] != "admin-requires-auth" {
		t.Errorf("EvaluatedPolicies = %v, want [admin-requires-auth]", result.EvaluatedPolicies)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(result.Findings), result.Findings)
	}
	if result.Findings[0].Route == nil || *result.Findings[0].Route != "GET /admin/users" {
		t.Errorf("finding route = %v, want GET /admin/users", result.Findings[0].Route)
	}
}

func TestEvaluateSuppressedByException(t *testing.T) {
	routes := []model.Route{routeWithAuth("GET", "/admin/users", model.AuthUnknown, nil, nil, nil)}
	cfg := &config.Config{
		Policies: []config.Policy{{
			ID:       "admin-requires-auth",
			Selector: config.PolicySelector{Path: []string{"/admin/**"}},
			Require:  config.PolicyRequirement{Auth: "proven"},
			Exceptions: []config.Exception{{
				ID: "e1", Reason: "reviewed",
				Selector: config.PolicySelector{Path: []string{"/admin/**"}},
				Expires:  "2026-12-31",
			}},
		}},
	}
	now := time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC)

	result := Evaluate(routes, cfg, now)
	if len(result.Findings) != 0 {
		t.Errorf("expected exception to suppress the finding, got: %+v", result.Findings)
	}
}
