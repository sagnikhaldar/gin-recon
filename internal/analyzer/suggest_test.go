package analyzer

import (
	"context"
	"runtime"
	"testing"

	"github.com/sagnikhaldar/gin-recon/internal/model"
)

func loadAndSuggestAuth(t *testing.T, fixture string) *SuggestAuthResult {
	t.Helper()
	loaded, err := Load(context.Background(), LoadOptions{
		Src:            fixtureDir(t, fixture),
		GOOS:           runtime.GOOS,
		GOARCH:         runtime.GOARCH,
		ModuleMode:     model.ModuleReadonly,
		AllowDownloads: true,
	})
	if err != nil {
		t.Fatalf("Load(%s): %v", fixture, err)
	}
	if len(loaded.LoadErrors) != 0 {
		t.Fatalf("Load(%s) reported load errors: %+v", fixture, loaded.LoadErrors)
	}
	return SuggestAuth(loaded)
}

func candidateFor(result *SuggestAuthResult, suffix string) *AuthCandidate {
	for i := range result.Candidates {
		if hasSuffix(result.Candidates[i].CanonicalSymbol, suffix) {
			return &result.Candidates[i]
		}
	}
	return nil
}

func TestSuggestAuthRanksNameHintedMiddlewareFirst(t *testing.T) {
	result := loadAndSuggestAuth(t, "middleware-order")

	if result.TotalRoutes != 3 {
		t.Fatalf("TotalRoutes = %d, want 3", result.TotalRoutes)
	}
	if len(result.Candidates) == 0 {
		t.Fatal("expected at least one candidate")
	}

	// RequireAuth/RequireAdmin must rank ahead of RequestID/RateLimit, which
	// have no auth-related name hint.
	authIdx, adminIdx, reqIDIdx, rateLimitIdx := -1, -1, -1, -1
	for i, c := range result.Candidates {
		switch {
		case hasSuffix(c.CanonicalSymbol, ".RequireAuth"):
			authIdx = i
		case hasSuffix(c.CanonicalSymbol, ".RequireAdmin"):
			adminIdx = i
		case hasSuffix(c.CanonicalSymbol, ".RequestID"):
			reqIDIdx = i
		case hasSuffix(c.CanonicalSymbol, ".RateLimit"):
			rateLimitIdx = i
		}
	}
	for name, idx := range map[string]int{"RequireAuth": authIdx, "RequireAdmin": adminIdx, "RequestID": reqIDIdx, "RateLimit": rateLimitIdx} {
		if idx == -1 {
			t.Fatalf("candidate %s not found; candidates: %+v", name, result.Candidates)
		}
	}
	if authIdx >= reqIDIdx || authIdx >= rateLimitIdx {
		t.Errorf("RequireAuth (idx %d) must rank ahead of RequestID (idx %d) and RateLimit (idx %d)", authIdx, reqIDIdx, rateLimitIdx)
	}
	if adminIdx >= reqIDIdx || adminIdx >= rateLimitIdx {
		t.Errorf("RequireAdmin (idx %d) must rank ahead of RequestID (idx %d) and RateLimit (idx %d)", adminIdx, reqIDIdx, rateLimitIdx)
	}

	auth := candidateFor(result, ".RequireAuth")
	if auth.NameHint != true {
		t.Errorf("RequireAuth.NameHint = %v, want true", auth.NameHint)
	}
	if auth.AppliesToAllRoutes {
		t.Errorf("RequireAuth.AppliesToAllRoutes = true, want false (only 2 of 3 routes)")
	}
	if auth.RouteCount != 2 {
		t.Errorf("RequireAuth.RouteCount = %d, want 2", auth.RouteCount)
	}

	reqID := candidateFor(result, ".RequestID")
	if reqID.NameHint {
		t.Errorf("RequestID.NameHint = true, want false (no auth-related name pattern)")
	}
}

func TestSuggestAuthNeverPopulatesRouteAuthClassification(t *testing.T) {
	// SuggestAuth must run pure Inventory, not Audit — a route's Auth field
	// must stay nil, proving suggestions cannot leak into classification.
	loaded, err := Load(context.Background(), LoadOptions{
		Src:            fixtureDir(t, "middleware-order"),
		GOOS:           runtime.GOOS,
		GOARCH:         runtime.GOARCH,
		ModuleMode:     model.ModuleReadonly,
		AllowDownloads: true,
	})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	_ = SuggestAuth(loaded)
	inv := Inventory(loaded)
	for _, r := range inv.Routes {
		if r.Auth != nil {
			t.Errorf("route %s %s has a non-nil Auth after SuggestAuth ran; suggest-auth must never classify", r.Method, r.NormalizedPath)
		}
	}
}

func TestSuggestAuthKnownNonAuthDenylistDoesNotOverclaim(t *testing.T) {
	// The denylist only ever suppresses a hint for framework/ecosystem
	// plumbing this analyzer is highly confident has no auth semantics — it
	// must never mark a fixture-local, user-defined symbol as known-non-auth.
	result := loadAndSuggestAuth(t, "middleware-order")
	for _, c := range result.Candidates {
		if c.KnownNonAuth {
			t.Errorf("candidate %s marked knownNonAuth, but this fixture defines no framework plumbing symbols", c.CanonicalSymbol)
		}
	}
}

func hasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}
