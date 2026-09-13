package analyzer

import (
	"context"
	"runtime"
	"strings"
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

func TestAuthNameHintTargetIgnoresUnrelatedImportPathSegments(t *testing.T) {
	cases := []struct {
		symbol string
		want   bool
	}{
		// Real bug found reviewing real fleet-auth-candidates.json output:
		// a repository named "sc-platform-otp-service" made every symbol in
		// it hint true, including plain Recovery/logging middleware, purely
		// because "otp-service" contains "otp" — nothing to do with the
		// symbol's own name.
		{"github.com/smallcase/sc-platform-otp-service/api/routes/middleware.CustomRecovery", false},
		{"github.com/smallcase/sc-platform-otp-service/api/routes/middleware.RequestResponseLogger", false},
		// The package's own name still counts: this is a deliberate,
		// meaningful part of the symbol's identity, unlike a repository name
		// or an unrelated ancestor directory.
		{"github.com/example/auth.Handle", true},
		// A genuine auth-named identifier still hints true regardless of
		// where it lives.
		{"github.com/smallcase/las-be-unity/internal/api/ops.(*OpsAPI).VendorAuthMiddleware", true},
		{"github.com/gin-gonic/gin.RequestID", false},
	}
	for _, tc := range cases {
		got := authNameHint.MatchString(authNameHintTarget(tc.symbol))
		if got != tc.want {
			t.Errorf("authNameHint on authNameHintTarget(%q) = %v, want %v", tc.symbol, got, tc.want)
		}
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

// TestSuggestAuthExcerptIncludesDelegatedAbortBody guards a real evidence
// gap in suggest-auth's own output (not just gin.EnforcementExcerpt in
// isolation): a reviewer reading RequireAuthFactory's own candidate must see
// the actual abort statement gin.AnalyzeEnforcement's confirmed-shape
// verdict is based on, not just the delegating factory call — this fixture's
// own doc comment says it "mirrors the real-world JWTMiddleware/
// jwtMiddleware pattern exactly", the real production case that first
// surfaced this gap.
func TestSuggestAuthExcerptIncludesDelegatedAbortBody(t *testing.T) {
	result := loadAndSuggestAuth(t, "enforcement-shapes")
	candidate := candidateFor(result, ".RequireAuthFactory")
	if candidate == nil {
		t.Fatalf("RequireAuthFactory not found; candidates: %+v", result.Candidates)
	}
	if !strings.Contains(candidate.Excerpt, "func RequireAuthFactory(") {
		t.Errorf("excerpt missing RequireAuthFactory's own declaration:\n%s", candidate.Excerpt)
	}
	if !strings.Contains(candidate.Excerpt, "func requireAuthImpl(") {
		t.Errorf("excerpt missing the delegated requireAuthImpl declaration whose body actually aborts:\n%s", candidate.Excerpt)
	}
	if !strings.Contains(candidate.Excerpt, "AbortWithStatus") {
		t.Errorf("excerpt missing the actual abort statement confirmed-shape is based on:\n%s", candidate.Excerpt)
	}
}

// TestSuggestAuthEnforcementShapeOutranksNameHintAlone guards the real new
// capability EnforcementShape adds: a middleware whose own code has a
// genuine, independently-verified direct-abort shape must rank ahead of a
// name-hinted middleware whose code is provably a no-op — code-shape
// evidence outranking a name pattern alone is exactly the point (see
// suggest.go's package doc comment on why this stays a ranking signal, never
// a classification one).
func TestSuggestAuthEnforcementShapeOutranksNameHintAlone(t *testing.T) {
	result := loadAndSuggestAuth(t, "mw-shape-signal")

	header := candidateFor(result, ".CheckHeaderPresence")
	logger := candidateFor(result, ".AuthLogger")
	if header == nil || logger == nil {
		t.Fatalf("expected both candidates; got: %+v", result.Candidates)
	}

	if header.NameHint {
		t.Errorf("CheckHeaderPresence.NameHint = true, want false (its name matches no auth pattern)")
	}
	if header.EnforcementShape != model.EnforcementConfirmedShape {
		t.Errorf("CheckHeaderPresence.EnforcementShape = %q, want %q", header.EnforcementShape, model.EnforcementConfirmedShape)
	}
	if !logger.NameHint {
		t.Errorf("AuthLogger.NameHint = false, want true (its name matches \"auth\")")
	}
	if logger.EnforcementShape != model.EnforcementContradicted {
		t.Errorf("AuthLogger.EnforcementShape = %q, want %q", logger.EnforcementShape, model.EnforcementContradicted)
	}

	headerIdx, loggerIdx := -1, -1
	for i, c := range result.Candidates {
		switch {
		case hasSuffix(c.CanonicalSymbol, ".CheckHeaderPresence"):
			headerIdx = i
		case hasSuffix(c.CanonicalSymbol, ".AuthLogger"):
			loggerIdx = i
		}
	}
	if headerIdx >= loggerIdx {
		t.Errorf("CheckHeaderPresence (confirmed-shape, no name hint, idx %d) must rank ahead of AuthLogger (name hint, contradicted, idx %d)", headerIdx, loggerIdx)
	}
}

func hasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}
