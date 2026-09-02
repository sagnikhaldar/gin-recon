// Package analyzer's SuggestAuth implements the `suggest-auth` command
// (docs/cli-contract.md: "emit ranked canonical middleware candidates as
// JSON; suggestions never change classification"). It runs Inventory (never
// Audit — suggest-auth has no notion of a configured authMiddleware list to
// classify against) and ranks every distinct, canonically-resolved
// middleware symbol by two purely structural, self-contained signals: a
// name-pattern hint, and whether it is applied to every route or only a
// subset. Neither signal is a security judgment. Per docs/threat-model.md
// ("never use the curated auth-middleware reference list to auto-promote a
// route — it only ranks suggest-auth output") and docs/auth-catalog.md, a
// governed, security-reviewed catalog of known Gin auth-adjacent middleware
// is a separate, not-yet-built enhancement requiring its own two-person
// review process with primary-source evidence per entry — this v1 ranking
// deliberately does not fabricate one. knownNonAuthSymbols below is not that
// catalog: it only ever suppresses the hint for a small set of well-known
// framework/ecosystem plumbing with no auth semantics at all (Gin's own
// Recovery/Logger, gin-contrib/cors, gin-contrib/gzip), which needs far less
// evidentiary weight than affirmatively asserting something IS an auth
// guard — getting that wrong only makes an obviously-non-auth symbol rank
// slightly lower, never higher, and never creates or removes evidence.
package analyzer

import (
	"regexp"
	"sort"

	"github.com/sagnikhaldar/gin-recon/internal/model"
)

// AuthCandidate is one distinct, canonically-resolved middleware symbol seen
// across the inventory, ranked for a human/AI reviewer building an
// authMiddleware allowlist — never itself authentication evidence.
type AuthCandidate struct {
	CanonicalSymbol    string   `json:"canonicalSymbol"`
	RouteCount         int      `json:"routeCount"`
	TotalRoutes        int      `json:"totalRoutes"`
	AppliesToAllRoutes bool     `json:"appliesToAllRoutes"`
	NameHint           bool     `json:"nameHint"`
	KnownNonAuth       bool     `json:"knownNonAuth"`
	SampleRoutes       []string `json:"sampleRoutes"`
}

// SuggestAuthResult is the whole `suggest-auth` JSON output.
type SuggestAuthResult struct {
	Module           string             `json:"module"`
	TotalRoutes      int                `json:"totalRoutes"`
	Candidates       []AuthCandidate    `json:"candidates"`
	OpaqueMiddleware int                `json:"opaqueMiddleware"`
	ScanCoverage     model.ScanCoverage `json:"scanCoverage"`
}

// authNameHint matches common naming conventions for authentication,
// authorization, and adjacent concerns (sessions, signatures/webhooks, rate
// limiting by identity) across the Gin ecosystem's own naming conventions —
// a structural hint only, per the package doc comment.
var authNameHint = regexp.MustCompile(`(?i)auth|login|logout|token|session|verify|guard|require|permit|acl|jwt|bearer|csrf|xsrf|role|scope|rbac|api[-_]?key|apikey|protect|admin|sso|saml|oidc|signature|hmac|otp|mfa|whitelist|allowlist`)

// knownNonAuthSymbols are well-known Gin ecosystem plumbing canonical
// symbols with no auth semantics at all — see the package doc comment for
// why this denylist needs far less evidentiary weight than an allowlist
// would, and is not the governed catalog docs/auth-catalog.md describes.
var knownNonAuthSymbols = map[string]bool{
	"github.com/gin-gonic/gin.Recovery":            true,
	"github.com/gin-gonic/gin.RecoveryWithWriter":  true,
	"github.com/gin-gonic/gin.CustomRecovery":      true,
	"github.com/gin-gonic/gin.Logger":              true,
	"github.com/gin-gonic/gin.LoggerWithConfig":    true,
	"github.com/gin-gonic/gin.LoggerWithFormatter": true,
	"github.com/gin-gonic/gin.LoggerWithWriter":    true,
	"github.com/gin-contrib/cors.Default":          true,
	"github.com/gin-contrib/cors.New":              true,
	"github.com/gin-contrib/gzip.Gzip":             true,
	"github.com/gin-contrib/requestid.New":         true,
}

// SuggestAuth runs discovery (never classification) and ranks every
// distinct canonical middleware symbol seen across the module's routes.
// Middleware that never resolved to a canonical symbol (anonymous or
// otherwise unresolved) cannot become a config key at all — an
// authMiddleware entry is keyed by canonical symbol — so it is counted
// separately as OpaqueMiddleware rather than listed as a candidate a user
// could not actually paste into configuration.
func SuggestAuth(loaded *Loaded) *SuggestAuthResult {
	result := Inventory(loaded)

	type acc struct {
		routes map[string]bool
	}
	bySymbol := map[string]*acc{}
	opaque := 0

	record := func(symbol *string, routeIdentity string) {
		if symbol == nil {
			opaque++
			return
		}
		a, ok := bySymbol[*symbol]
		if !ok {
			a = &acc{routes: map[string]bool{}}
			bySymbol[*symbol] = a
		}
		if routeIdentity != "" {
			a.routes[routeIdentity] = true
		}
	}

	for _, r := range result.Routes {
		identity := r.Method + " " + r.NormalizedPath
		for _, mw := range r.Middleware {
			record(mw.CanonicalSymbol, identity)
		}
	}
	for _, mw := range result.GlobalMiddleware {
		record(mw.CanonicalSymbol, "")
	}

	totalRoutes := len(result.Routes)
	candidates := make([]AuthCandidate, 0, len(bySymbol))
	for symbol, a := range bySymbol {
		samples := make([]string, 0, len(a.routes))
		for route := range a.routes {
			samples = append(samples, route)
		}
		sort.Strings(samples)
		if len(samples) > 5 {
			samples = samples[:5]
		}
		candidates = append(candidates, AuthCandidate{
			CanonicalSymbol:    symbol,
			RouteCount:         len(a.routes),
			TotalRoutes:        totalRoutes,
			AppliesToAllRoutes: totalRoutes > 0 && len(a.routes) == totalRoutes,
			NameHint:           !knownNonAuthSymbols[symbol] && authNameHint.MatchString(symbol),
			KnownNonAuth:       knownNonAuthSymbols[symbol],
			SampleRoutes:       samples,
		})
	}
	sort.SliceStable(candidates, func(i, j int) bool { return rankLess(candidates[i], candidates[j]) })

	return &SuggestAuthResult{
		Module:           result.Module,
		TotalRoutes:      totalRoutes,
		Candidates:       candidates,
		OpaqueMiddleware: opaque,
		ScanCoverage:     result.ScanCoverage,
	}
}

// rankLess orders likely-auth hints first, known plumbing last, partial
// route coverage before whole-inventory coverage (a guard on a subset of
// routes is more often the interesting case than one applied everywhere,
// which is more often session/logging/tracing plumbing), then by symbol for
// full determinism.
func rankLess(a, b AuthCandidate) bool {
	if a.NameHint != b.NameHint {
		return a.NameHint
	}
	if a.KnownNonAuth != b.KnownNonAuth {
		return b.KnownNonAuth
	}
	if a.AppliesToAllRoutes != b.AppliesToAllRoutes {
		return b.AppliesToAllRoutes
	}
	if a.RouteCount != b.RouteCount {
		return a.RouteCount < b.RouteCount
	}
	return a.CanonicalSymbol < b.CanonicalSymbol
}
