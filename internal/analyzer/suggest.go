// Package analyzer's SuggestAuth implements the `suggest-auth` command
// (docs/reference.md: "emit ranked canonical middleware candidates as
// JSON; suggestions never change classification"). It runs discovery (never
// Audit — suggest-auth has no notion of a configured authMiddleware list to
// classify against) and ranks every distinct, canonically-resolved
// middleware symbol by three purely structural, self-contained signals: a
// name-pattern hint, whether it is applied to every route or only a subset,
// and — when the typed profile resolved it to a real function — the same
// independent control-flow shape check gin.AnalyzeEnforcement already
// applies to a *configured* guard during classification (internal/classify),
// run here against every candidate instead. None of the three is a security
// judgment on its own: ADR-0005 ("Rejected Alternatives") is explicit that
// "abort/control-flow heuristics cannot identify auth without a configured
// symbol match" — a function that provably aborts under some condition may
// be a rate limiter, a feature flag, or a maintenance-mode check just as
// easily as an auth guard; EnforcementShape only ever ranks/informs a
// suggestion a human still has to add to --config before ClassifyRoute can
// ever call anything proven, it never classifies by itself. Per
// docs/threat-model.md ("never use the curated auth-middleware reference
// list to auto-promote a route — it only ranks suggest-auth output") and
// docs/auth-catalog.md, a governed, security-reviewed catalog of known Gin
// auth-adjacent middleware is a separate, not-yet-built enhancement
// requiring its own two-person review process with primary-source evidence
// per entry — this ranking deliberately does not fabricate one.
// knownNonAuthSymbols below is not that catalog: it only ever suppresses the
// hint for a small set of well-known framework/ecosystem plumbing with no
// auth semantics at all (Gin's own Recovery/Logger, gin-contrib/cors,
// gin-contrib/gzip), which needs far less evidentiary weight than
// affirmatively asserting something IS an auth guard — getting that wrong
// only makes an obviously-non-auth symbol rank slightly lower, never higher,
// and never creates or removes evidence.
package analyzer

import (
	"go/types"
	"regexp"
	"sort"
	"strings"

	"github.com/sagnikhaldar/gin-recon/internal/analyzer/gin"
	"github.com/sagnikhaldar/gin-recon/internal/model"
)

// AuthCandidate is one distinct, canonically-resolved middleware symbol seen
// across the inventory, ranked for a human/AI reviewer building an
// authMiddleware allowlist — never itself authentication evidence.
type AuthCandidate struct {
	CanonicalSymbol    string `json:"canonicalSymbol"`
	RouteCount         int    `json:"routeCount"`
	TotalRoutes        int    `json:"totalRoutes"`
	AppliesToAllRoutes bool   `json:"appliesToAllRoutes"`
	NameHint           bool   `json:"nameHint"`
	KnownNonAuth       bool   `json:"knownNonAuth"`
	// EnforcementShape is gin.AnalyzeEnforcement's own independent
	// control-flow judgment of this candidate's resolved function body —
	// empty when the typed profile could not resolve it to a real
	// function (syntax-only profile, or a symbol the loader never saw a
	// declaration for). See the package doc comment for why this can only
	// ever inform ranking, never classification.
	EnforcementShape model.EnforcementAnalysis `json:"enforcementShape,omitempty"`
	SampleRoutes     []string                  `json:"sampleRoutes"`
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

// authNameHintTarget is the part of a canonical symbol authNameHint actually
// matches against: the symbol's own package name plus its identifier
// (function, or (*Type).Method), with every import-path segment above the
// package itself stripped off. Matching the pattern against the full
// canonical symbol instead — module host, org, repository, and every
// intermediate directory — produces real false positives: a repository or
// directory whose own name happens to contain a hint substring (an
// "-otp-service" or "-auth-lib" repo, a "session/" directory) would flag
// every symbol inside it regardless of what that symbol's own name says,
// including plain plumbing like a Recovery or request logger that has
// nothing to do with authentication.
func authNameHintTarget(canonicalSymbol string) string {
	if i := strings.LastIndexByte(canonicalSymbol, '/'); i >= 0 {
		return canonicalSymbol[i+1:]
	}
	return canonicalSymbol
}

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
	result, api, funcIndex := discover(loaded)
	var symbolIndex map[string]*types.Func
	if api != nil {
		symbolIndex = BuildSymbolIndex(funcIndex)
	}

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
		var shape model.EnforcementAnalysis
		if fn, ok := symbolIndex[symbol]; ok {
			shape = gin.AnalyzeEnforcement(funcIndex, api, fn)
		}
		candidates = append(candidates, AuthCandidate{
			CanonicalSymbol:    symbol,
			RouteCount:         len(a.routes),
			TotalRoutes:        totalRoutes,
			AppliesToAllRoutes: totalRoutes > 0 && len(a.routes) == totalRoutes,
			NameHint:           !knownNonAuthSymbols[symbol] && authNameHint.MatchString(authNameHintTarget(symbol)),
			KnownNonAuth:       knownNonAuthSymbols[symbol],
			EnforcementShape:   shape,
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
// confirmedShapeFirst orders EnforcementConfirmedShape ahead of everything
// else (a real, independently-verified abort-under-some-condition shape is
// stronger evidence than a name pattern alone), EnforcementContradicted
// last (a provably abort-free function is positive evidence against being a
// real guard, not neutral), and EnforcementUnresolved — by far the most
// common case, everything the typed profile could not resolve at all —
// exactly where it already ranked before this signal existed.
func confirmedShapeFirst(shape model.EnforcementAnalysis) int {
	switch shape {
	case model.EnforcementConfirmedShape:
		return 0
	case model.EnforcementContradicted:
		return 2
	default:
		return 1
	}
}

func rankLess(a, b AuthCandidate) bool {
	if ra, rb := confirmedShapeFirst(a.EnforcementShape), confirmedShapeFirst(b.EnforcementShape); ra != rb {
		return ra < rb
	}
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
