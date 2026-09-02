// Package classify implements authentication classification: turning a
// route's discovered middleware chain plus reviewer-supplied configuration
// into the proven/public/unknown verdict ADR 0005 defines. It is the only
// package that decides AuthStatus — internal/analyzer/gin's Discover never
// makes a security judgment, and internal/analyzer/gin's AnalyzeEnforcement
// only ever answers the narrower, bounded "does this specific function's
// control flow match the ADR 0008 shape" question. Classify is where those
// two facts (a reviewer's configured trust, and the analyzer's independent
// control-flow evidence) are combined — deliberately kept separate exactly
// as ADR 0005 requires, so neither one alone can manufacture "proven."
package classify

import (
	"go/types"

	"github.com/sagnikhaldar/gin-recon/internal/analyzer/gin"
	"github.com/sagnikhaldar/gin-recon/internal/config"
	"github.com/sagnikhaldar/gin-recon/internal/model"
	"github.com/sagnikhaldar/gin-recon/internal/report"
)

// Inputs bundles everything Classify needs beyond the route list itself.
type Inputs struct {
	Config      *config.Config
	API         *gin.API
	FuncIndex   map[*types.Func]gin.FuncInfo
	SymbolIndex map[string]*types.Func

	// Profile is the analysis profile the routes were discovered under. It
	// exists solely so ClassifyAll can suppress stale-auth-config for
	// syntax-only (see its own doc comment): every syntax-only route has a
	// nil CanonicalSymbol on every middleware entry by construction, so
	// "never matched" would otherwise be indistinguishable from "matched but
	// unresolvable," and every configured authMiddleware/authWrappers entry
	// would spuriously report stale on every syntax-only audit regardless of
	// whether it is genuinely used. ClassifyRoute itself needs no profile
	// distinction: its own CanonicalSymbol==nil guard already makes a
	// syntax-only route classify exactly like any other unresolved-evidence
	// route, with no special-casing required.
	Profile model.AnalysisProfile
}

// Result is one route's classification plus any findings it produced.
// Findings are returned alongside rather than embedded in the route because
// a single route can produce more than one (e.g. a contradicted middleware
// finding and, independently, a public-route finding is not possible on the
// same route, but stale-auth-config findings are cross-route and reported
// once by ClassifyAll rather than per route).
type Result struct {
	Auth     model.AuthClassification
	Findings []report.Finding
}

// isOpaque reports whether a middleware entry could be hiding a check this
// analyzer cannot see through — an unresolved reference or an anonymous
// closure — per docs/threat-model.md's classification-safety rules.
func isOpaque(mw model.Middleware) bool {
	return mw.ResolutionStatus == model.Unresolved ||
		mw.CallableKind == model.CallableAnonymous ||
		mw.CallableKind == model.CallableUnknown
}

// matchedGuard is one middleware entry that matched a configured
// authMiddleware symbol, with its independently-computed enforcement
// evidence attached.
type matchedGuard struct {
	symbol      string
	entry       config.AuthMiddlewareEntry
	enforcement model.EnforcementAnalysis
}

// ClassifyRoute implements ADR 0005 for a single route. It only ever
// examines route.Middleware — not FinalHandler — since a "guard" is by
// definition something that runs before the handler; matching an
// authMiddleware symbol against the terminal handler itself is not a case
// docs/configuration-contract.md describes, and treating it as one would
// blur a distinction the rest of the schema depends on.
func ClassifyRoute(route model.Route, in Inputs) Result {
	var guards []matchedGuard
	sawOpaque := false

	for _, mw := range route.Middleware {
		if isOpaque(mw) {
			sawOpaque = true
		}
		if mw.CanonicalSymbol == nil {
			continue
		}
		if g, ok := matchGuardFor(*mw.CanonicalSymbol, in); ok {
			guards = append(guards, g)
			continue
		}
		// authWrappers: only an explicitly configured canonical wrapper —
		// reviewer-attested to always preserve and invoke a nested
		// middleware argument, per docs/configuration-contract.md — may
		// expose what it wraps as authentication evidence. mw.WrappedSymbols
		// is the bounded chain internal/analyzer/gin already resolved from
		// this call's own arguments (never a literal, never re-derived from
		// source here); this only ever walks that pre-resolved chain, and
		// only when the wrapper itself is on the list, so an arbitrary,
		// unconfigured call's arguments never become evidence.
		if !contains(in.Config.AuthWrappers, *mw.CanonicalSymbol) {
			continue
		}
		for _, wrapped := range mw.WrappedSymbols {
			if g, ok := matchGuardFor(wrapped, in); ok {
				guards = append(guards, g)
				break // the first configured guard found in the chain is the evidence; stop rather than keep unwrapping past it.
			}
		}
	}

	if len(guards) == 0 {
		return classifyUnmatched(route, sawOpaque, in)
	}
	return classifyMatched(route, guards, in)
}

// matchGuardFor resolves symbol into a matchedGuard exactly once: is it a
// configured authMiddleware entry at all, and if so, what does independent
// control-flow analysis say about its own enforcement shape. This is the
// single place both a direct middleware match and a wrapper-unwrapped match
// go through, so a guard discovered via authWrappers is classified by
// exactly the same rules (assurance, confirmed-shape/unresolved/contradicted)
// as one matched directly — wrapping changes how a guard is found, never
// what is required of it once found.
func matchGuardFor(symbol string, in Inputs) (matchedGuard, bool) {
	entry, configured := in.Config.AuthMiddleware[symbol]
	if !configured {
		return matchedGuard{}, false
	}
	enforcement := model.EnforcementUnresolved
	if fn, ok := in.SymbolIndex[symbol]; ok {
		enforcement = gin.AnalyzeEnforcement(in.FuncIndex, in.API, fn)
	}
	return matchedGuard{symbol: symbol, entry: entry, enforcement: enforcement}, true
}

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func classifyUnmatched(route model.Route, sawOpaque bool, in Inputs) Result {
	if sawOpaque {
		auth := model.AuthClassification{
			AuthStatus:          model.AuthUnknown,
			ClassificationBasis: "opaque-middleware-present",
			Confidence:          model.ConfidenceMedium,
		}
		return Result{Auth: auth, Findings: []report.Finding{
			newFinding(report.RuleOpaqueMiddleware, route, report.SeverityMedium,
				"the route's middleware chain contains an unresolved or anonymous entry that could be hiding an authentication check",
				"Name the middleware as a package-level function or method so it can be resolved, or configure it explicitly if it is a known guard."),
		}}
	}

	auth := model.AuthClassification{
		AuthStatus:          model.AuthPublic,
		ClassificationBasis: "no-configured-guard-matched",
		Confidence:          model.ConfidenceHigh,
	}
	if accepted, ok := acceptedPublicMatch(route, in.Config); ok {
		auth.Accepted = accepted
		return Result{Auth: auth} // accepted-public suppresses the public-route finding
	}
	return Result{Auth: auth, Findings: []report.Finding{
		newFinding(report.RulePublicRoute, route, report.SeverityMedium,
			"no configured authentication guard matched this route's middleware chain",
			"Add authentication middleware, or add this route to acceptedPublic if it is intentionally public."),
	}}
}

func classifyMatched(route model.Route, guards []matchedGuard, in Inputs) Result {
	var findings []report.Finding
	var proven *matchedGuard
	var contradicted *matchedGuard
	var unconfirmed *matchedGuard

	for i := range guards {
		g := &guards[i]
		assurance := g.entry.Assurance
		if assurance == "" {
			assurance = config.AssuranceAnalyze
		}
		switch g.enforcement {
		case model.EnforcementContradicted:
			if contradicted == nil {
				contradicted = g
			}
			findings = append(findings, newFinding(report.RuleMatchedButUnenforced, route, report.SeverityHigh,
				"configured guard \""+g.symbol+"\" matched by canonical symbol but its control flow provably never terminates the chain",
				"Remove this middleware from authMiddleware, or fix it to actually enforce a deny path."))
		case model.EnforcementConfirmedShape:
			if proven == nil {
				proven = g
			}
		case model.EnforcementUnresolved:
			if assurance == config.AssuranceAttested {
				if proven == nil {
					proven = g
				}
			} else if unconfirmed == nil {
				unconfirmed = g
			}
		}
	}

	if proven != nil {
		assurance := proven.entry.Assurance
		if assurance == "" {
			assurance = config.AssuranceAnalyze
		}
		basis := "configured-guard-confirmed"
		if proven.enforcement == model.EnforcementUnresolved {
			basis = "configured-guard-attested"
		}
		symbol := proven.symbol
		enforcement := proven.enforcement
		modelAssurance := toModelAssurance(assurance)
		return Result{Auth: model.AuthClassification{
			AuthStatus:          model.AuthProven,
			ClassificationBasis: basis,
			Assurance:           &modelAssurance,
			EnforcementAnalysis: &enforcement,
			MatchedEvidence:     &symbol,
			Confidence:          model.ConfidenceHigh,
			Tags:                proven.entry.Tags,
			Roles:               proven.entry.Roles,
			Scopes:              proven.entry.Scopes,
		}, Findings: findings}
	}

	// No guard reached "proven": pick the most actionable one to surface as
	// the primary matched evidence — a contradicted guard is a more urgent
	// signal than a merely-unresolved one.
	primary := contradicted
	if primary == nil {
		primary = unconfirmed
	}
	assurance := primary.entry.Assurance
	if assurance == "" {
		assurance = config.AssuranceAnalyze
	}
	basis := "configured-guard-unconfirmed"
	if primary.enforcement == model.EnforcementContradicted {
		basis = "configured-guard-contradicted"
	}
	symbol := primary.symbol
	enforcement := primary.enforcement
	modelAssurance := toModelAssurance(assurance)
	return Result{Auth: model.AuthClassification{
		AuthStatus:          model.AuthUnknown,
		ClassificationBasis: basis,
		Assurance:           &modelAssurance,
		EnforcementAnalysis: &enforcement,
		MatchedEvidence:     &symbol,
		Confidence:          model.ConfidenceMedium,
		Tags:                primary.entry.Tags,
		Roles:               primary.entry.Roles,
		Scopes:              primary.entry.Scopes,
	}, Findings: findings}
}

// toModelAssurance converts config.Assurance (the configuration format's
// type) to model.Assurance (the report format's type). They share the same
// two string values by design, but are deliberately distinct Go types since
// internal/config and internal/model serve different contracts that should
// not be coupled by accident through a shared type.
func toModelAssurance(a config.Assurance) model.Assurance {
	return model.Assurance(a)
}

// acceptedPublicMatch reports whether route appears in cfg.AcceptedPublic.
func acceptedPublicMatch(route model.Route, cfg *config.Config) (bool, bool) {
	want := route.Method + " " + route.NormalizedPath
	for _, entry := range cfg.AcceptedPublic {
		if entry == want {
			return true, true
		}
	}
	return false, false
}
