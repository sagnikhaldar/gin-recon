package classify

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/sagnikhaldar/gin-recon/internal/config"
	"github.com/sagnikhaldar/gin-recon/internal/model"
	"github.com/sagnikhaldar/gin-recon/internal/report"
)

// newFinding builds a Finding with a stable fingerprint. Per
// docs/report-contract.md, the fingerprint hashes rule identity plus
// normalized route identity and excludes source line and absolute checkout
// path — Source is attached for human navigation but deliberately excluded
// from the hash input, so moving a registration to a different line in the
// same file does not change the fingerprint.
func newFinding(ruleID report.RuleID, route model.Route, severity report.Severity, detail, recommendation string) report.Finding {
	routeIdentity := route.Method + " " + route.NormalizedPath
	fp := fingerprint(string(ruleID), routeIdentity)
	rec := recommendation
	return report.Finding{
		ID:             fp,
		RuleID:         ruleID,
		Fingerprint:    fp,
		Severity:       severity,
		Confidence:     model.ConfidenceHigh,
		Route:          &routeIdentity,
		Source:         route.Source,
		Detail:         detail,
		Recommendation: &rec,
	}
}

func fingerprint(parts ...string) string {
	h := sha256.New()
	h.Write([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(h.Sum(nil))
}

// AllResult is the merged output of classifying every route in a report,
// including the cross-route findings that cannot be computed per-route:
// stale-auth-config (a configured symbol that never matched anywhere) and
// stale-baseline (an acceptedPublic entry that no longer names a public
// route).
type AllResult struct {
	Findings []report.Finding
}

// ClassifyAll classifies every route in place (setting each Route.Auth) and
// returns the additional findings that require seeing the whole route set at
// once.
func ClassifyAll(routes []model.Route, in Inputs) AllResult {
	seenSymbols := map[string]bool{}
	var findings []report.Finding

	for i := range routes {
		for _, mw := range routes[i].Middleware {
			if mw.CanonicalSymbol != nil {
				seenSymbols[*mw.CanonicalSymbol] = true
			}
		}
		result := ClassifyRoute(routes[i], in)
		auth := result.Auth
		routes[i].Auth = &auth
		findings = append(findings, result.Findings...)
	}

	// stale-auth-config requires distinguishing "never matched anywhere" from
	// "matched but unresolvable" — a distinction syntax-only cannot make,
	// since every one of its routes has a nil CanonicalSymbol by
	// construction (see Inputs.Profile's doc comment). Suppressing it here
	// for syntax-only, per docs/report-contract.md, avoids every configured
	// authMiddleware/authWrappers entry spuriously reporting stale on every
	// syntax-only audit; internal/analyzer.AuditSyntax emits a single
	// coverage diagnostic in its place when auth config is configured at all.
	if in.Profile != model.ProfileSyntaxOnly {
		findings = append(findings, staleAuthConfigFindings(in.Config, seenSymbols)...)
	}
	findings = append(findings, staleBaselineFindings(routes, in.Config)...)
	findings = append(findings, perVerbGapFindings(routes)...)

	return AllResult{Findings: findings}
}

// staleAuthConfigFindings implements docs/report-contract.md's
// "stale-auth-config fires once per configured authMiddleware ... canonical
// symbol that is never matched against any resolved call site" — surfacing a
// target-side rename or removal as its own signal rather than only as routes
// silently becoming unknown.
func staleAuthConfigFindings(cfg *config.Config, seenSymbols map[string]bool) []report.Finding {
	var findings []report.Finding
	for symbol := range cfg.AuthMiddleware {
		if seenSymbols[symbol] {
			continue
		}
		sym := symbol
		fp := fingerprint(string(report.RuleStaleAuthConfig), symbol)
		rec := "Remove this entry from authMiddleware, or check whether the symbol was renamed or moved."
		findings = append(findings, report.Finding{
			ID:             fp,
			RuleID:         report.RuleStaleAuthConfig,
			Fingerprint:    fp,
			Severity:       report.SeverityMedium,
			Confidence:     model.ConfidenceHigh,
			Detail:         "configured authMiddleware symbol \"" + sym + "\" was never matched against any resolved middleware in the scanned code",
			Recommendation: &rec,
		})
	}
	return findings
}

// staleBaselineFindings implements the inverse case: an acceptedPublic entry
// that no longer names a route that is actually classified public (the
// route was removed, or it is now guarded).
func staleBaselineFindings(routes []model.Route, cfg *config.Config) []report.Finding {
	current := map[string]model.AuthStatus{}
	for _, r := range routes {
		if r.Auth != nil {
			current[r.Method+" "+r.NormalizedPath] = r.Auth.AuthStatus
		}
	}

	var findings []report.Finding
	for _, entry := range cfg.AcceptedPublic {
		status, exists := current[entry]
		if exists && status == model.AuthPublic {
			continue
		}
		e := entry
		fp := fingerprint(string(report.RuleStaleBaseline), entry)
		detail := "acceptedPublic entry \"" + e + "\" no longer matches a public route"
		if !exists {
			detail = "acceptedPublic entry \"" + e + "\" does not match any discovered route"
		}
		rec := "Remove this entry from acceptedPublic if the route was removed or is no longer intentionally public."
		findings = append(findings, report.Finding{
			ID:             fp,
			RuleID:         report.RuleStaleBaseline,
			Fingerprint:    fp,
			Severity:       report.SeverityLow,
			Confidence:     model.ConfidenceHigh,
			Detail:         detail,
			Recommendation: &rec,
		})
	}
	return findings
}

// perVerbGapFindings implements docs/report-contract.md's built-in
// per-verb-gap rule: the same normalized path registered with more than one
// distinct AuthStatus across its HTTP methods, which often indicates a
// guard applied to some verbs on a resource but missed on others — a
// classic write-path bypass (e.g. GET proven but DELETE public on the same
// resource). Mirrors express-recon's equivalent inconsistentPaths check,
// with one deliberate improvement: a route already accepted-public (via
// acceptedPublic, reviewed and intentionally open) does not itself count
// toward a gap, the same suppression already applied to public-route
// findings — an intentionally-open health check alongside a proven business
// endpoint on the same path is not a gap to keep re-flagging.
func perVerbGapFindings(routes []model.Route) []report.Finding {
	type verbEntry struct {
		method string
		status model.AuthStatus
	}
	byPath := map[string][]verbEntry{}
	var pathOrder []string
	for _, r := range routes {
		if r.Auth == nil || r.Auth.Accepted {
			continue
		}
		if _, seen := byPath[r.NormalizedPath]; !seen {
			pathOrder = append(pathOrder, r.NormalizedPath)
		}
		byPath[r.NormalizedPath] = append(byPath[r.NormalizedPath], verbEntry{r.Method, r.Auth.AuthStatus})
	}

	var findings []report.Finding
	for _, path := range pathOrder {
		entries := byPath[path]
		statuses := map[model.AuthStatus]bool{}
		for _, e := range entries {
			statuses[e.status] = true
		}
		if len(statuses) < 2 {
			continue
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].method < entries[j].method })

		summary := make([]string, len(entries))
		evidenceMethods := make([]map[string]any, len(entries))
		for i, e := range entries {
			summary[i] = e.method + "=" + string(e.status)
			evidenceMethods[i] = map[string]any{"method": e.method, "authStatus": string(e.status)}
		}

		p := path
		fp := fingerprint(string(report.RulePerVerbGap), p)
		rec := "Confirm whether every method on this path should share the same authentication requirement; add the missing guard, or move an intentionally-open method to acceptedPublic."
		findings = append(findings, report.Finding{
			ID:             fp,
			RuleID:         report.RulePerVerbGap,
			Fingerprint:    fp,
			Severity:       report.SeverityHigh,
			Confidence:     model.ConfidenceHigh,
			Detail:         "path \"" + p + "\" has inconsistent authentication across methods: " + strings.Join(summary, ", "),
			Recommendation: &rec,
			Evidence:       map[string]any{"normalizedPath": p, "methods": evidenceMethods},
		})
	}
	return findings
}
