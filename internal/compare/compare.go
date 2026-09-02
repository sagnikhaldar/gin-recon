// Package compare implements baseline report comparison (--baseline,
// --fail-on new|regression) per docs/report-contract.md. Product semantics
// (risk ordering, route-key deduplication to the least-safe view,
// structural regression explanations) are ported from express-recon's
// src/compare.js by explicit instruction, adapted to gin-recon's richer
// evidence fields (Tags/Roles/Scopes, canonical middleware chains) rather
// than re-derived from scratch. This package performs no analysis of its
// own — it only diffs two already-normalized report.Report values, and
// Compatible must be checked (and, on failure, the comparison rejected) by
// the caller before Compare is ever called; Compare itself trusts its
// inputs are comparable.
package compare

import (
	"fmt"
	"sort"
	"strings"

	"github.com/sagnikhaldar/gin-recon/internal/model"
	"github.com/sagnikhaldar/gin-recon/internal/report"
)

// authRisk mirrors express-recon's AUTH_RISK exactly: proven is least risky,
// public is most. A regression is a route's risk increasing; an improvement
// is it decreasing.
var authRisk = map[model.AuthStatus]int{
	model.AuthProven:  0,
	model.AuthUnknown: 1,
	model.AuthPublic:  2,
}

// Compatible checks whether baseline can be meaningfully compared against
// current, per docs/report-contract.md: "Require compatible schema major,
// analysis profile, route normalization, and build context." Route
// normalization has no version field of its own — it changes only when the
// report schema's own major version does, so a schema-major check already
// covers it. Returns a descriptive error rather than a bool specifically so
// the CLI can reject an incompatible baseline with an explanation instead
// of silently producing a misleading comparison.
func Compatible(baseline, current *report.Report) error {
	baselineMajor, ok := SchemaMajor(baseline.SchemaVersion)
	if !ok {
		return fmt.Errorf("baseline: unrecognized schemaVersion %q", baseline.SchemaVersion)
	}
	currentMajor, ok := SchemaMajor(current.SchemaVersion)
	if !ok {
		return fmt.Errorf("current report: unrecognized schemaVersion %q", current.SchemaVersion)
	}
	if baselineMajor != currentMajor {
		return fmt.Errorf("baseline schema major %q is not compatible with current schema major %q", baselineMajor, currentMajor)
	}
	if baseline.Command != report.CommandAudit {
		return fmt.Errorf("baseline must be an audit report, got command %q", baseline.Command)
	}
	if current.Command != report.CommandAudit {
		return fmt.Errorf("current report must be an audit report, got command %q", current.Command)
	}
	if baseline.AnalysisProfile != current.AnalysisProfile {
		return fmt.Errorf("baseline analysis profile %q does not match current profile %q", baseline.AnalysisProfile, current.AnalysisProfile)
	}
	if !buildContextEqual(baseline.Target.BuildContext, current.Target.BuildContext) {
		return fmt.Errorf("baseline build context (goos=%s goarch=%s tags=%v) does not match current (goos=%s goarch=%s tags=%v)",
			baseline.Target.BuildContext.GOOS, baseline.Target.BuildContext.GOARCH, baseline.Target.BuildContext.Tags,
			current.Target.BuildContext.GOOS, current.Target.BuildContext.GOARCH, current.Target.BuildContext.Tags)
	}
	return nil
}

// SchemaMajor extracts a report schemaVersion's major component (e.g. "1"
// from "1.0"). Exported so cmd/gin-recon's render command can apply the same
// schema-major compatibility check Compatible uses for --baseline, without
// requiring the loaded document to be an audit report the way Compatible
// itself does (render also accepts inventory-shaped reports).
func SchemaMajor(version string) (string, bool) {
	i := strings.Index(version, ".")
	if i <= 0 {
		return "", false
	}
	return version[:i], true
}

func buildContextEqual(a, b model.BuildContext) bool {
	return a.GOOS == b.GOOS && a.GOARCH == b.GOARCH &&
		a.ModuleMode == b.ModuleMode && a.WorkspaceMode == b.WorkspaceMode &&
		stringSlicesEqual(a.Tags, b.Tags)
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Compare computes the delta between baseline and current. Call Compatible
// first — Compare does not re-check compatibility itself.
func Compare(baseline, current *report.Report) *report.Delta {
	before := routeMap(baseline.Routes)
	after := routeMap(current.Routes)

	delta := &report.Delta{}
	for key := range after {
		if _, existed := before[key]; !existed {
			delta.AddedRoutes = append(delta.AddedRoutes, key)
		}
	}
	for key := range before {
		if _, exists := after[key]; !exists {
			delta.RemovedRoutes = append(delta.RemovedRoutes, key)
		}
	}
	sort.Strings(delta.AddedRoutes)
	sort.Strings(delta.RemovedRoutes)

	for key, curRoute := range after {
		prevRoute, existed := before[key]
		if !existed {
			continue
		}
		fromRisk, fromOK := riskOf(prevRoute)
		toRisk, toOK := riskOf(curRoute)
		if !fromOK || !toOK || fromRisk == toRisk {
			continue
		}
		change := report.AuthChange{
			Method:      curRoute.Method,
			Path:        curRoute.NormalizedPath,
			From:        authStatusOf(prevRoute),
			To:          authStatusOf(curRoute),
			Explanation: explainAuthChange(prevRoute, curRoute),
		}
		if toRisk > fromRisk {
			delta.AuthRegressions = append(delta.AuthRegressions, change)
		} else {
			delta.AuthImprovements = append(delta.AuthImprovements, change)
		}
	}
	sortAuthChanges(delta.AuthRegressions)
	sortAuthChanges(delta.AuthImprovements)

	beforeFindings := findingFingerprints(baseline.Findings)
	afterFindings := findingFingerprints(current.Findings)
	for fp := range afterFindings {
		if _, existed := beforeFindings[fp]; !existed {
			delta.NewFindings = append(delta.NewFindings, fp)
		}
	}
	for fp := range beforeFindings {
		if _, exists := afterFindings[fp]; !exists {
			delta.ResolvedFindings = append(delta.ResolvedFindings, fp)
		}
	}
	sort.Strings(delta.NewFindings)
	sort.Strings(delta.ResolvedFindings)

	return delta
}

func routeKey(r model.Route) string { return r.Method + " " + r.NormalizedPath }

// routeMap collapses duplicate route keys (a real, legitimate shape for
// gin-recon specifically — see the las-be-lms mutually-exclusive
// build-variant case docs/openapi-strategy.md's collision handling covers)
// to the least-safe (highest-risk) view, mirroring express-recon's
// routeMap exactly: a baseline/current diff must never let a safer
// duplicate registration mask a riskier one at the same method/path.
func routeMap(routes []model.Route) map[string]model.Route {
	m := make(map[string]model.Route, len(routes))
	for _, r := range routes {
		key := routeKey(r)
		existing, ok := m[key]
		risk, _ := riskOf(r)
		existingRisk := -2
		if ok {
			existingRisk, _ = riskOf(existing)
		}
		if !ok || risk > existingRisk {
			m[key] = r
		}
	}
	return m
}

func riskOf(r model.Route) (int, bool) {
	if r.Auth == nil {
		return 0, false
	}
	risk, ok := authRisk[r.Auth.AuthStatus]
	return risk, ok
}

func authStatusOf(r model.Route) model.AuthStatus {
	if r.Auth == nil {
		return ""
	}
	return r.Auth.AuthStatus
}

func sortAuthChanges(changes []report.AuthChange) {
	sort.SliceStable(changes, func(i, j int) bool {
		if changes[i].Path != changes[j].Path {
			return changes[i].Path < changes[j].Path
		}
		return changes[i].Method < changes[j].Method
	})
}

func findingFingerprints(findings []report.Finding) map[string]bool {
	set := make(map[string]bool, len(findings))
	for _, f := range findings {
		set[f.Fingerprint] = true
	}
	return set
}

// explainAuthChange ports express-recon's authenticationCause structural
// explanation, evaluated in the same priority order, using gin-recon's own
// evidence fields (Tags/Roles/Scopes from AuthClassification, middleware
// DisplayName from the resolved chain) in place of express-recon's raw
// middleware name/inner lists.
func explainAuthChange(before, after model.Route) string {
	beforeMW := middlewareDisplayNames(before)
	afterMW := middlewareDisplayNames(after)
	removedMW := difference(beforeMW, afterMW)

	var beforeTags, afterTags, beforeRoles, afterRoles, beforeScopes, afterScopes []string
	if before.Auth != nil {
		beforeTags, beforeRoles, beforeScopes = before.Auth.Tags, before.Auth.Roles, before.Auth.Scopes
	}
	if after.Auth != nil {
		afterTags, afterRoles, afterScopes = after.Auth.Tags, after.Auth.Roles, after.Auth.Scopes
	}
	removedTags := difference(beforeTags, afterTags)
	addedTags := difference(afterTags, beforeTags)
	removedGrants := append(difference(beforeRoles, afterRoles), difference(beforeScopes, afterScopes)...)
	addedGrants := append(difference(afterRoles, beforeRoles), difference(afterScopes, beforeScopes)...)

	switch {
	case len(removedTags) > 0:
		return "Recognized auth tag(s) removed: " + strings.Join(removedTags, ", ") + "."
	case len(addedTags) > 0:
		return "Recognized auth tag(s) added: " + strings.Join(addedTags, ", ") + "."
	case len(removedGrants) > 0:
		return "Authorization grant(s) removed: " + strings.Join(removedGrants, ", ") + "."
	case len(addedGrants) > 0:
		return "Authorization grant(s) added: " + strings.Join(addedGrants, ", ") + "."
	case len(removedMW) > 0:
		return "Middleware removed from the route chain: " + strings.Join(removedMW, ", ") + "."
	case after.Auth != nil && after.Auth.AuthStatus == model.AuthUnknown && (before.Auth == nil || before.Auth.AuthStatus != model.AuthUnknown):
		return "The route is now guarded only by middleware whose enforcement could not be confirmed."
	case sameMultiset(beforeMW, afterMW) && !stringSlicesEqual(beforeMW, afterMW):
		return "The middleware chain order changed alongside the authentication classification."
	default:
		return "Authentication classification changed without a visible route-level middleware difference; check authMiddleware configuration or shared mount wiring."
	}
}

func middlewareDisplayNames(r model.Route) []string {
	names := make([]string, len(r.Middleware))
	for i, mw := range r.Middleware {
		names[i] = mw.DisplayName
	}
	return names
}

// difference returns elements of before not present in after, deduplicated,
// order-preserving — mirrors express-recon's difference() (a set-based
// before-minus-after) exactly.
func difference(before, after []string) []string {
	afterSet := make(map[string]bool, len(after))
	for _, a := range after {
		afterSet[a] = true
	}
	seen := map[string]bool{}
	var out []string
	for _, b := range before {
		if afterSet[b] || seen[b] {
			continue
		}
		seen[b] = true
		out = append(out, b)
	}
	return out
}

func sameMultiset(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	counts := map[string]int{}
	for _, x := range a {
		counts[x]++
	}
	for _, x := range b {
		if counts[x] == 0 {
			return false
		}
		counts[x]--
	}
	return true
}
