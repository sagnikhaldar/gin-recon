// Package policy evaluates docs/configuration-contract.md's configured
// policies against already-classified routes (internal/classify runs first;
// policy evaluation only ever reads model.Route.Auth, it never sets it).
// This separation matters: a policy can require "auth: proven", but it
// cannot manufacture proven — that stays exclusively internal/classify's
// decision, per ADR 0005.
package policy

import (
	"time"

	"github.com/sagnikhaldar/gin-recon/internal/config"
	"github.com/sagnikhaldar/gin-recon/internal/model"
	"github.com/sagnikhaldar/gin-recon/internal/report"
)

// Result is Evaluate's output: every policy that was evaluated (for
// PolicyEvaluation.EvaluatedPolicies, regardless of whether it produced a
// finding) and the policy-violation findings themselves.
type Result struct {
	EvaluatedPolicies []string
	Findings          []report.Finding
}

// Evaluate runs every configured policy against every route. now is the
// current time in UTC (passed in, not read from the system clock here, so
// callers control it and tests stay deterministic) and decides which
// exceptions have expired.
func Evaluate(routes []model.Route, cfg *config.Config, now time.Time) Result {
	var findings []report.Finding
	evaluated := make([]string, 0, len(cfg.Policies))

	for _, p := range cfg.Policies {
		evaluated = append(evaluated, p.ID)
		for _, route := range routes {
			if !matchesSelector(route, p.Selector) {
				continue
			}
			if evaluateRequirement(route, p.Require) {
				continue // requirement satisfied: no violation
			}
			if exceptionApplies(route, p.Exceptions, now) {
				continue
			}
			findings = append(findings, newPolicyFinding(p.ID, route))
		}
	}

	return Result{EvaluatedPolicies: evaluated, Findings: findings}
}
