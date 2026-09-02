package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/sagnikhaldar/gin-recon/internal/model"
	"github.com/sagnikhaldar/gin-recon/internal/report"
)

// newPolicyFinding builds a policy-violation finding. Fingerprints hash rule
// identity, the policy ID, and normalized route identity — excluding source
// line and absolute checkout path, matching the same stability rule
// internal/classify's fingerprints follow (docs/report-contract.md).
func newPolicyFinding(policyID string, route model.Route) report.Finding {
	routeIdentity := route.Method + " " + route.NormalizedPath
	h := sha256.New()
	h.Write([]byte(strings.Join([]string{string(report.RulePolicyViolation), policyID, routeIdentity}, "|")))
	fp := hex.EncodeToString(h.Sum(nil))
	rec := "Bring this route into compliance with policy \"" + policyID + "\", or add a time-bounded exception if the violation is reviewed and accepted."
	detail := "route does not satisfy policy \"" + policyID + "\""
	return report.Finding{
		ID:             fp,
		RuleID:         report.RulePolicyViolation,
		Fingerprint:    fp,
		Severity:       report.SeverityHigh,
		Confidence:     model.ConfidenceHigh,
		Route:          &routeIdentity,
		Source:         route.Source,
		Detail:         detail,
		Recommendation: &rec,
		Evidence:       map[string]any{"policyId": policyID},
	}
}
