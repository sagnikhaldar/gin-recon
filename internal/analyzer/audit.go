package analyzer

import (
	"crypto/sha256"
	"encoding/hex"
	"go/ast"
	"strings"
	"time"

	"github.com/sagnikhaldar/gin-recon/internal/analyzer/gin"
	"github.com/sagnikhaldar/gin-recon/internal/classify"
	"github.com/sagnikhaldar/gin-recon/internal/config"
	"github.com/sagnikhaldar/gin-recon/internal/model"
	"github.com/sagnikhaldar/gin-recon/internal/policy"
	"github.com/sagnikhaldar/gin-recon/internal/report"
)

// AuditResult is Inventory's result plus authentication classification and
// policy evaluation: every route's Auth field populated, classification
// findings (public-route, matched-but-unenforced, stale-auth-config, ...),
// policy-violation findings, and which policies were evaluated.
type AuditResult struct {
	*InventoryResult
	Findings          []report.Finding
	Summary           report.Summary
	EvaluatedPolicies []string
}

// Audit runs the same discovery Inventory does, classifies every route
// against cfg per ADR 0005 (internal/classify), and evaluates cfg's
// policies against the classified routes (internal/policy). now is passed
// in rather than read from the system clock here so callers control
// exception-expiry evaluation and tests stay deterministic. A target with no
// Gin usage at all produces a valid, empty audit result — the same "not a
// finding" outcome Inventory has for that case.
func Audit(loaded *Loaded, cfg *config.Config, now time.Time) *AuditResult {
	result, api, funcIndex := discover(loaded)
	if api == nil {
		return &AuditResult{
			InventoryResult:   result,
			Summary:           report.Summary{FindingsBySeverity: map[report.Severity]int{}},
			EvaluatedPolicies: []string{},
		}
	}

	symbolIndex := BuildSymbolIndex(funcIndex)
	classified := classify.ClassifyAll(result.Routes, classify.Inputs{
		Config:      cfg,
		API:         api,
		FuncIndex:   funcIndex,
		SymbolIndex: symbolIndex,
		Profile:     model.ProfileTyped,
	})

	policyResult := policy.Evaluate(result.Routes, cfg, now)
	engineFindings, engineDiagnostics := engineSecurityFindings(loaded, api)
	// engineSecurityFindings runs after discover's own relativizeSources
	// pass, so its findings/diagnostics still carry the absolute paths
	// go/packages' Fset naturally produces — relativize them here, the one
	// place both Audit's own evidence and discover's merged result meet.
	for i := range engineFindings {
		relativizeSource(loaded.Root, nil, engineFindings[i].Source)
	}
	for i := range engineDiagnostics {
		relativizeSource(loaded.Root, nil, engineDiagnostics[i].Source)
	}
	result.Diagnostics = append(result.Diagnostics, engineDiagnostics...)

	findings := append(classified.Findings, policyResult.Findings...)
	findings = append(findings, engineFindings...)

	return &AuditResult{
		InventoryResult:   result,
		Findings:          findings,
		Summary:           buildSummary(result.Routes, findings),
		EvaluatedPolicies: policyResult.EvaluatedPolicies,
	}
}

// engineSecurityFindings walks every function in every loaded package for
// docs/gin-security-rules.md's two engine misconfiguration rules. These are
// audit-only: an inventory report never carries findings at all (see
// schema/report-1.0.json's conditional forbidding them), so this only runs
// from Audit, never from Inventory/discover.
func engineSecurityFindings(loaded *Loaded, api *gin.API) ([]report.Finding, []model.Diagnostic) {
	var findings []report.Finding
	var diagnostics []model.Diagnostic
	for _, pkg := range loaded.Packages {
		for _, file := range pkg.Syntax {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				evidence, diags := gin.AnalyzeEngineSecurity(pkg.Fset, pkg.TypesInfo, api, fn)
				diagnostics = append(diagnostics, diags...)
				for _, e := range evidence {
					findings = append(findings, newEngineFinding(e, pkg.PkgPath, fn.Name.Name))
				}
			}
		}
	}
	return findings, diagnostics
}

func newEngineFinding(evidence gin.EngineEvidence, pkgPath, funcName string) report.Finding {
	severity := report.SeverityLow
	detail := "gin.SetMode(gin.DebugMode) (or an equivalent constant) is called explicitly, which may expose verbose diagnostics or route information in production"
	recommendation := "Select release mode in production and keep mode configuration outside attacker control."
	if evidence.Rule == gin.RuleTrustAllProxies {
		severity = report.SeverityMedium
		detail = "SetTrustedProxies is configured to trust all addresses, so client IP derived from forwarded headers may be attacker-controlled"
		recommendation = "Configure only known proxy CIDRs, or pass nil when a forwarded client IP is unnecessary."
	}

	h := sha256.New()
	h.Write([]byte(strings.Join([]string{string(evidence.Rule), pkgPath, funcName}, "|")))
	fp := hex.EncodeToString(h.Sum(nil))
	rec := recommendation

	return report.Finding{
		ID:             fp,
		RuleID:         report.RuleID(evidence.Rule),
		Fingerprint:    fp,
		Severity:       severity,
		Confidence:     model.ConfidenceHigh,
		Source:         evidence.Source,
		Detail:         detail,
		Recommendation: &rec,
	}
}

func buildSummary(routes []model.Route, findings []report.Finding) report.Summary {
	summary := report.Summary{FindingsBySeverity: map[report.Severity]int{}}
	for _, r := range routes {
		summary.TotalRoutes++
		if r.Auth == nil {
			continue
		}
		switch r.Auth.AuthStatus {
		case model.AuthProven:
			if r.Auth.EnforcementAnalysis != nil && *r.Auth.EnforcementAnalysis == model.EnforcementConfirmedShape {
				summary.ProvenByConfirmedShape++
			} else {
				summary.ProvenByAttestedUnresolved++
			}
		case model.AuthPublic:
			summary.Public++
		case model.AuthUnknown:
			summary.Unknown++
		}
	}
	for _, f := range findings {
		summary.FindingsBySeverity[f.Severity]++
	}
	return summary
}
