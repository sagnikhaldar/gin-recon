// Package report defines the top-level report envelope (schema/report-1.0.json)
// and its construction. The JSON Schema is the normative contract
// (docs/report-contract.md); this package must stay in lockstep with it —
// internal/report/schema_test.go enforces that with round-trip validation
// against the schema file itself.
package report

import (
	"encoding/json"

	"github.com/sagnikhaldar/gin-recon/internal/model"
)

// SchemaVersion is the report schema version this package produces. Bumping
// it is a MAJOR change under docs/PLAN.md#versioning unless the change is
// purely additive, in which case only ToolVersion/ClassifierRulesetVersion
// move.
const SchemaVersion = "1.0"

// Tool is the constant "tool" field value for every Gin Recon report.
const Tool = "gin-recon"

// Command is which top-level command produced the report. Only inventory and
// audit produce a Report; schema and suggest-auth have their own output
// shapes (docs/cli-contract.md).
type Command string

const (
	CommandInventory Command = "inventory"
	CommandAudit     Command = "audit"
)

// Target identifies the scanned module/workspace and the single build
// context the report was produced under.
type Target struct {
	Module       string             `json:"module"`
	Workspace    *string            `json:"workspace"`
	BuildContext model.BuildContext `json:"buildContext"`
}

// RuleID enumerates every built-in finding rule. This set is closed for v1 —
// adding a rule requires an ADR and fixture corpus per docs/gin-security-rules.md
// and docs/report-contract.md#findings-and-policies.
type RuleID string

const (
	RulePublicRoute          RuleID = "public-route"
	RuleOpaqueMiddleware     RuleID = "opaque-middleware"
	RuleMatchedButUnenforced RuleID = "matched-but-unenforced"
	RuleStaleAuthConfig      RuleID = "stale-auth-config"
	RulePerVerbGap           RuleID = "per-verb-gap"
	RuleStaleBaseline        RuleID = "stale-baseline"
	RuleIncompleteAnalysis   RuleID = "incomplete-analysis"
	RuleGinTrustAllProxies   RuleID = "gin-explicit-trust-all-proxies"
	RuleGinExplicitDebugMode RuleID = "gin-explicit-debug-mode"
	RulePolicyViolation      RuleID = "policy-violation"
)

// Severity is a finding's security/policy severity. It is distinct from
// model.DiagnosticSeverity, which describes analysis quality rather than a
// security outcome.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Finding is one audit-time security or policy result. Fingerprint hashes
// rule identity plus normalized route identity and excludes source line and
// absolute checkout path, so it stays stable across unrelated line moves
// (docs/report-contract.md#findings-and-policies).
type Finding struct {
	ID             string           `json:"id"`
	RuleID         RuleID           `json:"ruleId"`
	Fingerprint    string           `json:"fingerprint"`
	Severity       Severity         `json:"severity"`
	Confidence     model.Confidence `json:"confidence"`
	Route          *string          `json:"route,omitempty"`
	Source         *model.Source    `json:"source,omitempty"`
	Detail         string           `json:"detail"`
	Recommendation *string          `json:"recommendation,omitempty"`
	Evidence       map[string]any   `json:"evidence,omitempty"`
}

// Summary aggregates route counts for quick consumption. ProvenByConfirmedShape
// and ProvenByAttestedUnresolved are reported separately, never merged into a
// single "proven" count, so a consumer can tell analyzer-confirmed
// enforcement apart from reviewer-trusted enforcement without reading every
// route (docs/report-contract.md#authentication).
type Summary struct {
	TotalRoutes                int              `json:"totalRoutes"`
	ProvenByConfirmedShape     int              `json:"provenByConfirmedShape"`
	ProvenByAttestedUnresolved int              `json:"provenByAttestedUnresolved"`
	Public                     int              `json:"public"`
	Unknown                    int              `json:"unknown"`
	FindingsBySeverity         map[Severity]int `json:"findingsBySeverity"`
}

// MarshalJSON defaults a nil FindingsBySeverity to {}; schema/report-1.0.json
// requires it as a non-nullable object (see internal/model's package doc
// comment for the general rationale).
func (s Summary) MarshalJSON() ([]byte, error) {
	type alias Summary
	x := alias(s)
	if x.FindingsBySeverity == nil {
		x.FindingsBySeverity = map[Severity]int{}
	}
	return json.Marshal(x)
}

// PolicyEvaluation records which configured policies were evaluated in this
// audit, independent of whether they produced findings.
type PolicyEvaluation struct {
	EvaluatedPolicies []string `json:"evaluatedPolicies"`
}

// MarshalJSON defaults a nil EvaluatedPolicies to []; see Summary.MarshalJSON
// above for why this guard lives on the type rather than every call site.
func (p PolicyEvaluation) MarshalJSON() ([]byte, error) {
	type alias PolicyEvaluation
	x := alias(p)
	if x.EvaluatedPolicies == nil {
		x.EvaluatedPolicies = []string{}
	}
	return json.Marshal(x)
}

// ExceptionRef is the subset of a configured policy exception that is safe to
// echo back into a report: no route selector internals, just enough to audit
// which exception fired and when it expires.
type ExceptionRef struct {
	ID      string `json:"id"`
	Reason  string `json:"reason"`
	Expires string `json:"expires"` // strict YYYY-MM-DD, evaluated in UTC
}

// AuthChange describes one route's authentication state moving between a
// baseline and the current report.
type AuthChange struct {
	Method      string           `json:"method"`
	Path        string           `json:"path"`
	From        model.AuthStatus `json:"from"`
	To          model.AuthStatus `json:"to"`
	Explanation string           `json:"explanation"`
}

// Delta is present only when a baseline was supplied. Baseline comparison
// requires the same schema major, analysis profile, normalized build
// context, and route-normalization version; a mismatch is an operational
// error, not a misleading delta (docs/report-contract.md#baselines-and-exit-codes).
type Delta struct {
	AddedRoutes      []string     `json:"addedRoutes"`
	RemovedRoutes    []string     `json:"removedRoutes"`
	AuthRegressions  []AuthChange `json:"authRegressions"`
	AuthImprovements []AuthChange `json:"authImprovements"`
	NewFindings      []string     `json:"newFindings"`
	ResolvedFindings []string     `json:"resolvedFindings"`
}

// MarshalJSON defaults every nil slice field to []. schema/report-1.0.json
// requires all six as non-nullable arrays; see internal/model's package doc
// comment for why this is a MarshalJSON concern rather than a call-site one.
func (d Delta) MarshalJSON() ([]byte, error) {
	type alias Delta
	x := alias(d)
	if x.AddedRoutes == nil {
		x.AddedRoutes = []string{}
	}
	if x.RemovedRoutes == nil {
		x.RemovedRoutes = []string{}
	}
	if x.AuthRegressions == nil {
		x.AuthRegressions = []AuthChange{}
	}
	if x.AuthImprovements == nil {
		x.AuthImprovements = []AuthChange{}
	}
	if x.NewFindings == nil {
		x.NewFindings = []string{}
	}
	if x.ResolvedFindings == nil {
		x.ResolvedFindings = []string{}
	}
	return json.Marshal(x)
}

// Report is the full envelope for both inventory and audit output. Audit-only
// fields use pointers/nil so an inventory report serializes without them
// entirely, matching schema/report-1.0.json's conditional requirement that
// forbids Summary/Findings/PolicyEvaluation/ActiveExceptions from appearing
// on an inventory report at all — see NewInventoryReport and NewAuditReport,
// which are the only supported constructors.
type Report struct {
	SchemaVersion            string                  `json:"schemaVersion"`
	ToolName                 string                  `json:"tool"`
	ToolVersion              string                  `json:"toolVersion"`
	ClassifierRulesetVersion string                  `json:"classifierRulesetVersion"`
	Command                  Command                 `json:"command"`
	AnalysisProfile          model.AnalysisProfile   `json:"analysisProfile"`
	Target                   Target                  `json:"target"`
	Routes                   []model.Route           `json:"routes"`
	GlobalMiddleware         []model.Middleware      `json:"globalMiddleware"`
	FallbackSurfaces         []model.FallbackSurface `json:"fallbackSurfaces"`
	ScanCoverage             model.ScanCoverage      `json:"scanCoverage"`
	Diagnostics              []model.Diagnostic      `json:"diagnostics"`

	// Audit-only. Tagged "-" because plain struct-tag omitempty cannot express
	// this field's actual rule: appear as a required array key (even "[]")
	// for command "audit", and be entirely absent for "inventory". Regular
	// omitempty would drop an audit report's genuinely-empty Findings/
	// ActiveExceptions the same way it drops an inventory report's nil ones,
	// which schema/report-1.0.json forbids (both are required, non-optional
	// arrays under command "audit"). MarshalJSON below implements the actual
	// rule; UnmarshalJSON mirrors it on the way back in.
	Summary          *Summary          `json:"-"`
	Findings         []Finding         `json:"-"`
	PolicyEvaluation *PolicyEvaluation `json:"-"`
	ActiveExceptions []ExceptionRef    `json:"-"`

	Delta *Delta `json:"delta,omitempty"`
}

// reportEnvelope is the always-present portion of a Report, shared by
// inventory and audit output. It exists only so MarshalJSON/UnmarshalJSON can
// delegate the common fields to encoding/json and hand-splice the
// conditional audit-only fields around it.
type reportEnvelope struct {
	SchemaVersion            string                  `json:"schemaVersion"`
	ToolName                 string                  `json:"tool"`
	ToolVersion              string                  `json:"toolVersion"`
	ClassifierRulesetVersion string                  `json:"classifierRulesetVersion"`
	Command                  Command                 `json:"command"`
	AnalysisProfile          model.AnalysisProfile   `json:"analysisProfile"`
	Target                   Target                  `json:"target"`
	Routes                   []model.Route           `json:"routes"`
	GlobalMiddleware         []model.Middleware      `json:"globalMiddleware"`
	FallbackSurfaces         []model.FallbackSurface `json:"fallbackSurfaces"`
	ScanCoverage             model.ScanCoverage      `json:"scanCoverage"`
	Diagnostics              []model.Diagnostic      `json:"diagnostics"`
	Delta                    *Delta                  `json:"delta,omitempty"`
}

// envelope defaults every nil top-level slice to empty. schema/report-1.0.json
// requires routes/globalMiddleware/fallbackSurfaces/diagnostics as
// non-nullable arrays; NewInventoryReport/NewAuditReport already construct
// these as non-nil, but nothing stops a caller from directly overwriting
// e.g. Report.GlobalMiddleware with a result slice that happens to be nil
// (which is exactly what happened in cmd/gin-recon's first wiring of the
// inventory command — a nil analyzer result slice reached the JSON encoder
// as null). Guarding here, at the one place every Report passes through on
// its way to JSON, makes that mistake structurally impossible to reintroduce
// rather than trusting every call site to remember — the same principle
// internal/model's package doc comment explains at greater length.
func (r Report) envelope() reportEnvelope {
	routes := r.Routes
	if routes == nil {
		routes = []model.Route{}
	}
	globalMiddleware := r.GlobalMiddleware
	if globalMiddleware == nil {
		globalMiddleware = []model.Middleware{}
	}
	fallbackSurfaces := r.FallbackSurfaces
	if fallbackSurfaces == nil {
		fallbackSurfaces = []model.FallbackSurface{}
	}
	diagnostics := r.Diagnostics
	if diagnostics == nil {
		diagnostics = []model.Diagnostic{}
	}
	return reportEnvelope{
		SchemaVersion:            r.SchemaVersion,
		ToolName:                 r.ToolName,
		ToolVersion:              r.ToolVersion,
		ClassifierRulesetVersion: r.ClassifierRulesetVersion,
		Command:                  r.Command,
		AnalysisProfile:          r.AnalysisProfile,
		Target:                   r.Target,
		Routes:                   routes,
		GlobalMiddleware:         globalMiddleware,
		FallbackSurfaces:         fallbackSurfaces,
		ScanCoverage:             r.ScanCoverage,
		Diagnostics:              diagnostics,
		Delta:                    r.Delta,
	}
}

// MarshalJSON emits Summary/Findings/PolicyEvaluation/ActiveExceptions as
// present (never null, even when empty) for command "audit", and omits them
// entirely for command "inventory" — the exact rule schema/report-1.0.json
// enforces and that struct-tag omitempty cannot express (see the field
// comment above).
func (r Report) MarshalJSON() ([]byte, error) {
	base, err := json.Marshal(r.envelope())
	if err != nil {
		return nil, err
	}
	if r.Command != CommandAudit {
		return base, nil
	}

	var merged map[string]json.RawMessage
	if err := json.Unmarshal(base, &merged); err != nil {
		return nil, err
	}

	summary := r.Summary
	if summary == nil {
		summary = &Summary{FindingsBySeverity: map[Severity]int{}}
	}
	findings := r.Findings
	if findings == nil {
		findings = []Finding{}
	}
	policyEvaluation := r.PolicyEvaluation
	if policyEvaluation == nil {
		policyEvaluation = &PolicyEvaluation{EvaluatedPolicies: []string{}}
	}
	activeExceptions := r.ActiveExceptions
	if activeExceptions == nil {
		activeExceptions = []ExceptionRef{}
	}

	for key, value := range map[string]any{
		"summary":          summary,
		"findings":         findings,
		"policyEvaluation": policyEvaluation,
		"activeExceptions": activeExceptions,
	} {
		encoded, err := json.Marshal(value)
		if err != nil {
			return nil, err
		}
		merged[key] = encoded
	}

	return json.Marshal(merged)
}

// UnmarshalJSON is the inverse of MarshalJSON: it always decodes the common
// envelope, and additionally decodes the audit-only fields only when present,
// leaving them nil otherwise. This is what lets --baseline load a previously
// emitted report of either command back into the same Report type.
func (r *Report) UnmarshalJSON(data []byte) error {
	var env reportEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return err
	}
	*r = Report{
		SchemaVersion:            env.SchemaVersion,
		ToolName:                 env.ToolName,
		ToolVersion:              env.ToolVersion,
		ClassifierRulesetVersion: env.ClassifierRulesetVersion,
		Command:                  env.Command,
		AnalysisProfile:          env.AnalysisProfile,
		Target:                   env.Target,
		Routes:                   env.Routes,
		GlobalMiddleware:         env.GlobalMiddleware,
		FallbackSurfaces:         env.FallbackSurfaces,
		ScanCoverage:             env.ScanCoverage,
		Diagnostics:              env.Diagnostics,
		Delta:                    env.Delta,
	}

	var audit struct {
		Summary          *Summary          `json:"summary"`
		Findings         []Finding         `json:"findings"`
		PolicyEvaluation *PolicyEvaluation `json:"policyEvaluation"`
		ActiveExceptions []ExceptionRef    `json:"activeExceptions"`
	}
	if err := json.Unmarshal(data, &audit); err != nil {
		return err
	}
	r.Summary = audit.Summary
	r.Findings = audit.Findings
	r.PolicyEvaluation = audit.PolicyEvaluation
	r.ActiveExceptions = audit.ActiveExceptions
	return nil
}

// toolVersion and classifierRulesetVersion are placeholders until phase 5
// wires them to build-time version injection (see PLAN.md#versioning).
//
// toolVersion is 0.3.0 for the v0.3.0 tag, bumped from the tagged v0.2.0
// per PLAN.md#versioning's MINOR definition: fleet --use-target-config
// (docs/adr/0031) is a new opt-in flag with a safe (off) default and a new
// optional report field (targetConfig) — it doesn't change classification
// results for anyone not passing it, so classifierRulesetVersion stays at
// 0.1.0. (v0.2.0 itself covered fleet's `--out` default (docs/adr/0028),
// the fleet.html evidence dashboard and its auth-config/enumeration-
// coverage visibility (docs/adr/0029, docs/adr/0030), and the `--out .`
// sibling-directory fix (docs/adr/0027) — also all additive.)
const (
	toolVersion              = "0.3.0"
	classifierRulesetVersion = "0.1.0"
)

// ToolVersion exports toolVersion for callers outside this package that need
// to stamp gin-recon's own version onto a non-Report artifact (fleet.json's
// aggregate, for instance) without duplicating the version string anywhere
// else it could drift out of sync.
const ToolVersion = toolVersion

// NewInventoryReport builds a Report with no authentication judgment, policy
// results, summary, or findings, matching docs/report-contract.md's
// "Inventory reports omit authentication judgment..." rule.
func NewInventoryReport(profile model.AnalysisProfile, target Target) *Report {
	return &Report{
		SchemaVersion:            SchemaVersion,
		ToolName:                 Tool,
		ToolVersion:              toolVersion,
		ClassifierRulesetVersion: classifierRulesetVersion,
		Command:                  CommandInventory,
		AnalysisProfile:          profile,
		Target:                   target,
		Routes:                   []model.Route{},
		GlobalMiddleware:         []model.Middleware{},
		FallbackSurfaces:         []model.FallbackSurface{},
		Diagnostics:              []model.Diagnostic{},
	}
}

// NewAuditReport builds a Report carrying the audit-only fields that
// NewInventoryReport omits. summary, findings, policyEvaluation, and
// activeExceptions are all required by schema/report-1.0.json for command
// "audit" — callers must supply real (possibly empty) values, never nil.
func NewAuditReport(
	profile model.AnalysisProfile,
	target Target,
	summary Summary,
	findings []Finding,
	policyEvaluation PolicyEvaluation,
	activeExceptions []ExceptionRef,
) *Report {
	r := NewInventoryReport(profile, target)
	r.Command = CommandAudit
	r.Summary = &summary
	r.Findings = findings
	r.PolicyEvaluation = &policyEvaluation
	r.ActiveExceptions = activeExceptions
	return r
}
