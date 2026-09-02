// Package format's SARIF formatter emits a SARIF 2.1.0 log
// (docs/express-parity-matrix.md: "Emit GitHub Code Scanning-compatible
// findings and locations"). SARIF is audit-only (docs/cli-contract.md); an
// inventory report has no Findings at all, so calling SARIF on one produces
// a structurally valid but empty results array rather than an error — the
// CLI layer is what actually rejects `--format sarif` on inventory
// (internal/cli's Validate), not this formatter.
package format

import (
	"encoding/json"
	"sort"

	"github.com/sagnikhaldar/gin-recon/internal/model"
	"github.com/sagnikhaldar/gin-recon/internal/report"
)

const sarifSchemaURI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Results     []sarifResult     `json:"results"`
	Invocations []sarifInvocation `json:"invocations,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string           `json:"id"`
	ShortDescription     sarifMessage     `json:"shortDescription"`
	FullDescription      sarifMessage     `json:"fullDescription"`
	Help                 sarifMessage     `json:"help"`
	DefaultConfiguration sarifRuleConfig  `json:"defaultConfiguration"`
	Properties           *sarifRuleExtras `json:"properties,omitempty"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifRuleExtras struct {
	Tags []string `json:"tags,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifMessage      `json:"message"`
	Locations           []sarifLocation   `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

type sarifInvocation struct {
	ExecutionSuccessful        bool                `json:"executionSuccessful"`
	ToolExecutionNotifications []sarifNotification `json:"toolExecutionNotifications,omitempty"`
}

type sarifNotification struct {
	Descriptor sarifDescriptor `json:"descriptor"`
	Level      string          `json:"level"`
	Message    sarifMessage    `json:"message"`
	Locations  []sarifLocation `json:"locations,omitempty"`
}

type sarifDescriptor struct {
	ID string `json:"id"`
}

// sarifRuleOrder is docs/report-contract.md's full closed set of built-in
// rule IDs, in a fixed order — driver.rules always lists every rule Gin
// Recon can ever produce, in this order, regardless of which ones actually
// fired in a given run. GitHub Code Scanning (and SARIF consumers generally)
// use a stable ruleIndex to cross-reference results back into this catalog,
// so the order must not depend on finding content or map iteration.
var sarifRuleOrder = []report.RuleID{
	report.RulePublicRoute,
	report.RuleOpaqueMiddleware,
	report.RuleMatchedButUnenforced,
	report.RuleStaleAuthConfig,
	report.RulePerVerbGap,
	report.RuleStaleBaseline,
	report.RuleIncompleteAnalysis,
	report.RuleGinTrustAllProxies,
	report.RuleGinExplicitDebugMode,
	report.RulePolicyViolation,
}

type sarifRuleMeta struct {
	short string
	full  string
	help  string
	level string
}

// sarifRuleCatalog's short/full/help text and default level mirror
// docs/report-contract.md and docs/gin-security-rules.md exactly. Default
// level is that rule's typical Severity from the rule's own implementation
// (internal/classify, internal/policy, internal/analyzer/gin/security.go);
// each individual sarifResult's actual level still comes from that finding's
// own Severity, since per-verb-gap and policy-violation especially can occur
// at more than one severity depending on policy configuration.
var sarifRuleCatalog = map[report.RuleID]sarifRuleMeta{
	report.RulePublicRoute: {
		short: "Route has no configured authentication guard",
		full:  "No configured authMiddleware entry matched this route's resolved middleware chain, so it is classified public.",
		help:  "Add authentication middleware, or add this route to acceptedPublic if it is intentionally public.",
		level: "warning",
	},
	report.RuleOpaqueMiddleware: {
		short: "Route's middleware chain contains an unresolved entry",
		full:  "The route's middleware chain contains an anonymous or otherwise unresolved entry that could be hiding an authentication check the analyzer cannot see.",
		help:  "Name the middleware as a package-level function or method so it can be resolved, or configure it explicitly if it is a known guard.",
		level: "warning",
	},
	report.RuleMatchedButUnenforced: {
		short: "Configured guard never enforces a deny path",
		full:  "A configured authMiddleware entry matched this route by canonical symbol, but bounded control-flow analysis proves its body never terminates the request chain on failure (enforcementAnalysis: contradicted).",
		help:  "Remove this middleware from authMiddleware, or fix it to actually enforce a deny path.",
		level: "error",
	},
	report.RuleStaleAuthConfig: {
		short: "Configured auth middleware symbol never matched",
		full:  "A configured authMiddleware canonical symbol was never matched against any resolved middleware call site in the scanned code, suggesting a rename, move, or removal in the target repository.",
		help:  "Remove this entry from authMiddleware, or check whether the symbol was renamed or moved.",
		level: "warning",
	},
	report.RulePerVerbGap: {
		short: "Same path has inconsistent authentication across methods",
		full:  "The same normalized path is registered with different authentication outcomes across HTTP methods, which often indicates a missed guard on one verb rather than an intentional design.",
		help:  "Confirm whether every method on this path should share the same authentication requirement.",
		level: "warning",
	},
	report.RuleStaleBaseline: {
		short: "acceptedPublic entry no longer matches a public route",
		full:  "A configured acceptedPublic entry does not match any discovered route, or matches a route that is no longer classified public.",
		help:  "Remove this entry from acceptedPublic if the route was removed or is no longer intentionally public.",
		level: "note",
	},
	report.RuleIncompleteAnalysis: {
		short: "Analysis coverage is incomplete",
		full:  "One or more packages, files, or registrations could not be fully resolved, so the report's coverage is incomplete for the recorded build context.",
		help:  "Review scanCoverage for the specific packages, files, or registrations that failed, and re-run after resolving the underlying load or resolution failure.",
		level: "warning",
	},
	report.RuleGinTrustAllProxies: {
		short: "Gin engine explicitly trusts all proxies",
		full:  "A resolved SetTrustedProxies call configures the engine to trust all addresses (0.0.0.0/0, ::/0, or an equivalent all-address CIDR), so client IP derived from forwarded headers may be attacker-controlled.",
		help:  "Configure only known proxy CIDRs, or pass nil when a forwarded client IP is unnecessary.",
		level: "warning",
	},
	report.RuleGinExplicitDebugMode: {
		short: "Gin engine explicitly set to debug mode",
		full:  "A resolved gin.SetMode(gin.DebugMode) call (or equivalent constant assignment) is present in the selected build context, which may expose verbose diagnostics or route information in production.",
		help:  "Select release mode in production and keep mode configuration outside attacker control.",
		level: "note",
	},
	report.RulePolicyViolation: {
		short: "Configured policy requirement not satisfied",
		full:  "A route matched a configured policy's selector but did not satisfy that policy's requirement.",
		help:  "Adjust the route's middleware/authentication to satisfy the policy, or add a time-bounded, reviewed exception.",
		level: "error",
	},
}

// SARIF renders rep's findings and diagnostics as a SARIF 2.1.0 log for
// GitHub Code Scanning and other SARIF consumers. Every text field that
// could echo content derived from the scanned repository's own source
// (route/method identity embedded in a finding's Detail, Recommendation, or
// a diagnostic's Message) is passed through mdEscape before being written —
// GitHub's Code Scanning UI renders SARIF message.text as Markdown, so the
// same "values designed to enter reports" threat docs/threat-model.md
// describes for Markdown output applies here too.
func SARIF(rep *report.Report) ([]byte, error) {
	log := sarifLog{
		Schema:  sarifSchemaURI,
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool:        sarifTool{Driver: sarifDriverFor(rep)},
			Results:     sarifResultsFor(rep),
			Invocations: []sarifInvocation{sarifInvocationFor(rep)},
		}},
	}
	data, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func sarifDriverFor(rep *report.Report) sarifDriver {
	rules := make([]sarifRule, len(sarifRuleOrder))
	for i, id := range sarifRuleOrder {
		meta := sarifRuleCatalog[id]
		rules[i] = sarifRule{
			ID:                   string(id),
			ShortDescription:     sarifMessage{Text: meta.short},
			FullDescription:      sarifMessage{Text: meta.full},
			Help:                 sarifMessage{Text: meta.help},
			DefaultConfiguration: sarifRuleConfig{Level: meta.level},
		}
	}
	return sarifDriver{
		Name:           rep.ToolName,
		Version:        rep.ToolVersion,
		InformationURI: "https://github.com/sagnikhaldar/gin-recon",
		Rules:          rules,
	}
}

var sarifRuleIndex = func() map[report.RuleID]int {
	index := make(map[report.RuleID]int, len(sarifRuleOrder))
	for i, id := range sarifRuleOrder {
		index[id] = i
	}
	return index
}()

func sarifLevelForSeverity(sev report.Severity) string {
	switch sev {
	case report.SeverityCritical, report.SeverityHigh:
		return "error"
	case report.SeverityMedium:
		return "warning"
	default: // low, info, or any future value: fail open to the quietest level
		return "note"
	}
}

func sarifLevelForDiagnosticSeverity(sev model.DiagnosticSeverity) string {
	switch sev {
	case model.DiagnosticError:
		return "error"
	case model.DiagnosticWarning:
		return "warning"
	default:
		return "note"
	}
}

// sarifResultsFor converts rep.Findings into results, sorted by severity for
// readability — report.go does not itself guarantee finding order (unlike
// routes/diagnostics, which its own normalization step sorts), so this
// formatter sorts a copy rather than assume an incoming order, mirroring
// Pretty and Markdown's identical severity-then-fingerprint sort.
func sarifResultsFor(rep *report.Report) []sarifResult {
	findings := make([]report.Finding, len(rep.Findings))
	copy(findings, rep.Findings)
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Severity != findings[j].Severity {
			return severityRank(findings[i].Severity) < severityRank(findings[j].Severity)
		}
		return findings[i].Fingerprint < findings[j].Fingerprint
	})

	results := make([]sarifResult, len(findings))
	for i, f := range findings {
		results[i] = sarifResultFor(f)
	}
	return results
}

func sarifResultFor(f report.Finding) sarifResult {
	message := mdEscape(f.Detail)
	if f.Recommendation != nil && *f.Recommendation != "" {
		message += " " + mdEscape(*f.Recommendation)
	}

	result := sarifResult{
		RuleID:              string(f.RuleID),
		RuleIndex:           sarifRuleIndex[f.RuleID],
		Level:               sarifLevelForSeverity(f.Severity),
		Message:             sarifMessage{Text: message},
		PartialFingerprints: map[string]string{"ginReconFingerprint/v1": f.Fingerprint},
	}
	if f.Source != nil {
		result.Locations = []sarifLocation{sarifLocationFor(f.Source)}
	}
	return result
}

func sarifLocationFor(src *model.Source) sarifLocation {
	loc := sarifLocation{PhysicalLocation: sarifPhysicalLocation{
		ArtifactLocation: sarifArtifactLocation{URI: src.File},
	}}
	if src.Line != nil {
		loc.PhysicalLocation.Region = &sarifRegion{StartLine: *src.Line}
	}
	return loc
}

// sarifInvocationFor reports diagnostics as tool execution notifications —
// SARIF's dedicated concept for problems with the analysis run itself
// (incomplete coverage, unresolved registrations) as distinct from results,
// which describe findings about the target's code.
func sarifInvocationFor(rep *report.Report) sarifInvocation {
	inv := sarifInvocation{ExecutionSuccessful: true}
	for _, d := range rep.Diagnostics {
		n := sarifNotification{
			Descriptor: sarifDescriptor{ID: d.Code},
			Level:      sarifLevelForDiagnosticSeverity(d.Severity),
			Message:    sarifMessage{Text: mdEscape(d.Message)},
		}
		if d.Source != nil {
			n.Locations = []sarifLocation{sarifLocationFor(d.Source)}
		}
		inv.ToolExecutionNotifications = append(inv.ToolExecutionNotifications, n)
	}
	if !rep.ScanCoverage.Complete {
		inv.ToolExecutionNotifications = append(inv.ToolExecutionNotifications, sarifNotification{
			Descriptor: sarifDescriptor{ID: string(report.RuleIncompleteAnalysis)},
			Level:      "warning",
			Message: sarifMessage{Text: "scan coverage is incomplete for the recorded build context: " +
				"see scanCoverage in the JSON report for the specific packages, files, or registrations that could not be resolved."},
		})
	}
	return inv
}
