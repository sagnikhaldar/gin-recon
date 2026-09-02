// Package format implements gin-recon's output formats. Every formatter
// takes the same immutable *report.Report and must not mutate, reclassify,
// or silently discard evidence — docs/report-contract.md's "Output
// Guarantees" applies to every formatter equally, pretty included.
package format

import (
	"fmt"
	"io"
	"sort"
	"text/tabwriter"

	"github.com/sagnikhaldar/gin-recon/internal/model"
	"github.com/sagnikhaldar/gin-recon/internal/report"
)

// Pretty writes a human-readable rendering of rep to w. It is deterministic
// for a given report (report.go's own normalization already sorts routes/
// findings/etc.; Pretty does not re-sort anything that would change meaning,
// only groups findings by severity for readability).
func Pretty(w io.Writer, rep *report.Report) error {
	p := &prettyPrinter{w: w}
	p.header(rep)
	p.scanCoverage(rep)
	if rep.Command == report.CommandAudit {
		p.summary(rep)
	}
	p.routes(rep)
	p.globalMiddleware(rep)
	p.fallbackSurfaces(rep)
	if rep.Command == report.CommandAudit {
		p.findings(rep)
		p.policies(rep)
	}
	p.diagnostics(rep)
	return p.err
}

type prettyPrinter struct {
	w   io.Writer
	err error
}

func (p *prettyPrinter) printf(format string, args ...any) {
	if p.err != nil {
		return
	}
	_, err := fmt.Fprintf(p.w, format, args...)
	if err != nil {
		p.err = err
	}
}

func (p *prettyPrinter) header(rep *report.Report) {
	bc := rep.Target.BuildContext
	p.printf("%s %s — %s (%s, %s/%s)\n", rep.ToolName, rep.Command, rep.Target.Module, bc.Profile, bc.GOOS, bc.GOARCH)
}

func (p *prettyPrinter) scanCoverage(rep *report.Report) {
	sc := rep.ScanCoverage
	status := "complete"
	if !sc.Complete {
		status = "INCOMPLETE"
	}
	p.printf("scan: %d package(s), %d file(s) analyzed — %s\n", sc.AnalyzedPackages, sc.AnalyzedFiles, status)
	if sc.FailedPackages > 0 {
		p.printf("  %d package(s) failed to load\n", sc.FailedPackages)
	}
	p.printf("\n")
}

func (p *prettyPrinter) summary(rep *report.Report) {
	if rep.Summary == nil {
		return
	}
	s := rep.Summary
	p.printf("SUMMARY\n")
	p.printf("  %d route(s): %d proven (confirmed-shape), %d proven (attested), %d public, %d unknown\n",
		s.TotalRoutes, s.ProvenByConfirmedShape, s.ProvenByAttestedUnresolved, s.Public, s.Unknown)
	if len(s.FindingsBySeverity) > 0 {
		p.printf("  findings:")
		for _, sev := range orderedSeverities(s.FindingsBySeverity) {
			p.printf(" %d %s", s.FindingsBySeverity[sev], sev)
		}
		p.printf("\n")
	}
	p.printf("\n")
}

func (p *prettyPrinter) routes(rep *report.Report) {
	p.printf("ROUTES (%d)\n", len(rep.Routes))
	if len(rep.Routes) == 0 {
		p.printf("  (none)\n\n")
		return
	}
	tw := tabwriter.NewWriter(p.w, 0, 2, 2, ' ', 0)
	for _, r := range rep.Routes {
		status := ""
		if r.Auth != nil {
			status = "  " + authLabel(*r.Auth)
		}
		mw := middlewareSummary(r.Middleware)
		handler := r.FinalHandler.DisplayName
		src := sourceLabel(r.Source)
		fmt.Fprintf(tw, "  %s\t%s%s\t%s -> %s\t%s\n", r.Method, r.NormalizedPath, status, mw, handler, src)
	}
	if err := tw.Flush(); err != nil && p.err == nil {
		p.err = err
	}
	p.printf("\n")
}

func authLabel(auth model.AuthClassification) string {
	label := "[" + string(auth.AuthStatus)
	if auth.EnforcementAnalysis != nil {
		label += "/" + string(*auth.EnforcementAnalysis)
	}
	if auth.Accepted {
		label += ", accepted"
	}
	return label + "]"
}

func middlewareSummary(mw []model.Middleware) string {
	if len(mw) == 0 {
		return "[]"
	}
	out := "["
	for i, m := range mw {
		if i > 0 {
			out += ", "
		}
		out += m.DisplayName
	}
	return out + "]"
}

func sourceLabel(src *model.Source) string {
	if src == nil {
		return ""
	}
	if src.Line == nil {
		return src.File
	}
	return fmt.Sprintf("%s:%d", src.File, *src.Line)
}

func (p *prettyPrinter) globalMiddleware(rep *report.Report) {
	if len(rep.GlobalMiddleware) == 0 {
		return
	}
	p.printf("GLOBAL MIDDLEWARE (%d)\n", len(rep.GlobalMiddleware))
	for _, m := range rep.GlobalMiddleware {
		p.printf("  - %s\n", m.DisplayName)
	}
	p.printf("\n")
}

func (p *prettyPrinter) fallbackSurfaces(rep *report.Report) {
	if len(rep.FallbackSurfaces) == 0 {
		return
	}
	p.printf("FALLBACK SURFACES\n")
	for _, fb := range rep.FallbackSurfaces {
		p.printf("  %s -> %s\n", fb.Kind, fb.FinalHandler.DisplayName)
	}
	p.printf("\n")
}

func (p *prettyPrinter) findings(rep *report.Report) {
	p.printf("FINDINGS (%d)\n", len(rep.Findings))
	if len(rep.Findings) == 0 {
		p.printf("  (none)\n\n")
		return
	}
	findings := make([]report.Finding, len(rep.Findings))
	copy(findings, rep.Findings)
	sort.SliceStable(findings, func(i, j int) bool {
		return severityRank(findings[i].Severity) < severityRank(findings[j].Severity)
	})
	for _, f := range findings {
		route := ""
		if f.Route != nil {
			route = "  " + *f.Route
		}
		p.printf("  [%s] %s%s\n", f.Severity, f.RuleID, route)
		p.printf("    %s\n", f.Detail)
		if f.Recommendation != nil && *f.Recommendation != "" {
			p.printf("    -> %s\n", *f.Recommendation)
		}
	}
	p.printf("\n")
}

func (p *prettyPrinter) policies(rep *report.Report) {
	if rep.PolicyEvaluation == nil || len(rep.PolicyEvaluation.EvaluatedPolicies) == 0 {
		return
	}
	p.printf("POLICIES EVALUATED: ")
	for i, id := range rep.PolicyEvaluation.EvaluatedPolicies {
		if i > 0 {
			p.printf(", ")
		}
		p.printf("%s", id)
	}
	p.printf("\n\n")
}

func (p *prettyPrinter) diagnostics(rep *report.Report) {
	if len(rep.Diagnostics) == 0 {
		return
	}
	p.printf("DIAGNOSTICS (%d)\n", len(rep.Diagnostics))
	for _, d := range rep.Diagnostics {
		src := sourceLabel(d.Source)
		if src != "" {
			src = " (" + src + ")"
		}
		p.printf("  [%s] %s: %s%s\n", d.Severity, d.Code, d.Message, src)
	}
	p.printf("\n")
}

var severityOrder = map[report.Severity]int{
	report.SeverityCritical: 0,
	report.SeverityHigh:     1,
	report.SeverityMedium:   2,
	report.SeverityLow:      3,
	report.SeverityInfo:     4,
}

func severityRank(s report.Severity) int {
	if rank, ok := severityOrder[s]; ok {
		return rank
	}
	return len(severityOrder)
}

func orderedSeverities(counts map[report.Severity]int) []report.Severity {
	sevs := make([]report.Severity, 0, len(counts))
	for s := range counts {
		sevs = append(sevs, s)
	}
	sort.Slice(sevs, func(i, j int) bool { return severityRank(sevs[i]) < severityRank(sevs[j]) })
	return sevs
}
