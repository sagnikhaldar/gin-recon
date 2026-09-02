package format

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/sagnikhaldar/gin-recon/internal/model"
	"github.com/sagnikhaldar/gin-recon/internal/report"
)

// Markdown writes a GitHub-Flavored-Markdown rendering of rep to w, for CI/PR
// summaries (docs/express-parity-matrix.md: "Support SARIF plus Markdown
// summaries"). It follows the same section structure as Pretty and carries
// the same determinism guarantee (report.go's own normalization already
// orders every slice; Markdown does not re-sort anything that would change
// meaning).
//
// Every value that could originate from the scanned repository's own source
// text — route paths, HTTP methods, diagnostic/finding messages that quote
// them — is escaped with mdEscape before being written. docs/threat-model.md
// treats a scanned repository as untrusted input capable of containing
// "values designed to enter reports"; a route registered with
// router.Handle("GET\n\n<script>...", "/x", h) or a literal path containing
// "|" must not be able to break a table's structure or inject raw HTML/script
// content into a rendered PR comment.
func Markdown(w io.Writer, rep *report.Report) error {
	m := &markdownPrinter{w: w}
	m.header(rep)
	m.scanCoverage(rep)
	if rep.Command == report.CommandAudit {
		m.summary(rep)
	}
	m.routes(rep)
	m.globalMiddleware(rep)
	m.fallbackSurfaces(rep)
	if rep.Command == report.CommandAudit {
		m.findings(rep)
		m.policies(rep)
	}
	m.diagnostics(rep)
	return m.err
}

type markdownPrinter struct {
	w   io.Writer
	err error
}

func (m *markdownPrinter) printf(format string, args ...any) {
	if m.err != nil {
		return
	}
	if _, err := fmt.Fprintf(m.w, format, args...); err != nil {
		m.err = err
	}
}

// mdEscape neutralizes every character GFM gives special meaning to inside a
// table cell or plain line: backslash and pipe (would otherwise break a
// table row's column structure), backtick (would otherwise break out of an
// inline code span this formatter wraps values in), embedded newlines (would
// otherwise inject an arbitrary new Markdown/HTML block), and angle brackets
// (GFM permits limited raw inline HTML; a route path or method containing a
// literal "<script>" must render as inert text, not as HTML). Backslash is
// escaped first so the backslashes this function itself introduces for "|"
// are never re-escaped.
func mdEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "|", `\|`)
	s = strings.ReplaceAll(s, "`", "'")
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

// mdCode renders s as an escaped inline code span.
func mdCode(s string) string {
	return "`" + mdEscape(s) + "`"
}

func (m *markdownPrinter) header(rep *report.Report) {
	bc := rep.Target.BuildContext
	m.printf("# %s %s — %s\n\n", rep.ToolName, rep.Command, mdEscape(rep.Target.Module))
	m.printf("_%s, %s/%s_\n\n", bc.Profile, bc.GOOS, bc.GOARCH)
}

func (m *markdownPrinter) scanCoverage(rep *report.Report) {
	sc := rep.ScanCoverage
	status := "complete"
	if !sc.Complete {
		status = "**INCOMPLETE**"
	}
	m.printf("Scan: %d package(s), %d file(s) analyzed — %s\n\n", sc.AnalyzedPackages, sc.AnalyzedFiles, status)
	if sc.FailedPackages > 0 {
		m.printf("> %d package(s) failed to load.\n\n", sc.FailedPackages)
	}
}

func (m *markdownPrinter) summary(rep *report.Report) {
	if rep.Summary == nil {
		return
	}
	s := rep.Summary
	m.printf("## Summary\n\n")
	m.printf("Total routes: **%d** — proven (confirmed-shape): **%d**, proven (attested): **%d**, public: **%d**, unknown: **%d**\n\n",
		s.TotalRoutes, s.ProvenByConfirmedShape, s.ProvenByAttestedUnresolved, s.Public, s.Unknown)
	if len(s.FindingsBySeverity) > 0 {
		var parts []string
		for _, sev := range orderedSeverities(s.FindingsBySeverity) {
			parts = append(parts, fmt.Sprintf("%s: **%d**", sev, s.FindingsBySeverity[sev]))
		}
		m.printf("Findings by severity: %s\n\n", strings.Join(parts, ", "))
	}
}

func (m *markdownPrinter) routes(rep *report.Report) {
	m.printf("## Routes (%d)\n\n", len(rep.Routes))
	if len(rep.Routes) == 0 {
		m.printf("_None._\n\n")
		return
	}
	audit := rep.Command == report.CommandAudit
	if audit {
		m.printf("| Method | Path | Auth | Middleware | Handler | Source |\n")
		m.printf("| --- | --- | --- | --- | --- | --- |\n")
	} else {
		m.printf("| Method | Path | Middleware | Handler | Source |\n")
		m.printf("| --- | --- | --- | --- | --- |\n")
	}
	for _, r := range rep.Routes {
		method := mdEscape(r.Method)
		path := mdCode(r.NormalizedPath)
		mw := mdMiddlewareList(r.Middleware)
		handler := mdEscape(r.FinalHandler.DisplayName)
		src := mdEscape(sourceLabel(r.Source))
		if audit {
			auth := ""
			if r.Auth != nil {
				auth = mdEscape(authLabel(*r.Auth))
			}
			m.printf("| %s | %s | %s | %s | %s | %s |\n", method, path, auth, mw, handler, src)
		} else {
			m.printf("| %s | %s | %s | %s | %s |\n", method, path, mw, handler, src)
		}
	}
	m.printf("\n")
}

func mdMiddlewareList(mw []model.Middleware) string {
	if len(mw) == 0 {
		return "—"
	}
	names := make([]string, len(mw))
	for i, x := range mw {
		names[i] = mdEscape(x.DisplayName)
	}
	return strings.Join(names, " → ")
}

func (m *markdownPrinter) globalMiddleware(rep *report.Report) {
	if len(rep.GlobalMiddleware) == 0 {
		return
	}
	m.printf("## Global middleware (%d)\n\n", len(rep.GlobalMiddleware))
	for _, x := range rep.GlobalMiddleware {
		m.printf("- %s\n", mdCode(x.DisplayName))
	}
	m.printf("\n")
}

func (m *markdownPrinter) fallbackSurfaces(rep *report.Report) {
	if len(rep.FallbackSurfaces) == 0 {
		return
	}
	m.printf("## Fallback surfaces\n\n")
	for _, fb := range rep.FallbackSurfaces {
		m.printf("- %s → %s\n", mdEscape(string(fb.Kind)), mdCode(fb.FinalHandler.DisplayName))
	}
	m.printf("\n")
}

func (m *markdownPrinter) findings(rep *report.Report) {
	m.printf("## Findings (%d)\n\n", len(rep.Findings))
	if len(rep.Findings) == 0 {
		m.printf("_None._\n\n")
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
			route = " · " + mdCode(*f.Route)
		}
		m.printf("- **%s** `%s`%s — %s\n", f.Severity, mdEscape(string(f.RuleID)), route, mdEscape(f.Detail))
		if f.Recommendation != nil && *f.Recommendation != "" {
			m.printf("  - _Recommendation:_ %s\n", mdEscape(*f.Recommendation))
		}
	}
	m.printf("\n")
}

func (m *markdownPrinter) policies(rep *report.Report) {
	if rep.PolicyEvaluation == nil || len(rep.PolicyEvaluation.EvaluatedPolicies) == 0 {
		return
	}
	m.printf("## Policies evaluated\n\n")
	for _, id := range rep.PolicyEvaluation.EvaluatedPolicies {
		m.printf("- %s\n", mdCode(id))
	}
	m.printf("\n")
}

func (m *markdownPrinter) diagnostics(rep *report.Report) {
	if len(rep.Diagnostics) == 0 {
		return
	}
	m.printf("## Diagnostics (%d)\n\n", len(rep.Diagnostics))
	for _, d := range rep.Diagnostics {
		src := sourceLabel(d.Source)
		if src != "" {
			src = " (" + mdEscape(src) + ")"
		}
		m.printf("- **%s** `%s`: %s%s\n", d.Severity, d.Code, mdEscape(d.Message), src)
	}
	m.printf("\n")
}
