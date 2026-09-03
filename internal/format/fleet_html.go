// Package format's fleet HTML formatter (docs/adr/0020-fleet-html-view.md)
// is a self-contained, dependency-free page over one fleet.Aggregate — the
// same offline-by-default, no-CDN posture html.go already applies to
// api.html, not a generated multi-page site. It uses html/template so every
// field (a target name, an error string carrying another process's
// stderr) is contextually auto-escaped rather than hand-escaped per call
// site, since fleet input — a manifest, a target's captured stderr — is
// exactly the kind of untrusted content docs/threat-model.md already
// treats scanned repositories and their output as. Shares its visual
// identity (theme.go) with api.html, so the two read as one tool's output.
package format

import (
	"bytes"
	"html/template"

	"github.com/sagnikhaldar/gin-recon/internal/fleet"
)

var fleetHTMLTemplate = template.Must(template.New("fleet").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>gin-recon fleet report</title>
<style>{{.ThemeCSS}}
.gr-status-ok { color: var(--gr-good); font-weight: 600; }
.gr-status-failed { color: var(--gr-bad); font-weight: 600; }
.gr-status-not-go-module { color: var(--gr-muted); }
.gr-table { width: 100%; border-collapse: collapse; }
.gr-table th, .gr-table td { text-align: left; padding: 8px 16px; border-bottom: 1px solid var(--gr-border); vertical-align: top; font-size: 13px; }
.gr-table th { background: var(--gr-panel-muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.03em; color: var(--gr-muted); }
.gr-table tr:last-child td { border-bottom: none; }
.gr-src { color: var(--gr-muted); font-size: 12px; }
.gr-error { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; white-space: pre-wrap; color: var(--gr-bad); }
.gr-shell code { background: var(--gr-panel-muted); padding: 1px 5px; border-radius: 4px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
</style>
</head>
<body class="gr-shell">
<header class="gr-site-header">
<span class="gr-brand">{{.BrandMark}}<span>gin-recon</span></span>
<div class="gr-header-meta">Generated offline, no network access at view time<br>gin-recon {{.Agg.ToolVersion}}</div>
</header>
<div class="gr-hero">
<p class="gr-eyebrow">Fleet report</p>
<h1>{{len .Agg.Targets}} target{{if ne (len .Agg.Targets) 1}}s{{end}} scanned</h1>
<p class="gr-lede">One audit per target, aggregated. Each target's own full report is untouched under <code>targets/&lt;name&gt;/</code>.</p>
</div>
<div class="gr-metrics">
<div class="gr-metric"><span class="gr-metric__value">{{.OKCount}}</span><span class="gr-metric__label">OK</span></div>
<div class="gr-metric"><span class="gr-metric__value">{{.FailedCount}}</span><span class="gr-metric__label">Failed</span></div>
<div class="gr-metric"><span class="gr-metric__value">{{.NotGoModuleCount}}</span><span class="gr-metric__label">Not a Go module</span></div>
<div class="gr-metric"><span class="gr-metric__value">{{.Agg.Coverage.Complete}}</span><span class="gr-metric__label">Coverage complete</span></div>
</div>
{{if .Agg.Resume.Requested}}<p class="gr-lede" style="margin:8px 24px 0;">Resumed: {{.Agg.Resume.Reused}} target(s) reused from checkpoint.</p>{{end}}
{{if .Agg.Resume.Checkpoint}}<p class="gr-lede" style="margin:4px 24px 0;">Checkpoint retained — this run is not yet complete.</p>{{end}}
<div class="gr-panel">
<h2 class="gr-panel__title">Targets</h2>
<table class="gr-table">
<thead><tr><th>Target</th><th>Status</th><th>Coverage</th><th>Report</th><th>Error</th></tr></thead>
<tbody>
{{range .Agg.Targets}}<tr>
<td><code>{{.Name}}</code><br><span class="gr-src">{{.Src}}</span></td>
<td class="gr-status-{{.Status}}">{{.Status}}</td>
<td>{{.Complete}}</td>
<td>{{if .Report}}<a href="{{.Report}}">routes.json</a>{{end}}</td>
<td class="gr-error">{{.Error}}</td>
</tr>
{{end}}</tbody>
</table>
</div>
{{if .Delta}}
<div class="gr-hero" style="padding-top:8px;">
<p class="gr-eyebrow">Baseline comparison</p>
<h1>What changed since the baseline</h1>
</div>
<div class="gr-metrics">
<div class="gr-metric"><span class="gr-metric__value">{{.Delta.Summary.AddedTargets}}</span><span class="gr-metric__label">Added targets</span></div>
<div class="gr-metric"><span class="gr-metric__value">{{.Delta.Summary.RemovedTargets}}</span><span class="gr-metric__label">Removed targets</span></div>
<div class="gr-metric"><span class="gr-metric__value">{{.Delta.Summary.AddedRoutes}}</span><span class="gr-metric__label">Added routes</span></div>
<div class="gr-metric"><span class="gr-metric__value">{{.Delta.Summary.RemovedRoutes}}</span><span class="gr-metric__label">Removed routes</span></div>
<div class="gr-metric"><span class="gr-badge gr-badge--bad">{{.Delta.Summary.AuthRegressions}} regression(s)</span></div>
<div class="gr-metric"><span class="gr-badge gr-badge--good">{{.Delta.Summary.AuthImprovements}} improvement(s)</span></div>
</div>
{{if .Delta.Summary.IncomparableTargets}}<p class="gr-lede" style="margin:8px 24px 0;">{{.Delta.Summary.IncomparableTargets}} target(s) could not be compared — see the reason column below.</p>{{end}}
<div class="gr-panel">
<h2 class="gr-panel__title">Per-target delta</h2>
<table class="gr-table">
<thead><tr><th>Target</th><th>Status</th><th>Added routes</th><th>Removed routes</th><th>Auth regressions</th><th>Reason</th></tr></thead>
<tbody>
{{range .Delta.Targets}}<tr>
<td><code>{{.Name}}</code></td>
<td>{{.Status}}</td>
<td>{{if .Delta}}{{range .Delta.AddedRoutes}}{{.}}<br>{{end}}{{end}}</td>
<td>{{if .Delta}}{{range .Delta.RemovedRoutes}}{{.}}<br>{{end}}{{end}}</td>
<td>{{if .Delta}}{{if .Delta.AuthRegressions}}<span class="gr-badge gr-badge--bad">{{len .Delta.AuthRegressions}}</span>{{end}}{{end}}</td>
<td class="gr-error">{{.Reason}}</td>
</tr>
{{end}}</tbody>
</table>
</div>
{{end}}
<p class="gr-footer">gin-recon {{.Agg.ToolVersion}} &middot; static analysis only, no target code was executed</p>
</body>
</html>
`))

// fleetHTMLData is the template's input: the aggregate every fleet run
// produces, plus the delta only a --baseline run also produces, plus
// pre-computed status counts for the metrics row (html/template has no
// convenient count-by-predicate of its own).
type fleetHTMLData struct {
	Agg              *fleet.Aggregate
	Delta            *fleet.FleetDelta
	ThemeCSS         template.CSS
	BrandMark        template.HTML
	OKCount          int
	FailedCount      int
	NotGoModuleCount int
}

// FleetHTML renders agg (and, when a --baseline was given, delta) as the
// browsable companion fleet.json always gets
// (docs/adr/0020-fleet-html-view.md, docs/adr/0022-fleet-baseline-delta.md) —
// generated directly from the same values being marshaled to JSON, nothing
// re-read from disk.
func FleetHTML(agg *fleet.Aggregate, delta *fleet.FleetDelta) ([]byte, error) {
	data := fleetHTMLData{
		Agg:       agg,
		Delta:     delta,
		ThemeCSS:  template.CSS(themeCSS),
		BrandMark: template.HTML(brandMarkHTML),
	}
	for _, t := range agg.Targets {
		switch t.Status {
		case fleet.StatusOK:
			data.OKCount++
		case fleet.StatusFailed:
			data.FailedCount++
		case fleet.StatusNotGoModule:
			data.NotGoModuleCount++
		}
	}

	var buf bytes.Buffer
	if err := fleetHTMLTemplate.Execute(&buf, data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
