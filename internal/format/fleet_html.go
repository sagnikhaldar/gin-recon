// Package format's fleet HTML formatter (docs/adr/0020-fleet-html-view.md)
// is a self-contained, dependency-free page over one fleet.Aggregate — the
// same offline-by-default, no-CDN posture html.go already applies to
// api.html, not a generated multi-page site (that half of the decision
// stands regardless of how much richer the one page itself gets). It uses
// html/template so every field (a target name, an error string carrying
// another process's stderr) is contextually auto-escaped rather than
// hand-escaped per call site, since fleet input — a manifest, a target's
// captured stderr — is exactly the kind of untrusted content
// docs/threat-model.md already treats scanned repositories and their
// output as. Shares its visual identity (theme.go) with api.html, so the
// two read as one tool's output.
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
<title>{{if .Scope}}{{.Scope.Org}} · {{end}}gin-recon fleet report</title>
<style>{{.ThemeCSS}}
.gr-table { width: 100%; border-collapse: collapse; }
.gr-table th, .gr-table td { text-align: left; padding: 8px 16px; border-bottom: 1px solid var(--gr-border); vertical-align: top; font-size: 13px; }
.gr-table th { background: var(--gr-panel-muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.03em; color: var(--gr-muted); }
.gr-table td.gr-num { text-align: right; font-variant-numeric: tabular-nums; }
.gr-table tr:last-child td { border-bottom: none; }
.gr-table tr[hidden] { display: none; }
.gr-src { color: var(--gr-muted); font-size: 12px; }
.gr-count { color: var(--gr-muted); }
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
{{if .Scope}}
<p class="gr-eyebrow">{{.GitMark}} GitHub organization inventory</p>
<h1>{{.Scope.Org}}</h1>
<p class="gr-lede">{{len .Agg.Targets}} discovered repositor{{if eq (len .Agg.Targets) 1}}y{{else}}ies{{end}}, one audit per target. Each target's own raw report lives under <code>{{$.RawDirLink}}/targets/&lt;name&gt;/</code>, untouched.</p>
{{else}}
<p class="gr-eyebrow">Fleet report</p>
<h1>{{len .Agg.Targets}} target{{if ne (len .Agg.Targets) 1}}s{{end}} scanned</h1>
<p class="gr-lede">One audit per target, aggregated. Each target's own raw report lives under <code>{{$.RawDirLink}}/targets/&lt;name&gt;/</code>, untouched.</p>
{{end}}
</div>
<div class="gr-metrics">
<div class="gr-metric"><span class="gr-metric__value">{{len .Agg.Targets}}</span><span class="gr-metric__label">Targets</span></div>
<div class="gr-metric"><span class="gr-metric__value">{{.OKCount}}</span><span class="gr-metric__label">OK</span></div>
<div class="gr-metric"><span class="gr-metric__value">{{.FailedCount}}</span><span class="gr-metric__label">Failed</span></div>
<div class="gr-metric"><span class="gr-metric__value">{{.NotGoModuleCount}}</span><span class="gr-metric__label">Not a Go module</span></div>
<div class="gr-metric"><span class="gr-metric__value">{{.Agg.Coverage.Complete}}</span><span class="gr-metric__label">Coverage complete</span></div>
<div class="gr-metric"><span class="gr-metric__value">{{.Agg.Totals.Routes}}</span><span class="gr-metric__label">Routes</span></div>
<div class="gr-metric"><span class="gr-metric__value">{{.Agg.Totals.Proven}}</span><span class="gr-metric__label">Proven</span></div>
<div class="gr-metric"><span class="gr-metric__value">{{.Agg.Totals.Public}}</span><span class="gr-metric__label">Public</span></div>
<div class="gr-metric"><span class="gr-metric__value">{{.Agg.Totals.Unknown}}</span><span class="gr-metric__label">Unknown</span></div>
</div>
{{if .Agg.Resume.Requested}}<p class="gr-lede" style="margin:8px 24px 0;">Resumed: {{.Agg.Resume.Reused}} target(s) reused from checkpoint.</p>{{end}}
{{if .Agg.Resume.Checkpoint}}<p class="gr-lede" style="margin:4px 24px 0;">Checkpoint retained — this run is not yet complete.</p>{{end}}
{{if not .Agg.AuthConfig.MiddlewareCount}}<p class="gr-lede" style="margin:4px 24px 0;">No <code>authMiddleware</code> configured for this run — every route below defaults to <strong>public</strong> or <strong>unknown</strong>; Proven can only ever be non-zero once <code>--config</code> names the actual auth-middleware symbols these targets call.</p>{{end}}
{{if .Scope}}
<div class="gr-panel">
<h2 class="gr-panel__title">Scope</h2>
<dl class="gr-key-values">
<dt>Organization</dt><dd>{{.Scope.Org}}</dd>
<dt>Concurrency</dt><dd>{{.Scope.Concurrency}}</dd>
<dt>Repository cap</dt><dd>{{.Scope.MaxRepos}}</dd>
<dt>Include archived</dt><dd>{{.Scope.IncludeArchived}}</dd>
<dt>Include forks</dt><dd>{{.Scope.IncludeForks}}</dd>
{{if .Scope.RepoInclude}}<dt>Repo include</dt><dd>{{range $i, $p := .Scope.RepoInclude}}{{if $i}}, {{end}}{{$p}}{{end}}</dd>{{end}}
{{if .Scope.RepoExclude}}<dt>Repo exclude</dt><dd>{{range $i, $p := .Scope.RepoExclude}}{{if $i}}, {{end}}{{$p}}{{end}}</dd>{{end}}
{{if .Scope.DiscoveryCompleteKnown}}<dt>Enumeration coverage</dt><dd>{{if .Scope.DiscoveryComplete}}<span class="gr-badge gr-badge--good">complete</span>{{else}}<span class="gr-badge gr-badge--warn">incomplete</span>{{end}}</dd>{{end}}
</dl>
</div>
{{end}}
<div class="gr-panel">
<h2 class="gr-panel__title">Configuration</h2>
<dl class="gr-key-values">
<dt>authMiddleware configured</dt><dd>{{.Agg.AuthConfig.MiddlewareCount}}</dd>
<dt>authWrappers configured</dt><dd>{{.Agg.AuthConfig.WrappersCount}}</dd>
{{if .TargetConfigCount}}<dt>Targets using their own repo-committed config</dt><dd>{{.TargetConfigCount}} of {{len .Agg.Targets}} — reviewed by whoever committed it to that repository, not necessarily independently of it</dd>{{end}}
{{if .TargetConfigDirCount}}<dt>Targets using an operator-owned config</dt><dd>{{.TargetConfigDirCount}} of {{len .Agg.Targets}} — from --target-config-dir, never sourced from the scanned repository itself</dd>{{end}}
</dl>
</div>
<div class="gr-panel">
<h2 class="gr-panel__title">Targets</h2>
<div class="gr-filters" data-gr-filter="gr-targets-table">
<div><label for="gr-target-search">Search</label><input id="gr-target-search" type="search" placeholder="Target, status, error…" data-gr-filter-search></div>
<div><label for="gr-target-status">Status</label><select id="gr-target-status" data-gr-filter-status><option value="">All statuses</option><option value="ok">ok</option><option value="failed">failed</option><option value="not-go-module">not-go-module</option></select></div>
<span class="gr-result-count" data-gr-result-count aria-live="polite"></span>
</div>
<div class="gr-table-wrap">
<table class="gr-table" id="gr-targets-table">
<thead><tr><th>Target</th><th>Status</th><th>Coverage</th><th>Routes</th><th>Proven</th><th>Public</th><th>Unknown</th><th>Report</th><th>Error</th></tr></thead>
<tbody>
{{range .Agg.Targets}}<tr data-gr-search="{{.Name}} {{.Status}} {{.Error}}" data-gr-status="{{.Status}}">
<td><code>{{.Name}}</code>{{if .TargetConfigDir}} <span class="gr-badge gr-badge--good" title="Used an operator-owned config from --target-config-dir, never sourced from this repository">own config (dir)</span>{{else if .TargetConfig}} <span class="gr-badge gr-badge--neutral" title="Used this target's own committed config instead of the fleet-wide --config">own config (repo)</span>{{end}}<br>{{if .GitURL}}<span class="gr-src">{{$.GitMark}} {{.GitURL}}</span>{{else}}<span class="gr-src">{{.Src}}</span>{{end}}</td>
<td>{{if eq .Status "ok"}}<span class="gr-badge gr-badge--good">{{.Status}}</span>{{else if eq .Status "failed"}}<span class="gr-badge gr-badge--bad">{{.Status}}</span>{{else}}<span class="gr-badge gr-badge--neutral">{{.Status}}</span>{{end}}</td>
<td>{{if eq .Status "ok"}}{{if .Complete}}<span class="gr-badge gr-badge--good">complete</span>{{else}}<span class="gr-badge gr-badge--warn">incomplete</span>{{end}}{{else}}<span class="gr-count">&mdash;</span>{{end}}</td>
<td class="gr-num">{{if .Routes}}{{.Routes}}{{else}}<span class="gr-count">0</span>{{end}}</td>
<td class="gr-num">{{if .Proven}}<span class="gr-badge gr-badge--good">{{.Proven}}</span>{{else}}<span class="gr-count">0</span>{{end}}</td>
<td class="gr-num">{{if .Public}}<span class="gr-badge gr-badge--warn">{{.Public}}</span>{{else}}<span class="gr-count">0</span>{{end}}</td>
<td class="gr-num">{{if .Unknown}}<span class="gr-badge gr-badge--warn">{{.Unknown}}</span>{{else}}<span class="gr-count">0</span>{{end}}</td>
<td>{{if .Report}}<a href="{{$.RawDirLink}}/{{.Report}}">routes.json</a>{{end}}{{if .APIHTML}} &middot; <a href="{{.APIHTML}}">api.html</a>{{end}}</td>
<td class="gr-error">{{.Error}}</td>
</tr>
{{end}}</tbody>
</table>
</div>
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
<div class="gr-table-wrap">
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
</div>
{{end}}
<p class="gr-footer">gin-recon {{.Agg.ToolVersion}} &middot; static analysis only, no target code was executed</p>
<script>{{.FilterJS}}</script>
</body>
</html>
`))

// fleetFilterJS is a small, hand-written vanilla-JS live filter for the
// targets table (search text + status dropdown), the same general
// data-attribute technique a table filter always uses — no library, no
// external script, and no target-derived value is ever written back as
// markup: it only ever reads data-gr-search/data-gr-status attributes
// html/template already escaped when the page was built, and only ever
// toggles the standard `hidden` attribute.
const fleetFilterJS = `
(function () {
  "use strict";
  document.querySelectorAll("[data-gr-filter]").forEach(function (controls) {
    var table = document.getElementById(controls.dataset.grFilter);
    if (!table) return;
    var rows = Array.prototype.slice.call(table.querySelectorAll("tbody tr[data-gr-search]"));
    var search = controls.querySelector("[data-gr-filter-search]");
    var status = controls.querySelector("[data-gr-filter-status]");
    var count = controls.querySelector("[data-gr-result-count]");

    function update() {
      var query = (search && search.value || "").trim().toLowerCase();
      var selected = (status && status.value) || "";
      var visible = 0;
      rows.forEach(function (row) {
        var matchesQuery = !query || row.dataset.grSearch.toLowerCase().indexOf(query) !== -1;
        var matchesStatus = !selected || row.dataset.grStatus === selected;
        var show = matchesQuery && matchesStatus;
        row.hidden = !show;
        if (show) visible++;
      });
      if (count) count.textContent = visible + " of " + rows.length;
    }

    if (search) search.addEventListener("input", update);
    if (status) status.addEventListener("change", update);
    update();
  });
})();
`

// fleetHTMLData is the template's input: the aggregate every fleet run
// produces, plus the delta only a --baseline run also produces, plus
// pre-computed status counts for the metrics row (html/template has no
// convenient count-by-predicate of its own).
type fleetHTMLData struct {
	Agg                  *fleet.Aggregate
	Delta                *fleet.FleetDelta
	Scope                *fleet.Scope
	RawDirLink           string // relative path from this page back to --out (docs/adr/0023-fleet-raw-rendered-split.md); plain string, auto-escaped like any other URL-context value
	ThemeCSS             template.CSS
	BrandMark            template.HTML
	GitMark              template.HTML
	FilterJS             template.JS
	OKCount              int
	FailedCount          int
	NotGoModuleCount     int
	TargetConfigCount    int
	TargetConfigDirCount int
}

// FleetHTML renders agg (and, when given, delta/scope) as the browsable
// companion fleet.json always gets (docs/adr/0020-fleet-html-view.md,
// docs/adr/0022-fleet-baseline-delta.md, docs/adr/0021-fleet-org-enumeration.md).
// rawDirLink is this page's relative path back to --out
// (docs/adr/0023-fleet-raw-rendered-split.md), used to link each target's
// raw routes.json across the raw/rendered directory split — everything
// else is generated directly from the same values being marshaled to
// JSON, nothing re-read from disk. scope is nil for a --targets run;
// non-nil for --org.
func FleetHTML(agg *fleet.Aggregate, delta *fleet.FleetDelta, scope *fleet.Scope, rawDirLink string) ([]byte, error) {
	data := fleetHTMLData{
		Agg:        agg,
		Delta:      delta,
		Scope:      scope,
		RawDirLink: rawDirLink,
		ThemeCSS:   template.CSS(themeCSS),
		BrandMark:  template.HTML(brandMarkHTML),
		GitMark:    template.HTML(gitMarkHTML),
		FilterJS:   template.JS(fleetFilterJS),
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
		if t.TargetConfig {
			data.TargetConfigCount++
		}
		if t.TargetConfigDir {
			data.TargetConfigDirCount++
		}
	}

	var buf bytes.Buffer
	if err := fleetHTMLTemplate.Execute(&buf, data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
