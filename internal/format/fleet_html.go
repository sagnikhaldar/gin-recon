// Package format's fleet HTML formatter is the opt-in rendered companion to
// one fleet.Aggregate (docs/adr/0037-fleet-html-opt-in.md). It keeps the same
// offline-by-default, no-CDN posture html.go applies to api.html and the raw /
// rendered directory split from docs/adr/0023-fleet-raw-rendered-split.md. It uses
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
	"fmt"
	"html/template"

	"github.com/sagnikhaldar/gin-recon/internal/fleet"
	"github.com/sagnikhaldar/gin-recon/internal/model"
)

var fleetHTMLTemplate = template.Must(template.New("fleet").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{if .Scope}}{{.Scope.Org}} · {{end}}gin-recon fleet report</title>
<style>{{.ThemeCSS}}
.gr-jump { display:flex; gap:6px; flex-wrap:wrap; padding:10px 0 0; }
.gr-jump a { border:1px solid var(--gr-border); border-radius:999px; padding:5px 10px; color:var(--gr-muted); background:var(--gr-panel); font-size:12px; font-weight:650; text-decoration:none; }
.gr-jump a:hover { border-color:var(--gr-accent); color:var(--gr-link); }
.gr-overview { display:grid; grid-template-columns:minmax(0, 1fr) auto; gap:14px; align-items:center; margin:12px 0 0; padding:11px 14px; border:1px solid var(--gr-border); border-radius:10px; background:var(--gr-panel); }
.gr-overview__label { color:var(--gr-muted); font-size:12px; }
.gr-evidence-rollup { display:flex; gap:8px; flex-wrap:wrap; justify-content:flex-end; }
.gr-notice { margin:14px 0 0; padding:11px 14px; border:1px solid var(--gr-border); border-left:4px solid var(--gr-accent); border-radius:8px; background:var(--gr-accent-soft); color:var(--gr-muted); font-size:13px; }
.gr-notice--warn { border-left-color:var(--gr-warn); background:var(--gr-warn-soft); color:var(--gr-ink); }
.gr-notice--bad { border-left-color:var(--gr-bad); background:var(--gr-bad-soft); color:var(--gr-ink); }
.gr-table { width:100%; border-collapse:collapse; }
.gr-table th, .gr-table td { text-align:left; padding:10px 14px; border-bottom:1px solid var(--gr-border); vertical-align:top; font-size:13px; }
.gr-table th { background:var(--gr-panel-muted); font-size:11px; text-transform:uppercase; letter-spacing:.045em; color:var(--gr-muted); }
.gr-table td.gr-num { text-align: right; font-variant-numeric: tabular-nums; }
.gr-table tr:last-child td { border-bottom: none; }
.gr-table tr[hidden] { display: none; }
.gr-table tbody tr:not(.gr-status-group):hover { background:color-mix(in srgb, var(--gr-accent-soft) 42%, transparent); }
.gr-status-group th { padding:8px 14px; color:var(--gr-ink); font-size:12px; text-transform:none; letter-spacing:0; }
.gr-target { min-width:240px; }
.gr-auth-counts { min-width:160px; }
.gr-auth-counts span + span::before { content:" · "; color:var(--gr-muted); }
.gr-src { color: var(--gr-muted); font-size: 12px; }
.gr-count { color: var(--gr-muted); }
.gr-error { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; white-space: pre-wrap; color: var(--gr-bad); }
.gr-shell code { background: var(--gr-panel-muted); padding: 1px 5px; border-radius: 4px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
.gr-callout { margin:12px 16px 0; padding:10px 12px; border:1px solid var(--gr-border); border-radius:6px; background:var(--gr-panel-muted); }
.gr-callout--warn { border-color: var(--gr-warn); }
.gr-details { padding: 0; }
.gr-details > summary { cursor:pointer; padding:16px; font-weight:650; list-style-position:inside; }
.gr-details[open] > summary { border-bottom: 1px solid var(--gr-border); }
.gr-evidence { min-width:140px; }
.gr-evidence > summary { cursor:pointer; color:var(--gr-link); font-weight:650; }
.gr-evidence__body { display:grid; gap:7px; margin-top:8px; min-width:220px; }
.gr-evidence__links { display:flex; flex-wrap:wrap; gap:5px 10px; }
.gr-empty { margin:0; padding:22px 16px; color:var(--gr-muted); text-align:center; }
.gr-section-spacer { scroll-margin-top:16px; }
@media (max-width:720px) {
  .gr-overview { grid-template-columns:1fr; }
  .gr-evidence-rollup { justify-content:flex-start; }
  .gr-jump { flex-wrap:nowrap; overflow-x:auto; padding-bottom:4px; }
  .gr-jump a { white-space:nowrap; }
  .gr-table th, .gr-table td { padding:9px 11px; }
}
@media print { .gr-jump, .gr-filters { display:none; } }
</style>
</head>
<body class="gr-shell">
<header class="gr-site-header">
<div class="gr-page gr-site-header__inner"><span class="gr-brand">{{.BrandMark}}<span>gin-recon</span></span>
<div class="gr-header-meta">Offline fleet evidence<br>gin-recon {{.Agg.ToolVersion}}</div></div>
</header>
<main class="gr-page gr-main">
<div class="gr-hero" id="overview">
{{if .Scope}}
<p class="gr-eyebrow">{{.GitMark}} GitHub organization inventory</p>
<h1>{{.Scope.Org}}</h1>
<p class="gr-lede">{{len .Agg.Targets}} selected repositor{{if eq (len .Agg.Targets) 1}}y{{else}}ies{{end}} audited; {{.WithRoutesCount}} produced observed Gin routes. Every selected target remains in the raw aggregate, including reference and unsuccessful outcomes. Raw reports live under <code>{{$.RawDirLink}}/targets/&lt;name&gt;/</code>.</p>
{{else}}
<p class="gr-eyebrow">Fleet report</p>
<h1>{{len .Agg.Targets}} target{{if ne (len .Agg.Targets) 1}}s{{end}} scanned</h1>
<p class="gr-lede">{{.WithRoutesCount}} target{{if ne .WithRoutesCount 1}}s{{end}} produced observed Gin routes. Every target remains in the raw aggregate, including reference and unsuccessful outcomes. Raw reports live under <code>{{$.RawDirLink}}/targets/&lt;name&gt;/</code>.</p>
{{end}}
<nav class="gr-jump" aria-label="Report sections"><a href="#repositories">Route evidence</a><a href="#reference-results">Reference results</a>{{if .Delta}}<a href="#baseline">Baseline</a>{{end}}<a href="#run-details">Run details</a></nav>
</div>
{{if or (not .Agg.Coverage.Complete) .IncompleteTargetCount}}
<div class="gr-notice gr-notice--warn" role="status"><strong>Incomplete fleet evidence.</strong> Fleet coverage is incomplete; {{.IncompleteTargetCount}} target record{{if ne .IncompleteTargetCount 1}}s{{end}} lack{{if eq .IncompleteTargetCount 1}}s{{end}} a complete terminal result. Keep partial route evidence visible, but do not read absence of routes as absence of an HTTP surface.</div>
{{end}}
<div class="gr-metrics">
<div class="gr-metric"><span class="gr-metric__value">{{len .Agg.Targets}}</span><span class="gr-metric__label">Audit targets</span></div>
<div class="gr-metric"><span class="gr-metric__value">{{.CompleteTargetCount}}</span><span class="gr-metric__label">Complete targets</span></div>
<div class="gr-metric"><span class="gr-metric__value">{{.IncompleteTargetCount}}</span><span class="gr-metric__label">Incomplete targets</span></div>
<div class="gr-metric"><span class="gr-metric__value">{{.WithRoutesCount}}</span><span class="gr-metric__label">With observed routes</span></div>
<div class="gr-metric"><span class="gr-metric__value">{{.Agg.Totals.Routes}}</span><span class="gr-metric__label">Routes</span></div>
<div class="gr-metric"><span class="gr-metric__value">{{.SpecificationDocumentCount}}</span><span class="gr-metric__label">OpenAPI/Swagger docs found</span></div>
</div>
<div class="gr-overview"><span class="gr-overview__label">Route authentication evidence across observed routes</span><div class="gr-evidence-rollup"><span class="gr-badge gr-badge--good">{{.Agg.Totals.Proven}} proven</span><span class="gr-badge gr-badge--warn">{{.Agg.Totals.Public}} public</span><span class="gr-badge gr-badge--warn">{{.Agg.Totals.Unknown}} unknown</span></div></div>
<div class="gr-overview"><span class="gr-overview__label">OpenAPI/Swagger documentation coverage</span><div class="gr-evidence-rollup"><span class="gr-badge {{if .SpecificationRepositoriesCount}}gr-badge--good{{else}}gr-badge--warn{{end}}">{{.SpecificationCoverageText}} of successfully-scanned repositories carry at least one specification</span></div></div>
{{if and (not .Agg.AuthConfig.MiddlewareCount) (not .TargetConfigCount) (not .TargetConfigDirCount) (not .Agg.Totals.Proven)}}<div class="gr-notice"><strong>No <code>authMiddleware</code> configured.</strong> Every route below defaults to <strong>public</strong> or <strong>unknown</strong>; Proven can only ever be non-zero once <code>--config</code> names the actual auth-middleware symbols these targets call.</div>{{end}}
<section class="gr-panel gr-section-spacer" id="repositories">
<h2 class="gr-panel__title">Repositories with observed routes <span class="gr-count">({{.WithRoutesCount}})</span></h2>
<p class="gr-lede" style="margin:0;padding:12px 16px 0;">Observed route evidence is primary. “Complete” means both process status <code>ok</code> and complete analysis coverage; partial routes remain visible under “Incomplete.”</p>
<div class="gr-filters" data-gr-filter="gr-route-targets-table">
<div><label for="gr-route-target-search">Search</label><div class="gr-search-control"><input id="gr-route-target-search" type="search" placeholder="Target, status, error…" data-gr-filter-search><button class="gr-search-clear" type="button" data-gr-filter-clear aria-label="Clear route repository search" hidden>&times;</button></div></div>
<div><label for="gr-route-target-status">Status</label><select id="gr-route-target-status" data-gr-filter-status><option value="">All statuses</option><option value="ok">ok</option><option value="failed">failed</option><option value="inconclusive">inconclusive</option><option value="not-go-module">not-go-module</option></select></div>
<div><label for="gr-route-target-completion">Completion</label><select id="gr-route-target-completion" data-gr-filter-completion><option value="">All completion</option><option value="complete">complete</option><option value="incomplete">incomplete</option></select></div>
<div><label for="gr-route-target-framework">Framework</label><select id="gr-route-target-framework" data-gr-filter-framework><option value="">All frameworks</option><option value="gin">Gin</option><option value="go">Go / non-Gin</option></select></div>
<div><label for="gr-route-target-docs">API docs</label><select id="gr-route-target-docs" data-gr-filter-docs><option value="">All</option><option value="openapi3">OpenAPI3</option><option value="swagger2">Swagger2</option><option value="both">Both</option><option value="none">None</option><option value="unavailable">Unavailable</option></select></div>
<div><label for="gr-route-target-evidence">Auth evidence</label><select id="gr-route-target-evidence" data-gr-filter-evidence><option value="">Any evidence</option><option value="proven">Has proven</option><option value="public">Has public</option><option value="unknown">Has unknown</option></select></div>
<span class="gr-result-count" data-gr-result-count aria-live="polite"></span>
</div>
<div class="gr-table-wrap">
<table class="gr-table" id="gr-route-targets-table">
<thead><tr><th>Repository</th><th>Audit</th><th>Routes</th><th>Authentication evidence</th><th>API documentation</th><th>Evidence</th></tr></thead>
<tbody>
<tr class="gr-status-group" data-gr-group="complete"><th colspan="6">Complete — status ok + coverage complete ({{len .RouteCompleteTargets}})</th></tr>
{{range .RouteCompleteTargets}}{{template "route-target" .}}{{end}}
<tr class="gr-status-group" data-gr-group="incomplete"><th colspan="6">Incomplete — process or coverage incomplete ({{len .RouteIncompleteTargets}})</th></tr>
{{range .RouteIncompleteTargets}}{{template "route-target" .}}{{end}}
</tbody>
</table>
</div>
<p class="gr-empty" data-gr-filter-empty hidden>No repositories match these filters.</p>
</section>
<details class="gr-panel gr-details gr-section-spacer" id="reference-results">
<summary>Reference results ({{.ReferenceCount}})</summary>
<p class="gr-lede" style="margin:0;padding:12px 16px 0;">These targets have no observed Gin routes. The category distinguishes complete Gin zero-route evidence from non-Gin Go modules, non-Go repositories, failed or inconclusive audits, and incomplete or metadata-free results that cannot safely be called clean.</p>
<div class="gr-filters" data-gr-filter="gr-reference-targets-table">
<div><label for="gr-reference-search">Search</label><div class="gr-search-control"><input id="gr-reference-search" type="search" placeholder="Target, category, status, error…" data-gr-filter-search><button class="gr-search-clear" type="button" data-gr-filter-clear aria-label="Clear reference repository search" hidden>&times;</button></div></div>
<div><label for="gr-reference-category">Category</label><select id="gr-reference-category" data-gr-filter-category><option value="">All categories</option><option value="gin-no-routes">Gin detected, no routes</option><option value="no-routes-unverified">No routes, unverified</option><option value="non-gin">Non-Gin Go</option><option value="not-go-module">Not a Go module</option><option value="failed">Failed</option><option value="inconclusive">Inconclusive</option></select></div>
<div><label for="gr-reference-framework">Framework</label><select id="gr-reference-framework" data-gr-filter-framework><option value="">All frameworks</option><option value="gin">Gin</option><option value="go">Go / non-Gin</option></select></div>
<div><label for="gr-reference-docs">API docs</label><select id="gr-reference-docs" data-gr-filter-docs><option value="">All</option><option value="openapi3">OpenAPI3</option><option value="swagger2">Swagger2</option><option value="both">Both</option><option value="none">None</option><option value="unavailable">Unavailable</option></select></div>
<span class="gr-result-count" data-gr-result-count aria-live="polite"></span>
</div>
<div class="gr-table-wrap">
<table class="gr-table" id="gr-reference-targets-table">
<thead><tr><th>Repository</th><th>Category</th><th>Audit</th><th>API documentation</th><th>Evidence</th></tr></thead>
<tbody>
{{range .ReferenceTargets}}<tr data-gr-search="{{.Name}} {{.Category}} {{.CategoryLabel}} {{.Status}} {{.Error}} {{.Framework}} {{.DocsClass}}" data-gr-status="{{.Status}}" data-gr-category="{{.Category}}" data-gr-framework="{{.Framework}}" data-gr-docs="{{.DocsClass}}">
<td class="gr-target"><code>{{.Name}}</code>{{if .TargetConfigDir}} <span class="gr-badge gr-badge--good" title="Used an operator-owned config from --target-config-dir, never sourced from this repository">own config (dir)</span>{{else if .TargetConfig}} <span class="gr-badge gr-badge--neutral" title="Used this target's own committed config instead of the fleet-wide --config">own config (repo)</span>{{end}}<br>{{if .GitURL}}<span class="gr-src">{{$.GitMark}} {{.GitURL}}</span>{{else}}<span class="gr-src">{{.Src}}</span>{{end}}{{if .Inventory.Kind}} <span class="gr-src">&middot; {{.Inventory.Kind}}</span>{{end}}</td>
<td><span class="gr-badge gr-badge--neutral">{{.CategoryLabel}}</span></td>
<td>{{if eq .Status "ok"}}<span class="gr-badge gr-badge--good">{{.Status}}</span>{{else if eq .Status "failed"}}<span class="gr-badge gr-badge--bad">{{.Status}}</span>{{else}}<span class="gr-badge gr-badge--neutral">{{.Status}}</span>{{end}} {{if and .Complete (or (eq .Status "ok") (eq .Status "not-go-module"))}}<span class="gr-badge gr-badge--good">complete</span>{{else}}<span class="gr-badge gr-badge--warn">incomplete</span>{{end}}</td>
<td>{{if .DocModules}}<details><summary>{{.DocsLabel}}</summary><div class="gr-evidence__body">{{range .DocModules}}<div><strong>{{.ModulePath}}</strong>: source files {{.SourceCoverage}}; observed API operations documented {{.OperationCoverage}}{{if .IncompleteScope}} <span class="gr-badge gr-badge--warn">incomplete scope</span>{{end}}</div>{{if .Specifications}}<label>Specification <select>{{range .Specifications}}<option>{{.Title}} {{.APIVersion}} · {{.Dialect}} {{.Version}} · {{.Path}} · {{.Authorship}}</option>{{end}}</select></label>{{else}}<div class="gr-src">No source specification discovered.</div>{{end}}{{end}}</div></details>{{else}}<span class="gr-src">N/A</span>{{end}}</td>
<td class="gr-evidence">{{if .APIHTML}}<a href="{{.APIHTML}}">Browse API</a>{{end}}<details><summary>Supporting evidence{{if .Error}} + error{{end}}</summary><div class="gr-evidence__body">{{if .Modules}}{{range .Modules}}<div><code>{{.Path}}</code>{{if .Kind}} <span class="gr-src">{{.Kind}}</span>{{end}} <span class="gr-evidence__links">{{if .Report}}<a href="{{$.RawDirLink}}/{{.Report}}">routes.json</a>{{end}}{{if .APIHTML}}<a href="{{.APIHTML}}">api.html</a>{{end}}</span></div>{{end}}{{else}}<div class="gr-evidence__links">{{if .Report}}<a href="{{$.RawDirLink}}/{{.Report}}">routes.json</a>{{end}}{{if .APIHTML}}<a href="{{.APIHTML}}">api.html</a>{{end}}</div>{{end}}{{if .Error}}<div class="gr-error">{{.Error}}</div>{{end}}</div></details></td>
</tr>
{{end}}</tbody>
</table>
</div>
<p class="gr-empty" data-gr-filter-empty hidden>No reference results match these filters.</p>
</details>
{{define "route-target"}}<tr data-gr-search="{{.Name}} {{.Status}} {{.Error}} {{.Framework}} {{.DocsClass}}" data-gr-status="{{.Status}}" data-gr-completion="{{.AuditGroup}}" data-gr-framework="{{.Framework}}" data-gr-docs="{{.DocsClass}}" data-gr-proven="{{if .Proven}}yes{{end}}" data-gr-public="{{if .Public}}yes{{end}}" data-gr-unknown="{{if .Unknown}}yes{{end}}">
<td class="gr-target"><code>{{.Name}}</code>{{if .TargetConfigDir}} <span class="gr-badge gr-badge--good" title="Used an operator-owned config from --target-config-dir, never sourced from this repository">own config (dir)</span>{{else if .TargetConfig}} <span class="gr-badge gr-badge--neutral" title="Used this target's own committed config instead of the fleet-wide --config">own config (repo)</span>{{end}}<br>{{if .GitURL}}<span class="gr-src">{{$.GitMark}} {{.GitURL}}</span>{{else}}<span class="gr-src">{{.Src}}</span>{{end}}{{if .Inventory.Kind}} <span class="gr-src">&middot; {{.Inventory.Kind}}</span>{{end}}</td>
<td>{{if eq .Status "ok"}}<span class="gr-badge gr-badge--good">{{.Status}}</span>{{else if eq .Status "failed"}}<span class="gr-badge gr-badge--bad">{{.Status}}</span>{{else}}<span class="gr-badge gr-badge--neutral">{{.Status}}</span>{{end}} {{if eq .AuditGroup "complete"}}<span class="gr-badge gr-badge--good">complete</span>{{else}}<span class="gr-badge gr-badge--warn">incomplete</span>{{end}}</td>
<td class="gr-num">{{.Routes}}</td>
<td class="gr-auth-counts"><span><span class="gr-badge gr-badge--good">{{.Proven}}</span> proven</span><span><span class="gr-badge gr-badge--warn">{{.Public}}</span> public</span><span><span class="gr-badge gr-badge--warn">{{.Unknown}}</span> unknown</span></td>
<td>{{if .DocModules}}<details><summary>{{.DocsLabel}}</summary><div class="gr-evidence__body">{{range .DocModules}}<div><strong>{{.ModulePath}}</strong>: source files {{.SourceCoverage}}; observed API operations documented {{.OperationCoverage}}{{if .IncompleteScope}} <span class="gr-badge gr-badge--warn">incomplete scope</span>{{end}}</div>{{if .Specifications}}<label>Specification <select>{{range .Specifications}}<option>{{.Title}} {{.APIVersion}} · {{.Dialect}} {{.Version}} · {{$.Name}}/{{.Path}} · {{.Authorship}}</option>{{end}}</select></label>{{else}}<div class="gr-src">No source specification discovered.</div>{{end}}{{end}}</div></details>{{else}}<span class="gr-src">N/A</span>{{end}}</td>
<td class="gr-evidence">{{if .APIHTML}}<a href="{{.APIHTML}}">Browse API</a>{{end}}<details><summary>Supporting evidence{{if .Error}} + error{{end}}</summary><div class="gr-evidence__body">{{if .Modules}}{{range .Modules}}<div><code>{{.Path}}</code>{{if .Kind}} <span class="gr-src">{{.Kind}}</span>{{end}} <span class="gr-evidence__links">{{if .Report}}<a href="{{$.RawDirLink}}/{{.Report}}">routes.json</a>{{end}}{{if .APIHTML}}<a href="{{.APIHTML}}">api.html</a>{{end}}</span></div>{{end}}{{else}}<div class="gr-evidence__links">{{if .Report}}<a href="{{.RawDirLink}}/{{.Report}}">routes.json</a>{{end}}{{if .APIHTML}}<a href="{{.APIHTML}}">api.html</a>{{end}}</div>{{end}}{{if .Error}}<div class="gr-error">{{.Error}}</div>{{end}}</div></details></td>
</tr>{{end}}
{{if .Delta}}
<div class="gr-hero gr-section-spacer" id="baseline" style="padding-top:28px;">
<p class="gr-eyebrow">Baseline comparison</p>
<h1>What changed since the baseline</h1>
</div>
<div class="gr-metrics">
<div class="gr-metric"><span class="gr-metric__value">{{.Delta.Summary.AddedTargets}}</span><span class="gr-metric__label">Added targets</span></div>
<div class="gr-metric"><span class="gr-metric__value">{{.Delta.Summary.RemovedTargets}}</span><span class="gr-metric__label">Removed targets</span></div>
<div class="gr-metric"><span class="gr-metric__value">{{.Delta.Summary.StatusChanges}}</span><span class="gr-metric__label">Status changes</span></div>
<div class="gr-metric"><span class="gr-metric__value">{{.Delta.Summary.AddedModules}}</span><span class="gr-metric__label">Added modules</span></div>
<div class="gr-metric"><span class="gr-metric__value">{{.Delta.Summary.RemovedModules}}</span><span class="gr-metric__label">Removed modules</span></div>
<div class="gr-metric"><span class="gr-metric__value">{{.Delta.Summary.AddedRoutes}}</span><span class="gr-metric__label">Added routes</span></div>
<div class="gr-metric"><span class="gr-metric__value">{{.Delta.Summary.RemovedRoutes}}</span><span class="gr-metric__label">Removed routes</span></div>
<div class="gr-metric"><span class="gr-badge gr-badge--bad">{{.Delta.Summary.AuthRegressions}} regression(s)</span></div>
<div class="gr-metric"><span class="gr-badge gr-badge--good">{{.Delta.Summary.AuthImprovements}} improvement(s)</span></div>
</div>
{{if not .Delta.Coverage.Complete}}<p class="gr-lede" style="margin:8px 24px 0;"><strong>Comparison coverage is incomplete.</strong>{{range .Delta.Coverage.Diagnostics}} {{.}}{{end}}</p>{{end}}
{{if .Delta.Summary.IncomparableTargets}}<p class="gr-lede" style="margin:8px 24px 0;">{{.Delta.Summary.IncomparableTargets}} target(s) could not be compared — see the reason column below.</p>{{end}}
<div class="gr-panel">
<h2 class="gr-panel__title">Per-target delta</h2>
<div class="gr-table-wrap">
<table class="gr-table">
<thead><tr><th>Target</th><th>Status</th><th>Added routes</th><th>Removed routes</th><th>Auth regressions</th><th>Reason</th></tr></thead>
<tbody>
{{range .Delta.Targets}}<tr>
<td><code>{{.Name}}</code></td>
<td>{{.Status}}{{range .Modules}}<br><code>{{.Path}}</code>: {{.Status}}{{end}}</td>
<td>{{if .Delta}}{{range .Delta.AddedRoutes}}{{.}}<br>{{end}}{{end}}{{range .Modules}}{{if .Delta}}{{range .Delta.AddedRoutes}}{{.}}<br>{{end}}{{end}}{{end}}</td>
<td>{{if .Delta}}{{range .Delta.RemovedRoutes}}{{.}}<br>{{end}}{{end}}{{range .Modules}}{{if .Delta}}{{range .Delta.RemovedRoutes}}{{.}}<br>{{end}}{{end}}{{end}}</td>
<td>{{if .Delta}}{{if .Delta.AuthRegressions}}<span class="gr-badge gr-badge--bad">{{len .Delta.AuthRegressions}}</span>{{end}}{{end}}{{range .Modules}}{{if .Delta}}{{if .Delta.AuthRegressions}}<span class="gr-badge gr-badge--bad">{{len .Delta.AuthRegressions}}</span>{{end}}{{end}}{{end}}</td>
<td class="gr-error">{{.Reason}}{{range .Modules}}{{if .Reason}}<br><code>{{.Path}}</code>: {{.Reason}}{{end}}{{end}}</td>
</tr>
{{end}}</tbody>
</table>
</div>
</div>
{{end}}
<details class="gr-panel gr-details gr-section-spacer" id="run-details">
<summary>Run details — scope and configuration</summary>
{{if .Agg.Resume.Requested}}<p class="gr-lede" style="margin:0;padding:12px 16px 0;">Resumed: {{.Agg.Resume.Reused}} target(s) reused from checkpoint.</p>{{end}}
{{if .Agg.Resume.Checkpoint}}<p class="gr-lede" style="margin:0;padding:8px 16px 0;">Checkpoint retained — this run is not yet complete.</p>{{end}}
{{if .Scope}}
<section>
<h2 class="gr-panel__title">Scope</h2>
<dl class="gr-key-values">
<dt>Organization</dt><dd>{{.Scope.Org}}</dd>
<dt>Concurrency</dt><dd>{{.Scope.Concurrency}}</dd>
<dt>Repository cap</dt><dd>{{.Scope.MaxRepos}}</dd>
<dt>Archived repositories</dt><dd>{{if .Scope.IncludeArchived}}<span class="gr-badge gr-badge--warn">included</span> by explicit <code>--include-archived</code> opt-in{{else}}excluded (default){{end}}</dd>
<dt>Forks</dt><dd>{{if .Scope.IncludeForks}}<span class="gr-badge gr-badge--warn">included</span> by explicit <code>--include-forks</code> opt-in{{else}}excluded (default){{end}}</dd>
{{if .Scope.RepoInclude}}<dt>Repo include</dt><dd>{{range $i, $p := .Scope.RepoInclude}}{{if $i}}, {{end}}{{$p}}{{end}}</dd>{{end}}
{{if .Scope.RepoExclude}}<dt>Repo exclude</dt><dd>{{range $i, $p := .Scope.RepoExclude}}{{if $i}}, {{end}}{{$p}}{{end}}</dd>{{end}}
{{if .Scope.DiscoveryCompleteKnown}}<dt>Enumeration coverage</dt><dd>{{if .Scope.DiscoveryComplete}}<span class="gr-badge gr-badge--good">complete</span>{{else}}<span class="gr-badge gr-badge--warn">incomplete</span>{{end}}</dd>{{end}}
{{if .Scope.Discovery}}<dt>Visible repositories</dt><dd>{{.Scope.Discovery.Visible}}</dd><dt>Selected repositories</dt><dd>{{.Scope.Discovery.Selected}}</dd><dt>API pages fetched</dt><dd>{{.Scope.Discovery.PagesFetched}}</dd>{{end}}
</dl>
{{if or .Scope.IncludeArchived .Scope.IncludeForks}}<p class="gr-callout gr-callout--warn"><strong>Expanded repository scope.</strong> This run preserved the caller's explicit opt-in to include {{if .Scope.IncludeArchived}}archived repositories{{end}}{{if and .Scope.IncludeArchived .Scope.IncludeForks}} and {{end}}{{if .Scope.IncludeForks}}forks{{end}}; the report has not silently removed them.</p>{{end}}
{{if .DiscoveryOmitted}}<details class="gr-details" style="margin-top:12px;"><summary>Discovery dispositions not audited ({{len .DiscoveryOmitted}})</summary><p class="gr-lede" style="margin:0;padding:12px 16px;">These are discovery decisions, not fabricated audit results. Each repository below was filtered, skipped, or capped before target scanning.</p><div class="gr-table-wrap"><table class="gr-table"><thead><tr><th>Repository</th><th>Disposition</th><th>Reason</th></tr></thead><tbody>{{range .DiscoveryOmitted}}<tr><td><code>{{.FullName}}</code></td><td>{{.Status}}</td><td>{{.Reason}}</td></tr>{{end}}</tbody></table></div></details>{{end}}
</section>
{{end}}
<section><h2 class="gr-panel__title">Configuration</h2><dl class="gr-key-values">
<dt>authMiddleware configured</dt><dd>{{.Agg.AuthConfig.MiddlewareCount}}</dd>
<dt>authWrappers configured</dt><dd>{{.Agg.AuthConfig.WrappersCount}}</dd>
<dt>analysis.followModules configured</dt><dd>{{.Agg.FollowModulesCount}}{{if not .Agg.FollowModulesCount}} — a target that imports and mounts another module's own routes (a common pattern: one service calling another module's own Init(router, ...)) won't have those routes counted at all without this{{end}}</dd>
{{if .TargetConfigCount}}<dt>Targets using their own repo-committed config</dt><dd>{{.TargetConfigCount}} of {{len .Agg.Targets}} — reviewed by whoever committed it to that repository, not necessarily independently of it</dd>{{end}}
{{if .TargetConfigDirCount}}<dt>Targets using an operator-owned config</dt><dd>{{.TargetConfigDirCount}} of {{len .Agg.Targets}} — from --target-config-dir, never sourced from the scanned repository itself</dd>{{end}}
</dl></section>
</details>
<p class="gr-footer">gin-recon {{.Agg.ToolVersion}} &middot; static analysis only, no target code was executed</p>
</main>
<script>{{.FilterJS}}</script>
</body>
</html>
`))

// fleetFilterJS is a small, hand-written vanilla-JS live filter for the
// report tables (search + select controls), the same general
// data-attribute technique a table filter always uses — no library, no
// external script, and no target-derived value is ever written back as
// markup: it only ever reads data-gr-search/data-gr-status attributes
// html/template already escaped when the page was built, and only ever
// toggles the standard `hidden` attribute. It also hides now-empty group
// headings and exposes an explicit no-matches state without synthesizing HTML.
const fleetFilterJS = `
(function () {
  "use strict";
  document.querySelectorAll("[data-gr-filter]").forEach(function (controls) {
    var table = document.getElementById(controls.dataset.grFilter);
    if (!table) return;
    var rows = Array.prototype.slice.call(table.querySelectorAll("tbody tr[data-gr-search]"));
    var search = controls.querySelector("[data-gr-filter-search]");
    var status = controls.querySelector("[data-gr-filter-status]");
    var category = controls.querySelector("[data-gr-filter-category]");
    var completion = controls.querySelector("[data-gr-filter-completion]");
    var evidence = controls.querySelector("[data-gr-filter-evidence]");
    var framework = controls.querySelector("[data-gr-filter-framework]");
    var docs = controls.querySelector("[data-gr-filter-docs]");
    var clearSearch = controls.querySelector("[data-gr-filter-clear]");
    var count = controls.querySelector("[data-gr-result-count]");
    var panel = controls.closest(".gr-panel");
    var empty = panel && panel.querySelector("[data-gr-filter-empty]");

    function update() {
      var query = (search && search.value || "").trim().toLowerCase();
      var selected = (status && status.value) || "";
      var selectedCategory = (category && category.value) || "";
      var selectedCompletion = (completion && completion.value) || "";
      var selectedEvidence = (evidence && evidence.value) || "";
      var selectedFramework = (framework && framework.value) || "";
      var selectedDocs = (docs && docs.value) || "";
      var visible = 0;
      rows.forEach(function (row) {
        var matchesQuery = !query || row.dataset.grSearch.toLowerCase().indexOf(query) !== -1;
        var matchesStatus = !selected || row.dataset.grStatus === selected;
        var matchesCategory = !selectedCategory || row.dataset.grCategory === selectedCategory;
        var matchesCompletion = !selectedCompletion || row.dataset.grCompletion === selectedCompletion;
        var matchesEvidence = !selectedEvidence || row.dataset["gr" + selectedEvidence.charAt(0).toUpperCase() + selectedEvidence.slice(1)] === "yes";
        var matchesFramework = !selectedFramework || row.dataset.grFramework === selectedFramework;
        var matchesDocs = !selectedDocs || row.dataset.grDocs === selectedDocs;
        var show = matchesQuery && matchesStatus && matchesCategory && matchesCompletion && matchesEvidence && matchesFramework && matchesDocs;
        row.hidden = !show;
        if (show) visible++;
      });
      if (count) count.textContent = visible + " of " + rows.length;
      if (clearSearch) clearSearch.hidden = !search || search.value.length === 0;
      table.querySelectorAll("[data-gr-group]").forEach(function (group) {
        group.hidden = !rows.some(function (row) { return !row.hidden && row.dataset.grCompletion === group.dataset.grGroup; });
      });
      if (empty) empty.hidden = visible !== 0;
    }

    function clearQuery() {
      if (!search) return;
      search.value = "";
      update();
      search.focus();
    }

    if (search) search.addEventListener("input", update);
    if (status) status.addEventListener("change", update);
    if (category) category.addEventListener("change", update);
    if (completion) completion.addEventListener("change", update);
    if (evidence) evidence.addEventListener("change", update);
    if (framework) framework.addEventListener("change", update);
    if (docs) docs.addEventListener("change", update);
    if (clearSearch) clearSearch.addEventListener("click", clearQuery);
    update();
  });
  document.querySelectorAll(".gr-jump a[href^='#']").forEach(function (link) {
    link.addEventListener("click", function () {
      var target = document.getElementById(link.getAttribute("href").slice(1));
      if (target && target.tagName === "DETAILS") target.open = true;
    });
  });
})();
`

// fleetHTMLData is the template's input: the aggregate every fleet run
// produces, plus the delta only a --baseline run also produces, plus
// pre-computed status counts for the metrics row (html/template has no
// convenient count-by-predicate of its own).
type fleetHTMLData struct {
	Agg                            *fleet.Aggregate
	Delta                          *fleet.FleetDelta
	Scope                          *fleet.Scope
	RawDirLink                     string // relative path from this page back to --out (docs/adr/0023-fleet-raw-rendered-split.md); plain string, auto-escaped like any other URL-context value
	ThemeCSS                       template.CSS
	BrandMark                      template.HTML
	GitMark                        template.HTML
	FilterJS                       template.JS
	OKCount                        int
	FailedCount                    int
	InconclusiveCount              int
	NotGoModuleCount               int
	TargetConfigCount              int
	TargetConfigDirCount           int
	CompleteTargetCount            int
	IncompleteTargetCount          int
	RouteCompleteTargets           []fleetHTMLTarget
	RouteIncompleteTargets         []fleetHTMLTarget
	ReferenceTargets               []fleetHTMLTarget
	WithRoutesCount                int
	ReferenceCount                 int
	DiscoveryOmitted               []fleet.RepositoryDisposition
	SpecificationRepositoriesCount int
	SpecificationDocumentCount     int
	SpecificationCoverageText      string
}

type fleetHTMLTarget struct {
	fleet.TargetResult
	Category      string
	CategoryLabel string
	AuditGroup    string
	RawDirLink    string
	GitMark       template.HTML
	Framework     string
	DocsClass     string
	DocsLabel     string
	DocModules    []fleetHTMLDocumentation
}

type fleetHTMLDocumentation struct {
	ModulePath        string
	SourceCoverage    string
	OperationCoverage string
	IncompleteScope   bool
	Specifications    []model.SpecificationRecord
}

// FleetHTML renders agg (and, when given, delta/scope) as the browsable
// companion requested with --render-html or `render` (docs/adr/0037-fleet-html-opt-in.md,
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
	targetsByName := make(map[string]fleet.TargetResult, len(agg.Targets))
	for _, t := range agg.Targets {
		targetsByName[t.Name] = t
		switch t.Status {
		case fleet.StatusOK:
			data.OKCount++
		case fleet.StatusFailed:
			data.FailedCount++
		case fleet.StatusInconclusive:
			data.InconclusiveCount++
		case fleet.StatusNotGoModule:
			data.NotGoModuleCount++
		}
		if t.TargetConfig {
			data.TargetConfigCount++
		}
		if t.TargetConfigDir {
			data.TargetConfigDirCount++
		}
		if t.Complete && (t.Status == fleet.StatusOK || t.Status == fleet.StatusNotGoModule) {
			data.CompleteTargetCount++
		} else {
			data.IncompleteTargetCount++
		}
		// Recomputed from each target's own already-decoded Specifications
		// (never from agg.Specifications itself) so this stays correct even
		// for an aggregate whose own rollup predates that field or was
		// never refreshed — the same "derive from Targets, don't trust a
		// possibly-stale aggregate-level field" posture every other count
		// in this loop already follows.
		hasSpecifications := false
		for _, module := range t.Specifications {
			if module.Catalog == nil {
				continue
			}
			if n := len(module.Catalog.Specifications); n > 0 {
				data.SpecificationDocumentCount += n
				hasSpecifications = true
			}
		}
		if hasSpecifications {
			data.SpecificationRepositoriesCount++
		}
	}
	groups := agg.RepositoryGroups
	if groups == nil {
		// Fleet 1.0 files written before repositoryGroups remain renderable;
		// derive the same deterministic index from their untouched targets.
		groups = fleet.GroupRepositories(agg.Targets)
	}
	for _, name := range groups.WithRoutes {
		if target, ok := targetsByName[name]; ok {
			view := fleetHTMLTarget{
				TargetResult:  target,
				Category:      fleet.CategoryGinRoutes,
				CategoryLabel: repositoryCategoryLabel(fleet.CategoryGinRoutes),
				AuditGroup:    "incomplete",
				RawDirLink:    rawDirLink,
				GitMark:       template.HTML(gitMarkHTML),
			}
			decorateFleetDocumentation(&view)
			if target.Status == fleet.StatusOK && target.Complete {
				view.AuditGroup = "complete"
				data.RouteCompleteTargets = append(data.RouteCompleteTargets, view)
			} else {
				data.RouteIncompleteTargets = append(data.RouteIncompleteTargets, view)
			}
		}
	}
	for _, reference := range groups.Reference {
		if target, ok := targetsByName[reference.Name]; ok {
			view := fleetHTMLTarget{
				TargetResult:  target,
				Category:      reference.Category,
				CategoryLabel: repositoryCategoryLabel(reference.Category),
				RawDirLink:    rawDirLink,
				GitMark:       template.HTML(gitMarkHTML),
			}
			decorateFleetDocumentation(&view)
			data.ReferenceTargets = append(data.ReferenceTargets, view)
		}
	}
	data.WithRoutesCount = len(data.RouteCompleteTargets) + len(data.RouteIncompleteTargets)
	data.ReferenceCount = len(data.ReferenceTargets)
	data.SpecificationCoverageText = metricText(model.DocumentationMetric{
		Numerator:   data.SpecificationRepositoriesCount,
		Denominator: data.OKCount,
		Status:      "complete",
	})
	if scope != nil && scope.Discovery != nil {
		for _, disposition := range scope.Discovery.Repositories {
			if disposition.Status != "selected" {
				data.DiscoveryOmitted = append(data.DiscoveryOmitted, disposition)
			}
		}
	}

	var buf bytes.Buffer
	if err := fleetHTMLTemplate.Execute(&buf, data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decorateFleetDocumentation(view *fleetHTMLTarget) {
	view.Framework = "go"
	for _, module := range view.Modules {
		if module.Kind == fleet.ModuleGinApplication || module.Kind == fleet.ModuleGinNoRoutes {
			view.Framework = "gin"
		}
	}
	if view.Routes > 0 {
		view.Framework = "gin"
	}
	has3, has2, unavailable := false, false, false
	for _, scoped := range view.Specifications {
		if scoped.Catalog == nil {
			unavailable = true
			continue
		}
		if scoped.Catalog.Status != "complete" {
			unavailable = true
		}
		entry := fleetHTMLDocumentation{ModulePath: scoped.ModulePath, SourceCoverage: metricText(scoped.Catalog.Metrics.SourceFiles), OperationCoverage: metricText(scoped.Catalog.Metrics.ObservedOperations), IncompleteScope: scoped.Catalog.Metrics.IncompleteScope, Specifications: scoped.Catalog.Specifications}
		if entry.ModulePath == "" {
			entry.ModulePath = scoped.ModuleID
		}
		view.DocModules = append(view.DocModules, entry)
		for _, specification := range scoped.Catalog.Specifications {
			if specification.Dialect == "openapi3" {
				has3 = true
			}
			if specification.Dialect == "swagger2" {
				has2 = true
			}
		}
	}
	switch {
	case has3 && has2:
		view.DocsClass, view.DocsLabel = "both", "OpenAPI3 + Swagger2"
	case has3:
		view.DocsClass, view.DocsLabel = "openapi3", "OpenAPI3"
	case has2:
		view.DocsClass, view.DocsLabel = "swagger2", "Swagger2"
	case unavailable || len(view.Specifications) == 0:
		view.DocsClass, view.DocsLabel = "unavailable", "Unavailable"
	default:
		view.DocsClass, view.DocsLabel = "none", "None"
	}
}

func metricText(metric model.DocumentationMetric) string {
	if metric.Denominator == 0 {
		return "N/A"
	}
	value := fmt.Sprintf("%.1f%% (%d/%d)", 100*float64(metric.Numerator)/float64(metric.Denominator), metric.Numerator, metric.Denominator)
	if metric.Status != "complete" {
		value += " · " + metric.Status
	}
	return value
}

func repositoryCategoryLabel(category string) string {
	switch category {
	case fleet.CategoryGinRoutes:
		return "Observed Gin routes"
	case fleet.CategoryGinNoRoutes:
		return "Gin detected, no routes"
	case fleet.CategoryNoRoutesUnverified:
		return "No routes, unverified"
	case fleet.CategoryNonGin:
		return "Non-Gin Go"
	case fleet.CategoryNotGoModule:
		return "Not a Go module"
	case fleet.CategoryFailed:
		return "Failed"
	case fleet.CategoryInconclusive:
		return "Inconclusive"
	default:
		return string(category)
	}
}
