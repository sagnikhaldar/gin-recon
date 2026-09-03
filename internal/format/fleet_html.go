// Package format's fleet HTML formatter (docs/adr/0020-fleet-html-view.md)
// is a self-contained, dependency-free page over one fleet.Aggregate — the
// same offline-by-default, no-CDN posture html.go already applies to
// api.html, not a generated multi-page site. It uses html/template so every
// field (a target name, an error string carrying another process's
// stderr) is contextually auto-escaped rather than hand-escaped per call
// site, since fleet input — a manifest, a target's captured stderr — is
// exactly the kind of untrusted content docs/threat-model.md already
// treats scanned repositories and their output as.
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
<title>gin-recon fleet report</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 2rem; color: #1a1a1a; }
h1 { font-size: 1.25rem; }
table { border-collapse: collapse; width: 100%; margin-top: 1rem; }
th, td { text-align: left; padding: 0.4rem 0.75rem; border-bottom: 1px solid #ddd; vertical-align: top; }
th { background: #f5f5f5; }
.status-ok { color: #0a7a2f; }
.status-failed { color: #b3261e; font-weight: 600; }
.status-not-go-module { color: #666; }
.summary { color: #444; }
.error { font-family: ui-monospace, monospace; font-size: 0.85em; white-space: pre-wrap; color: #b3261e; }
code { background: #f0f0f0; padding: 0.1em 0.3em; border-radius: 3px; }
.regression { color: #b3261e; font-weight: 600; }
.improvement { color: #0a7a2f; }
</style>
</head>
<body>
<h1>gin-recon fleet report</h1>
<p class="summary">
{{len .Agg.Targets}} target(s) &middot;
coverage complete: <strong>{{.Agg.Coverage.Complete}}</strong>
{{if .Agg.Resume.Requested}}&middot; resumed, {{.Agg.Resume.Reused}} reused from checkpoint{{end}}
{{if .Agg.Resume.Checkpoint}}&middot; checkpoint retained (run is not yet complete){{end}}
</p>
<table>
<thead><tr><th>Target</th><th>Status</th><th>Coverage complete</th><th>Report</th><th>Error</th></tr></thead>
<tbody>
{{range .Agg.Targets}}<tr>
<td><code>{{.Name}}</code><br><span class="summary">{{.Src}}</span></td>
<td class="status-{{.Status}}">{{.Status}}</td>
<td>{{.Complete}}</td>
<td>{{if .Report}}<a href="{{.Report}}">routes.json</a>{{end}}</td>
<td class="error">{{.Error}}</td>
</tr>
{{end}}</tbody>
</table>
{{if .Delta}}
<h1>Baseline comparison</h1>
<p class="summary">
{{.Delta.Summary.AddedTargets}} added target(s) &middot;
{{.Delta.Summary.RemovedTargets}} removed target(s) &middot;
<span class="regression">{{.Delta.Summary.AuthRegressions}} auth regression(s)</span> &middot;
<span class="improvement">{{.Delta.Summary.AuthImprovements}} auth improvement(s)</span> &middot;
{{.Delta.Summary.AddedRoutes}} added route(s) &middot;
{{.Delta.Summary.RemovedRoutes}} removed route(s) &middot;
{{.Delta.Summary.NewFindings}} new finding(s) &middot;
{{.Delta.Summary.ResolvedFindings}} resolved finding(s)
{{if .Delta.Summary.IncomparableTargets}}&middot; {{.Delta.Summary.IncomparableTargets}} target(s) could not be compared{{end}}
</p>
<table>
<thead><tr><th>Target</th><th>Status</th><th>Added routes</th><th>Removed routes</th><th>Auth regressions</th><th>Reason</th></tr></thead>
<tbody>
{{range .Delta.Targets}}<tr>
<td><code>{{.Name}}</code></td>
<td>{{.Status}}</td>
<td>{{if .Delta}}{{range .Delta.AddedRoutes}}{{.}}<br>{{end}}{{end}}</td>
<td>{{if .Delta}}{{range .Delta.RemovedRoutes}}{{.}}<br>{{end}}{{end}}</td>
<td class="regression">{{if .Delta}}{{len .Delta.AuthRegressions}}{{end}}</td>
<td class="error">{{.Reason}}</td>
</tr>
{{end}}</tbody>
</table>
{{end}}
</body>
</html>
`))

// fleetHTMLData is the template's input: the aggregate every fleet run
// produces, plus the delta only a --baseline run also produces.
type fleetHTMLData struct {
	Agg   *fleet.Aggregate
	Delta *fleet.FleetDelta
}

// FleetHTML renders agg (and, when a --baseline was given, delta) as the
// browsable companion fleet.json always gets
// (docs/adr/0020-fleet-html-view.md, docs/adr/0022-fleet-baseline-delta.md) —
// generated directly from the same values being marshaled to JSON, nothing
// re-read from disk.
func FleetHTML(agg *fleet.Aggregate, delta *fleet.FleetDelta) ([]byte, error) {
	var buf bytes.Buffer
	if err := fleetHTMLTemplate.Execute(&buf, fleetHTMLData{Agg: agg, Delta: delta}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
