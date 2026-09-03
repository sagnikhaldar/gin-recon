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
</style>
</head>
<body>
<h1>gin-recon fleet report</h1>
<p class="summary">
{{len .Targets}} target(s) &middot;
coverage complete: <strong>{{.Coverage.Complete}}</strong>
{{if .Resume.Requested}}&middot; resumed, {{.Resume.Reused}} reused from checkpoint{{end}}
{{if .Resume.Checkpoint}}&middot; checkpoint retained (run is not yet complete){{end}}
</p>
<table>
<thead><tr><th>Target</th><th>Status</th><th>Coverage complete</th><th>Report</th><th>Error</th></tr></thead>
<tbody>
{{range .Targets}}<tr>
<td><code>{{.Name}}</code><br><span class="summary">{{.Src}}</span></td>
<td class="status-{{.Status}}">{{.Status}}</td>
<td>{{.Complete}}</td>
<td>{{if .Report}}<a href="{{.Report}}">routes.json</a>{{end}}</td>
<td class="error">{{.Error}}</td>
</tr>
{{end}}</tbody>
</table>
</body>
</html>
`))

// FleetHTML renders agg as the browsable companion fleet.json always gets
// (docs/adr/0020-fleet-html-view.md) — generated directly from the same
// Aggregate value being marshaled to fleet.json, nothing re-read from disk.
func FleetHTML(agg *fleet.Aggregate) ([]byte, error) {
	var buf bytes.Buffer
	if err := fleetHTMLTemplate.Execute(&buf, agg); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
