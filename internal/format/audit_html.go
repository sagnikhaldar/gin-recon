// Package format's audit HTML formatter (this file) is html.go's sibling for
// a different reader: html.go's api.html shows an API consumer what a
// service exposes (the OpenAPI document); audit.html shows a reviewer what
// the service's route surface actually looks like, security-wise — the full
// report.Report a "json"-format run already produces (routes, middleware
// chains, auth classification, scan coverage, diagnostics, and, for audit,
// Summary/Findings). See docs/adr/0015-audit-html-report-viewer.md for why
// this is a second, independent file rather than a variant of html.go: the
// two pages are shaped around unrelated reader goals and unrelated source
// documents, and folding them into one file/template would only produce two
// rendering branches wearing one name.
package format

import (
	"encoding/json"
	"fmt"
	"html"

	"github.com/sagnikhaldar/gin-recon/internal/config"
	"github.com/sagnikhaldar/gin-recon/internal/report"
)

// AuditHTML renders rep — the exact document "--format json" writes as
// routes.json — as a self-contained, dependency-free HTML page: a metrics
// strip, a Findings section (present only when rep.Command is audit, since
// report.Report's own MarshalJSON omits Summary/Findings/PolicyEvaluation/
// ActiveExceptions entirely for inventory — see that method's doc comment),
// a searchable/filterable routes table, and a Diagnostics section. cfg is
// accepted for signature symmetry with HTML (api.html's generator) but
// unlike that page's OpenAPI title, audit.html's title is not
// config-derived: it is rendering routes.json itself, not an OpenAPI
// document config.OpenAPIConfig describes, so there is no configured title
// to prefer.
func AuditHTML(rep *report.Report, cfg *config.Config) ([]byte, error) {
	reportJSON, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return nil, err
	}

	title := "Gin Recon Audit"
	if rep != nil && rep.Target.Module != "" {
		title = fmt.Sprintf("Gin Recon Audit — %s", rep.Target.Module)
	}

	page := fmt.Sprintf(auditHTMLPageTemplate, html.EscapeString(title), auditHTMLViewerCSS, escapeScriptClose(reportJSON), auditHTMLViewerJS)
	return []byte(page), nil
}

const auditHTMLPageTemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%s</title>
<style>%s</style>
</head>
<body>
<div id="app">Loading…</div>
<script id="gin-recon-report" type="application/json">%s</script>
<script>%s</script>
</body>
</html>
`

// auditHTMLViewerCSS deliberately reuses html.go's color tokens, badge
// shapes, and monospace conventions (--get/--post/…, .badge, .path) so the
// two self-contained viewers read as one family rather than two
// independently designed pages, even though they share no template or JS.
const auditHTMLViewerCSS = `
:root {
  --bg: #ffffff; --fg: #1a1a1a; --muted: #6b7280; --border: #e5e7eb;
  --card: #f9fafb; --code-bg: #f3f4f6;
  --get: #2563eb; --post: #16a34a; --put: #d97706; --patch: #7c3aed;
  --delete: #dc2626; --other: #6b7280;
  --public: #16a34a; --proven: #2563eb; --unknown: #d97706;
  --critical: #b91c1c; --high: #dc2626; --medium: #d97706; --low: #2563eb; --info: #6b7280;
}
@media (prefers-color-scheme: dark) {
  :root { --bg: #0f1115; --fg: #e5e7eb; --muted: #9ca3af; --border: #262b36; --card: #171a21; --code-bg: #1c2028; }
}
* { box-sizing: border-box; }
html, body { overflow-x: hidden; max-width: 100%; }
body { margin: 0; background: var(--bg); color: var(--fg); font: 14px/1.5 -apple-system, "Segoe UI", Roboto, sans-serif; }
#app { max-width: 1400px; margin: 0 auto; padding: 24px 16px 64px; min-width: 0; }
header { margin-bottom: 20px; }
header h1 { margin: 0 0 4px; font-size: 22px; }
header .meta { color: var(--muted); font-size: 13px; }
section { margin: 24px 0; min-width: 0; }
section h2 { font-size: 15px; margin: 0 0 10px; }
.metrics { display: flex; flex-wrap: wrap; gap: 10px; }
.metric { border: 1px solid var(--border); border-radius: 8px; padding: 10px 16px; background: var(--card); min-width: 120px; }
.metric .value { font-size: 22px; font-weight: 700; }
.metric .label { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .03em; }
.controls { display: flex; gap: 10px; margin: 16px 0; flex-wrap: wrap; align-items: center; }
.controls .count { color: var(--muted); font-size: 12px; margin-left: auto; }
input#route-filter { flex: 1; min-width: 220px; padding: 8px 10px; border: 1px solid var(--border); border-radius: 6px; background: var(--card); color: var(--fg); font-size: 14px; }
select#auth-filter { padding: 8px 10px; border: 1px solid var(--border); border-radius: 6px; background: var(--card); color: var(--fg); font-size: 14px; }
/* table-layout: fixed forces every column, including unbroken content like a
   long file path or arrow-joined middleware chain, to wrap within its
   assigned share of the table's own width instead of stretching the table
   (and the whole page, since nothing upstream clips it) past the viewport —
   that stretch, not the content itself, is what forced horizontal scrolling. */
table.routes { border-collapse: collapse; width: 100%; table-layout: fixed; }
table.routes th, table.routes td { text-align: left; padding: 6px 10px; border-bottom: 1px solid var(--border); font-size: 13px; vertical-align: top; word-break: break-word; overflow-wrap: anywhere; }
table.routes th { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .03em; }
table.routes col.col-method { width: 8%; } table.routes col.col-path { width: 18%; }
table.routes col.col-auth { width: 8%; } table.routes col.col-middleware { width: 30%; }
table.routes col.col-handler { width: 16%; } table.routes col.col-source { width: 20%; }
.method { display: inline-block; min-width: 58px; text-align: center; padding: 2px 6px; border-radius: 4px; color: #fff; font-weight: 700; font-size: 11px; }
.method.get { background: var(--get); } .method.post { background: var(--post); }
.method.put { background: var(--put); } .method.patch { background: var(--patch); }
.method.delete { background: var(--delete); } .method.other { background: var(--other); }
.path { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
.badge { padding: 1px 7px; border-radius: 10px; font-size: 11px; border: 1px solid var(--border); color: var(--muted); }
.badge.public { color: var(--public); border-color: var(--public); }
.badge.proven { color: var(--proven); border-color: var(--proven); }
.badge.unknown { color: var(--unknown); border-color: var(--unknown); }
.badge.critical { color: var(--critical); border-color: var(--critical); }
.badge.high { color: var(--high); border-color: var(--high); }
.badge.medium { color: var(--medium); border-color: var(--medium); }
.badge.low { color: var(--low); border-color: var(--low); }
.badge.info { color: var(--info); border-color: var(--info); }
.badge.error { color: var(--delete); border-color: var(--delete); }
.badge.warning { color: var(--unknown); border-color: var(--unknown); }
.source, .chain { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; color: var(--muted); }
.finding-list { max-height: 420px; overflow-y: auto; border: 1px solid var(--border); border-radius: 8px; padding: 10px; }
.finding, .diagnostic { border: 1px solid var(--border); border-radius: 8px; padding: 10px 14px; margin-bottom: 8px; background: var(--card); }
.finding-list .finding:last-child { margin-bottom: 0; }
.finding-head, .diagnostic-head { display: flex; align-items: center; gap: 10px; margin-bottom: 4px; }
.finding-rule, .diagnostic-code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; color: var(--muted); }
.finding-route { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
.empty { color: var(--muted); padding: 16px; text-align: center; border: 1px dashed var(--border); border-radius: 8px; }
footer { margin-top: 32px; color: var(--muted); font-size: 12px; }
`

// auditHTMLViewerJS follows html.go's htmlViewerJS conventions exactly:
// framework-free vanilla JS, el()/textContent for every value that could
// originate from the scanned repository's own source, and a single
// filter-input wired to a dataset.search precedent already established
// there. Every section function returns null (rendering nothing) when its
// underlying data is absent or empty, so an inventory report — which never
// carries findings/summary/policyEvaluation at all — never shows a broken or
// empty placeholder for them; it simply omits those sections.
const auditHTMLViewerJS = `
(function () {
  "use strict";
  var data = JSON.parse(document.getElementById("gin-recon-report").textContent);
  var app = document.getElementById("app");

  function el(tag, attrs, text) {
    var e = document.createElement(tag);
    if (attrs) for (var k in attrs) e.setAttribute(k, attrs[k]);
    if (text !== undefined && text !== null) e.textContent = text;
    return e;
  }

  function methodClass(method) {
    var m = (method || "").toLowerCase();
    return ["get", "post", "put", "patch", "delete"].indexOf(m) >= 0 ? m : "other";
  }

  function middlewareNames(list) {
    return (list || []).map(function (m) { return m.displayName; });
  }

  function sourceLabel(source) {
    if (!source || !source.file) return "";
    return source.line ? (source.file + ":" + source.line) : source.file;
  }

  // metricsSection always renders (total routes and scan coverage are
  // present on every report, inventory or audit), but the proven/public/
  // unknown breakdown and findings count are only added when the
  // underlying evidence actually exists — route.auth is nil on every route
  // of an inventory report, and data.findings is entirely absent for one.
  function metricsSection() {
    var section = el("section");
    section.appendChild(el("h2", null, "Metrics"));
    var strip = el("div", { class: "metrics" });

    function metric(label, value) {
      var box = el("div", { class: "metric" });
      box.appendChild(el("div", { class: "value" }, String(value)));
      box.appendChild(el("div", { class: "label" }, label));
      strip.appendChild(box);
    }

    var routes = data.routes || [];
    metric("Total routes", routes.length);

    var counts = { proven: 0, public: 0, unknown: 0 };
    var haveAuth = false;
    routes.forEach(function (r) {
      if (r.auth && r.auth.authStatus) {
        haveAuth = true;
        if (counts.hasOwnProperty(r.auth.authStatus)) counts[r.auth.authStatus]++;
      }
    });
    if (haveAuth) {
      metric("Proven", counts.proven);
      metric("Public", counts.public);
      metric("Unknown", counts.unknown);
    }

    var cov = data.scanCoverage;
    if (cov) {
      metric("Packages analyzed", cov.analyzedPackages + " / " + cov.discoveredPackages);
      metric("Files analyzed", cov.analyzedFiles + " / " + cov.discoveredFiles);
      metric("Scan coverage complete", cov.complete ? "yes" : "no");
      if (cov.failedPackages > 0) metric("Packages failed", cov.failedPackages);
      if (cov.failedFiles > 0) metric("Files failed", cov.failedFiles);
    }

    if (data.findings) {
      metric("Findings", data.findings.length);
    }

    section.appendChild(strip);
    return section;
  }

  // findingsSection renders only when data.findings is present at all —
  // report.Report's MarshalJSON (internal/report/report.go) omits the
  // "findings" key entirely for command "inventory", so an inventory
  // report's embedded JSON never even has this key, and this function
  // never runs for one. An audit report with zero findings still gets the
  // key (an empty array, never null — see the same MarshalJSON), so this
  // renders an explicit "no findings" note rather than nothing at all: a
  // clean audit result is meaningfully different from "this section does
  // not apply," and only the former should say so.
  // findingsSection deliberately omits severity from the display for now —
  // dropped along with the severity filter this replaced, per explicit
  // direction, not merely simplified — and instead bounds the list itself
  // inside a fixed-height, independently-scrollable box (.finding-list) so a
  // report with dozens of findings sharing one root cause no longer forces
  // the whole page to a very long scroll; only that one box scrolls.
  function findingsSection() {
    if (!data.findings) return null;
    var section = el("section");
    section.appendChild(el("h2", null, "Findings"));
    if (data.findings.length === 0) {
      section.appendChild(el("div", { class: "empty" }, "No findings."));
      return section;
    }

    var list = el("div", { class: "finding-list" });
    data.findings.forEach(function (f) {
      var card = el("div", { class: "finding" });
      var head = el("div", { class: "finding-head" });
      head.appendChild(el("span", { class: "finding-rule" }, f.ruleId));
      if (f.route) head.appendChild(el("span", { class: "finding-route" }, f.route));
      card.appendChild(head);
      card.appendChild(el("div", null, f.detail));
      if (f.recommendation) card.appendChild(el("div", { class: "source" }, f.recommendation));
      list.appendChild(card);
    });
    section.appendChild(list);
    return section;
  }

  function routesSection() {
    var section = el("section");
    section.appendChild(el("h2", null, "Routes"));
    var routes = data.routes || [];
    if (routes.length === 0) {
      section.appendChild(el("div", { class: "empty" }, "No routes in this report."));
      return section;
    }

    var controls = el("div", { class: "controls" });
    var filterInput = el("input", { id: "route-filter", type: "search", placeholder: "Filter by path, middleware, or handler…" });
    controls.appendChild(filterInput);

    var haveAuth = routes.some(function (r) { return r.auth && r.auth.authStatus; });
    var authSelect = null;
    if (haveAuth) {
      authSelect = el("select", { id: "auth-filter" });
      [["", "All auth statuses"], ["proven", "Proven"], ["public", "Public"], ["unknown", "Unknown"]].forEach(function (opt) {
        authSelect.appendChild(el("option", { value: opt[0] }, opt[1]));
      });
      controls.appendChild(authSelect);
    }
    var routeCount = el("span", { class: "count" });
    controls.appendChild(routeCount);
    section.appendChild(controls);

    var table = el("table", { class: "routes" });
    var colgroup = el("colgroup");
    ["col-method", "col-path", "col-auth", "col-middleware", "col-handler", "col-source"].forEach(function (c) {
      colgroup.appendChild(el("col", { class: c }));
    });
    table.appendChild(colgroup);
    var head = el("tr");
    ["Method", "Path", "Auth", "Middleware", "Handler", "Source"].forEach(function (h) { head.appendChild(el("th", null, h)); });
    table.appendChild(head);

    var rows = [];
    routes.forEach(function (r) {
      var row = el("tr");
      row.appendChild(el("td", null)).appendChild(el("span", { class: "method " + methodClass(r.method) }, (r.method || "").toUpperCase()));
      row.appendChild(el("td", { class: "path" }, r.normalizedPath || r.ginPath));
      var authStatus = r.auth && r.auth.authStatus;
      var authCell = el("td");
      if (authStatus) authCell.appendChild(el("span", { class: "badge " + authStatus }, authStatus));
      row.appendChild(authCell);
      var mwNames = middlewareNames(r.middleware);
      row.appendChild(el("td", { class: "chain" }, mwNames.length ? mwNames.join(" → ") : "—"));
      row.appendChild(el("td", null, (r.finalHandler && r.finalHandler.displayName) || ""));
      row.appendChild(el("td", { class: "source" }, sourceLabel(r.source)));
      table.appendChild(row);

      row.dataset.search = ((r.normalizedPath || r.ginPath || "") + " " + mwNames.join(" ") + " " +
        ((r.finalHandler && r.finalHandler.displayName) || "")).toLowerCase();
      row.dataset.authStatus = authStatus || "";
      rows.push(row);
    });
    section.appendChild(table);

    function applyFilters() {
      var q = filterInput.value.toLowerCase();
      var authWant = authSelect ? authSelect.value : "";
      var shown = 0;
      rows.forEach(function (row) {
        var matchesText = row.dataset.search.indexOf(q) >= 0;
        var matchesAuth = !authWant || row.dataset.authStatus === authWant;
        var visible = matchesText && matchesAuth;
        row.style.display = visible ? "" : "none";
        if (visible) shown++;
      });
      routeCount.textContent = shown + " / " + rows.length + " routes";
    }
    filterInput.addEventListener("input", applyFilters);
    if (authSelect) authSelect.addEventListener("change", applyFilters);
    applyFilters();

    return section;
  }

  // diagnosticsSection renders Report.Diagnostics — analysis-quality notes
  // (e.g. swag-router-mismatch, gin-library-entry-point), distinct from
  // Findings' security/policy outcomes — in plain readable form. Present on
  // both inventory and audit reports, but only when non-empty.
  function diagnosticsSection() {
    var diagnostics = data.diagnostics || [];
    if (diagnostics.length === 0) return null;
    var section = el("section");
    section.appendChild(el("h2", null, "Diagnostics"));
    diagnostics.forEach(function (d) {
      var card = el("div", { class: "diagnostic" });
      var head = el("div", { class: "diagnostic-head" });
      head.appendChild(el("span", { class: "badge " + d.severity }, d.severity));
      head.appendChild(el("span", { class: "diagnostic-code" }, d.code));
      if (d.route) head.appendChild(el("span", { class: "finding-route" }, d.route));
      card.appendChild(head);
      card.appendChild(el("div", null, d.message));
      if (d.source) card.appendChild(el("div", { class: "source" }, sourceLabel(d.source)));
      section.appendChild(card);
    });
    return section;
  }

  function render() {
    app.textContent = "";
    var header = el("header");
    header.appendChild(el("h1", null, "Gin Recon Audit"));
    var metaText = data.command + " · " + data.target.module + " · schema " + data.schemaVersion;
    var cov = data.scanCoverage;
    if (cov && cov.buildContext) {
      metaText += " · " + cov.profile + ", " + cov.buildContext.goos + "/" + cov.buildContext.goarch;
    }
    header.appendChild(el("div", { class: "meta" }, metaText));
    app.appendChild(header);

    app.appendChild(metricsSection());

    var findings = findingsSection();
    if (findings) app.appendChild(findings);

    app.appendChild(routesSection());

    var diagnostics = diagnosticsSection();
    if (diagnostics) app.appendChild(diagnostics);

    app.appendChild(el("footer", null, "Generated by gin-recon."));
  }

  render();
})();
`
