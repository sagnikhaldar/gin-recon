// Package format's HTML formatter wraps the OpenAPI document (openapi.go)
// in a single self-contained, dependency-free HTML page for humans to
// browse. It deliberately does not follow express-recon's precedent of
// loading a Redoc/Swagger UI bundle from a CDN: docs/threat-model.md
// establishes gin-recon as offline-by-default (no network egress during
// analysis), and a viewer that reaches out to a third-party CDN every time
// someone opens it would be the first place this tool's own *output*
// breaks that posture, plus a new third-party JS supply-chain surface for a
// security tool to track. This page embeds the spec and a small hand-written
// vanilla-JS renderer inline; opening it needs no network access at all.
package format

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"

	"github.com/sagnikhaldar/gin-recon/internal/config"
	"github.com/sagnikhaldar/gin-recon/internal/model"
	"github.com/sagnikhaldar/gin-recon/internal/report"
)

// HTML renders rep as a browsable HTML page over the same OpenAPI document
// format.OpenAPI produces — it calls OpenAPI internally rather than
// re-deriving anything from rep, so the two formats can never disagree
// about which routes exist, are security-mapped, or are diagnosed. The
// returned diagnostics are OpenAPI's own (see OpenAPI's doc comment for why
// they cannot be folded into rep.Diagnostics).
func HTML(rep *report.Report, cfg *config.Config) ([]byte, []model.Diagnostic, error) {
	specJSON, diags, err := OpenAPI(rep, cfg)
	if err != nil {
		return nil, nil, err
	}

	// The browser tab must not show the same generic string for every
	// target in a fleet: default to the spec's own info.title, which
	// OpenAPI already resolved from the repository name or a @title
	// annotation (openapi.go) — falling back to the generic constant only
	// if that somehow came back empty. cfg.OpenAPI.Title, when set, still
	// wins over both — the same precedence OpenAPI itself applies to
	// info.Title.
	title := "Gin Recon API"
	var specInfo struct {
		Info struct {
			Title string `json:"title"`
		} `json:"info"`
	}
	if err := json.Unmarshal(specJSON, &specInfo); err == nil && specInfo.Info.Title != "" {
		title = specInfo.Info.Title
	}
	if cfg != nil && cfg.OpenAPI != nil && cfg.OpenAPI.Title != "" {
		title = cfg.OpenAPI.Title
	}

	// The page title is independent of the repository link: even a
	// --config-overridden title still points at the real repository this
	// report is actually about, derived straight from the module path
	// (openapi.go's repoURLFrom), never from the (possibly unrelated)
	// display title.
	repoURL := repoURLFrom(rep.Target.Module)

	page := fmt.Sprintf(htmlPageTemplate, html.EscapeString(title), themeCSS, htmlViewerCSS, brandMarkHTML, html.EscapeString(rep.ToolVersion), html.EscapeString(repoURL), escapeScriptClose(specJSON), htmlViewerJS)
	return []byte(page), diags, nil
}

// escapeScriptClose neutralizes the one sequence an HTML tokenizer looks for
// while inside any <script> element, regardless of its type attribute: a
// literal "</". Route paths, symbol names, and detail text embedded in the
// OpenAPI document can originate from the scanned repository's own source
// (docs/threat-model.md: "values designed to enter reports"), so a route
// registered with a path literally containing "</script>" must not be able
// to terminate the embedding script element early and inject sibling
// markup. This is unrelated to (and does not replace) JSON's own string
// escaping, which encoding/json already applied when OpenAPI built specJSON;
// it only protects the HTML parser's view of the surrounding document.
func escapeScriptClose(data []byte) []byte {
	return bytes.ReplaceAll(data, []byte("</"), []byte(`<\/`))
}

const htmlPageTemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%s</title>
<style>%s
%s</style>
</head>
<body class="gr-shell">
<header class="gr-site-header">
<div class="gr-page gr-site-header__inner"><span class="gr-brand">%s<span>gin-recon</span></span>
<div class="gr-header-meta">Offline API evidence<br>gin-recon %s</div></div>
</header>
<div id="app" class="gr-page gr-main" data-repo-url="%s">Loading…</div>
<script id="gin-recon-spec" type="application/json">%s</script>
<script>%s</script>
</body>
</html>
`

// htmlViewerCSS supplies only the styling api.html has no shared
// equivalent for (operation rows, method-color chips, schema trees,
// examples) — page chrome, hero, filter bar, panel framing, and status
// badges are deliberately left to theme.go's own .gr-page/.gr-hero/
// .gr-filters/.gr-panel/.gr-badge classes instead of a second, divergent
// copy, so this page reads as the same design system as fleet.html
// (docs/adr/0029-fleet-html-evidence-dashboard.md's dashboard and this
// page are meant to look like one tool's output, not two).
const htmlViewerCSS = `
:root {
  --bg: var(--gr-bg); --fg: var(--gr-ink); --muted: var(--gr-muted); --border: var(--gr-border);
  --card: var(--gr-panel); --code-bg: var(--gr-panel-muted);
  --get: #2563eb; --post: #16a34a; --put: #d97706; --patch: #7c3aed;
  --delete: #dc2626; --other: #6b7280;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--fg); }
.gr-hero h1 a { color: inherit; text-decoration: none; }
.gr-hero h1 a:hover { text-decoration: underline; }
.gr-ops-list details.tag-group { border-top: 1px solid var(--border); }
.gr-ops-list details.tag-group:first-child { border-top: none; }
details.tag-group > summary { cursor: pointer; padding: 12px 16px; background: var(--gr-panel-muted); font-weight: 700; list-style: none; display: flex; justify-content: space-between; }
details.tag-group > summary::-webkit-details-marker { display: none; }
details.tag-group > summary .count { color: var(--muted); font-weight: 400; }
.op-row { border-top: 1px solid var(--border); }
.op-row > summary { cursor: pointer; padding: 10px 16px; list-style: none; display: flex; align-items: center; gap: 10px; }
.op-row > summary::-webkit-details-marker { display: none; }
.op-row:hover > summary { background: var(--code-bg); }
.method { display: inline-block; min-width: 58px; text-align: center; padding: 2px 6px; border-radius: 4px; color: #fff; font-weight: 700; font-size: 11px; }
.method.get { background: var(--get); } .method.post { background: var(--post); }
.method.put { background: var(--put); } .method.patch { background: var(--patch); }
.method.delete { background: var(--delete); } .method.other { background: var(--other); }
.path { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
.op-body { padding: 4px 16px 16px 86px; color: var(--muted); }
.op-body dl { display: grid; grid-template-columns: max-content 1fr; gap: 4px 12px; margin: 8px 0; }
.op-body dt { font-weight: 600; color: var(--fg); }
.op-body dd { margin: 0; min-width:0; overflow-wrap:anywhere; }
.op-body code { background: var(--code-bg); padding: 1px 5px; border-radius: 4px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; overflow-wrap:anywhere; }
table.params { border-collapse: collapse; margin: 6px 0; width: 100%; }
table.params th, table.params td { text-align: left; padding: 4px 8px; border-bottom: 1px solid var(--border); font-size: 13px; }
.gr-empty { margin:0; padding:22px 16px; color:var(--gr-muted); text-align:center; }
.op-summary { color: var(--fg); font-weight: 600; font-size: 14px; margin: 6px 0 2px; }
.op-description { color: var(--muted); margin: 0 0 10px; white-space: pre-line; }
.schema-section { margin: 14px 0 4px; }
.schema-section h4 { margin: 0 0 6px; font-size: 12px; text-transform: uppercase; letter-spacing: .03em; color: var(--muted); font-weight: 700; }
.schema-media { font-size: 11px; color: var(--muted); margin-bottom: 4px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
ul.schema-tree { list-style: none; margin: 0; padding-left: 16px; border-left: 1px solid var(--border); }
ul.schema-tree.schema-tree-root { padding-left: 0; border-left: none; }
li.schema-field { margin: 5px 0; }
.schema-field-head { display: flex; align-items: baseline; gap: 8px; }
.schema-name { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; color: var(--fg); font-weight: 600; }
.schema-type { color: var(--gr-good); font-size: 12px; }
.schema-required { color: var(--delete); font-size: 10px; text-transform: uppercase; }
.schema-desc { color: var(--muted); font-size: 12px; margin: 1px 0 0; }
pre.example { background: var(--code-bg); border-radius: 6px; padding: 10px 12px; overflow-x: auto; margin: 6px 0 0; }
pre.example code { background: none; padding: 0; font-size: 12px; }
@media (max-width:720px) {
  .op-row > summary { align-items:flex-start; flex-wrap:wrap; }
  .op-body { padding-left:16px; }
  .op-body dl { grid-template-columns:1fr; gap:2px; }
  .op-body dd + dt { margin-top:8px; }
}
@media print { .gr-filters { display:none; } details.tag-group { break-inside:avoid; } }
`

// htmlViewerJS is intentionally framework-free vanilla JS. Every value that
// could originate from scanned-repository source (path segments, handler
// names, middleware symbols, source locations) is written with
// node.textContent, never innerHTML/insertAdjacentHTML — so no additional
// escaping is required for it to render as inert text regardless of
// content, the same guarantee mdEscape provides for Markdown/SARIF but
// enforced structurally here instead of by string substitution.
const htmlViewerJS = `
(function () {
  "use strict";
  var spec = JSON.parse(document.getElementById("gin-recon-spec").textContent);
  var app = document.getElementById("app");
  var usedOpIds = Object.create(null);

  function el(tag, attrs, text) {
    var e = document.createElement(tag);
    if (attrs) for (var k in attrs) e.setAttribute(k, attrs[k]);
    if (text !== undefined && text !== null) e.textContent = text;
    return e;
  }

  // tagFor is only a fallback for a spec with no tags — the OpenAPI
  // formatter now sets op.tags itself (internal/format/openapi.go's tagFor),
  // so both the raw JSON and this viewer agree on groupings from one place.
  function tagFor(path) {
    var parts = path.split("/").filter(Boolean);
    for (var i = 0; i < parts.length; i++) {
      if (parts[i].charAt(0) !== "{") return parts[i];
    }
    return "default";
  }

  // opId derives a stable per-operation element id from method+path, so an
  // operation can be linked and reopened directly via a URL fragment (see
  // render()'s deep-link handling below). The sanitized slug is lossy
  // (case and punctuation both collapse), so two distinct paths can
  // legitimately produce the same slug — e.g. a real pair of routes seen
  // in practice, "/lender/abfl/digiSIgn" and "/lender/abfl/digiSign",
  // differing only in case. usedOpIds disambiguates any such collision
  // with a numeric suffix, the same pattern openapi.go's own usedIDs
  // already uses for operationId collisions server-side, so every
  // operation still gets a unique, stable id to link to.
  function opId(method, path) {
    var base = "op-" + method + "-" + path.replace(/[^a-zA-Z0-9]+/g, "-").replace(/^-+|-+$/g, "").toLowerCase();
    var id = base;
    var n = 1;
    while (usedOpIds[id]) { n++; id = base + "-" + n; }
    usedOpIds[id] = true;
    return id;
  }

  // authStatusBadgeClass mirrors fleet_html.go's own gr-badge convention
  // for the same three statuses (proven good, public/unknown warn) so a
  // route's auth evidence reads the same color whether seen in fleet.html's
  // table or here.
  function authStatusBadgeClass(authStatus) {
    return "gr-badge " + (authStatus === "proven" ? "gr-badge--good" : "gr-badge--warn");
  }

  function authBadge(ext) {
    if (!ext || !ext.authStatus) return null;
    return el("span", { class: authStatusBadgeClass(ext.authStatus) }, ext.authStatus);
  }

  // evidenceBadge renders a small provenance marker next to Summary/
  // Description when x-gin-recon.evidenceSource says a source outside
  // gin-recon's own static analysis (a swag doc comment, or a pre-existing
  // OpenAPI document reconciled per ADR 0013) actually supplied that prose —
  // set only when one of those sources won, never for gin-recon's own
  // generic placeholder or for the (not-yet-built) analyzer-typed case, per
  // internal/format/openapi.go's ginReconExt.EvidenceSource. Worded for a
  // reader who has never seen gin-recon's internals, not by literal field
  // name.
  function evidenceBadge(ext) {
    if (!ext || !ext.evidenceSource) return null;
    var label = ext.evidenceSource === "swag" ? "from code comment" : "from existing OpenAPI document";
    return el("span", { class: "gr-badge gr-badge--neutral" }, label);
  }

  function paramsTable(params) {
    if (!params || !params.length) return null;
    var table = el("table", { class: "params" });
    var head = el("tr");
    ["Name", "In", "Required", "Type"].forEach(function (h) { head.appendChild(el("th", null, h)); });
    table.appendChild(head);
    params.forEach(function (p) {
      var row = el("tr");
      row.appendChild(el("td", null, p.name));
      row.appendChild(el("td", null, p.in));
      row.appendChild(el("td", null, p.required ? "yes" : "no"));
      row.appendChild(el("td", null, (p.schema && p.schema.type) || ""));
      table.appendChild(row);
    });
    return table;
  }

  // securityList renders the OpenAPI "security" requirement array's own
  // scheme names when present and non-empty. Otherwise — including when
  // the "security" key is absent from the operation entirely, not just an
  // empty array — the fallback text must reflect the route's real
  // authStatus (from x-gin-recon), never hardcode "public": gin-recon
  // *omits* the security key altogether (rather than emitting []) for a
  // proven route whose matched guard has no openapiScheme mapped to a
  // securitySchemes entry (see x-gin-recon.unrefined containing
  // "security") — that omission is by far the common case, not a rare
  // edge, since most audited services never configure openapiScheme at
  // all. Treating "no security array" (undefined or []) as silent evidence
  // of "public" would flatly contradict the auth badge shown right above
  // this same row for the majority of proven routes in a typical report.
  function securityList(security, authStatus) {
    if (security && security.length > 0) {
      var names = [];
      security.forEach(function (req) { for (var k in req) names.push(k); });
      return el("code", null, names.join(", ") || "(empty requirement)");
    }
    if (!authStatus) return null; // no x-gin-recon evidence at all (e.g. an inventory-only document) — nothing to say
    if (authStatus === "proven") {
      return el("code", null, "none — proven route, but no openapiScheme configured (see Middleware/Unrefined)");
    }
    return el("code", null, "none (" + authStatus + ")");
  }

  // resolveSchema resolves $ref against components.schemas and flattens
  // allOf (both used by an enriched document's shared response envelope
  // pattern — see skills/openapi-doc/SKILL.md's "shared response envelope"
  // guidance). seen tracks $ref names already visited on this branch so a
  // recursive/self-referential schema renders a note instead of recursing
  // forever — this runs in a real browser tab, not a bounded analysis
  // process, so it needs its own cycle guard.
  function resolveSchema(schema, seen) {
    if (!schema || typeof schema !== "object") return schema;
    if (schema.$ref) {
      if (seen.has(schema.$ref)) return { type: "object", description: "(circular reference to " + schema.$ref + ")" };
      var m = /^#\/components\/schemas\/([^/]+)$/.exec(schema.$ref);
      var target = m && spec.components && spec.components.schemas && spec.components.schemas[m[1]];
      if (!target) return { type: "object", description: "(unresolved " + schema.$ref + ")" };
      var next = new Set(seen);
      next.add(schema.$ref);
      return resolveSchema(target, next);
    }
    if (schema.allOf) {
      var merged = { type: "object", properties: {}, required: [] };
      schema.allOf.forEach(function (sub) {
        var r = resolveSchema(sub, seen);
        if (r.properties) for (var k in r.properties) merged.properties[k] = r.properties[k];
        if (r.required) merged.required = merged.required.concat(r.required);
        if (r.type && merged.type === "object") merged.type = r.type;
      });
      if (schema.description) merged.description = schema.description;
      return merged;
    }
    return schema;
  }

  function schemaTypeOf(schema) {
    if (Array.isArray(schema.type)) return schema.type.join(" | ");
    if (schema.type) return schema.type;
    if (schema.properties) return "object";
    if (schema.enum) return "enum";
    return "any";
  }

  var maxSchemaDepth = 6;

  function schemaFieldNode(name, rawSchema, required, depth) {
    var schema = resolveSchema(rawSchema, new Set());
    var li = el("li", { class: "schema-field" });
    var head = el("div", { class: "schema-field-head" });
    if (name) head.appendChild(el("span", { class: "schema-name" }, name));
    head.appendChild(el("span", { class: "schema-type" }, schemaTypeOf(schema)));
    if (required) head.appendChild(el("span", { class: "schema-required" }, "required"));
    li.appendChild(head);
    if (schema.description) li.appendChild(el("div", { class: "schema-desc" }, schema.description));
    if (schema.enum) li.appendChild(el("div", { class: "schema-desc" }, "enum: " + schema.enum.map(String).join(", ")));
    if (depth < maxSchemaDepth) {
      if (schema.properties) {
        var required2 = new Set(schema.required || []);
        var keys = Object.keys(schema.properties);
        if (keys.length) {
          var ul = el("ul", { class: "schema-tree" });
          keys.forEach(function (k) { ul.appendChild(schemaFieldNode(k, schema.properties[k], required2.has(k), depth + 1)); });
          li.appendChild(ul);
        }
      } else if (schema.type === "array" && schema.items) {
        var ul2 = el("ul", { class: "schema-tree" });
        ul2.appendChild(schemaFieldNode("[item]", schema.items, false, depth + 1));
        li.appendChild(ul2);
      }
    }
    return li;
  }

  function schemaTree(schema) {
    var ul = el("ul", { class: "schema-tree schema-tree-root" });
    ul.appendChild(schemaFieldNode(null, schema, false, 0));
    return ul;
  }

  // exampleFor deterministically synthesizes a sample value from a schema —
  // the same well-established, purely mechanical technique Redoc/Swagger UI
  // use for "response samples": prefer an explicit example/examples/default/
  // enum value, otherwise fall back to a type-driven placeholder. This is
  // not inference about the target API — it makes no claim beyond "a value
  // shaped like this schema," which is exactly what the schema itself
  // already asserts.
  function exampleFor(rawSchema, depth, seen) {
    if (!rawSchema || depth > maxSchemaDepth) return undefined;
    if (rawSchema.$ref) {
      if (seen.has(rawSchema.$ref)) return null;
      var next = new Set(seen);
      next.add(rawSchema.$ref);
      return exampleFor(resolveSchema(rawSchema, new Set()), depth, next);
    }
    var schema = rawSchema.allOf ? resolveSchema(rawSchema, new Set()) : rawSchema;
    if (schema.example !== undefined) return schema.example;
    if (schema.examples) {
      if (Array.isArray(schema.examples) && schema.examples.length) return schema.examples[0];
      var exKeys = Object.keys(schema.examples);
      if (exKeys.length) {
        var first = schema.examples[exKeys[0]];
        return first && first.value !== undefined ? first.value : first;
      }
    }
    if (schema.default !== undefined) return schema.default;
    if (schema.enum && schema.enum.length) return schema.enum[0];
    var type = Array.isArray(schema.type) ? (schema.type.filter(function (t) { return t !== "null"; })[0] || schema.type[0]) : schema.type;
    switch (type) {
      case "string":
        if (schema.format === "date-time") return "2024-01-01T00:00:00Z";
        if (schema.format === "date") return "2024-01-01";
        return schema.title || "string";
      case "integer": case "number": return 0;
      case "boolean": return true;
      case "null": return null;
      case "array": {
        var item = exampleFor(schema.items, depth + 1, seen);
        return item === undefined ? [] : [item];
      }
      default:
        if (schema.properties) {
          var obj = {};
          Object.keys(schema.properties).forEach(function (k) { obj[k] = exampleFor(schema.properties[k], depth + 1, seen); });
          return obj;
        }
        return {};
    }
  }

  // schemaAndExampleSection builds one "Request body"/"Response <code>"
  // section. alwaysShow controls what happens when content carries no
  // schema at all — true for a response (gin-recon's own output always sets
  // a response description, even for its placeholder default response, e.g.
  // "Unspecified response — schema not inferred; see the document
  // description." — that text must still be visible even with nothing to
  // render below it, or a reader has no way to tell "no schema yet" from
  // "the viewer silently dropped something"), false for a request body
  // (gin-recon never sets one at all in v1, so there is no description to
  // preserve either way — an empty section would just be visual noise).
  function schemaAndExampleSection(title, description, content, alwaysShow) {
    var extra = [];
    var any = false;
    Object.keys(content || {}).forEach(function (mediaType) {
      var schema = content[mediaType] && content[mediaType].schema;
      if (!schema) return;
      any = true;
      extra.push(el("div", { class: "schema-media" }, mediaType));
      extra.push(schemaTree(schema));
      var example = exampleFor(schema, 0, new Set());
      if (example !== undefined) {
        var pre = el("pre", { class: "example" });
        pre.appendChild(el("code", null, JSON.stringify(example, null, 2)));
        extra.push(pre);
      }
    });
    if (!any && !alwaysShow) return null;
    var section = el("div", { class: "schema-section" });
    section.appendChild(el("h4", null, title));
    if (description) section.appendChild(el("div", { class: "schema-desc" }, description));
    extra.forEach(function (node) { section.appendChild(node); });
    return section;
  }

  function opBody(op) {
    var body = el("div", { class: "op-body" });
    var ext = op["x-gin-recon"] || {};
    var evidence = evidenceBadge(ext);
    if (op.summary) {
      var summaryEl = el("div", { class: "op-summary" });
      summaryEl.appendChild(document.createTextNode(op.summary));
      if (evidence) { summaryEl.appendChild(document.createTextNode(" ")); summaryEl.appendChild(evidence); }
      body.appendChild(summaryEl);
    }
    if (op.description) body.appendChild(el("div", { class: "op-description" }, op.description));
    var dl = el("dl");
    function row(label, valueNode) {
      if (!valueNode) return;
      dl.appendChild(el("dt", null, label));
      var dd = el("dd");
      dd.appendChild(valueNode);
      dl.appendChild(dd);
    }
    if (ext.handler) row("Handler", el("code", null, ext.handler));
    if (ext.source) row("Source", el("code", null, ext.source));
    if (ext.middleware && ext.middleware.length) row("Middleware", el("span", null, ext.middleware.join(" → ")));
    var sec = securityList(op.security, ext.authStatus);
    if (sec) row("Security", sec);
    if (ext.roles && ext.roles.length) row("Roles", el("span", null, ext.roles.join(", ")));
    if (ext.scopes && ext.scopes.length) row("Scopes", el("span", null, ext.scopes.join(", ")));
    if (ext.analysisConfidence) row("Analysis confidence", el("code", null, ext.analysisConfidence));
    if (ext.registrationKind) row("Registration kind", el("code", null, ext.registrationKind));
    if (ext.catchAll) row("Catch-all", el("code", null, "true"));
    if (ext.documentationSecurity && ext.documentationSecurity.length) row("Documented security (not validated)", el("span", null, ext.documentationSecurity.map(function (s) { return s.name + (s.scopes && s.scopes.length ? " [" + s.scopes.join(", ") + "]" : ""); }).join("; ")));
    if (ext.documentationIssues && ext.documentationIssues.length) row("Documentation issues", el("span", null, ext.documentationIssues.map(function (i) { return i.directive + ": " + i.message; }).join("; ")));
    if (ext.unrefined && ext.unrefined.length) row("Unrefined", el("span", null, ext.unrefined.join(", ")));
    if (ext.diagnosticCodes && ext.diagnosticCodes.length) row("Diagnostic codes", el("span", null, ext.diagnosticCodes.join(", ")));
    body.appendChild(dl);
    var pt = paramsTable(op.parameters);
    if (pt) body.appendChild(pt);
    if (op.requestBody && op.requestBody.content) {
      var rb = schemaAndExampleSection("Request body", op.requestBody.description, op.requestBody.content, false);
      if (rb) body.appendChild(rb);
    }
    Object.keys(op.responses || {}).sort().forEach(function (code) {
      var resp = op.responses[code];
      var section = schemaAndExampleSection("Response " + code, resp.description, resp.content, true);
      if (section && resp.headers) section.appendChild(el("div", { class: "schema-desc" }, "Headers: " + Object.keys(resp.headers).sort().join(", ")));
      if (section) body.appendChild(section);
    });
    return body;
  }

  function opRow(method, path, op) {
    var details = el("details", { class: "op-row", id: opId(method, path) });
    var summary = el("summary");
    summary.appendChild(el("span", { class: "method " + (["get","post","put","patch","delete"].indexOf(method) >= 0 ? method : "other") }, method.toUpperCase()));
    summary.appendChild(el("span", { class: "path" }, path));
    var badge = authBadge(op["x-gin-recon"]);
    if (badge) summary.appendChild(badge);
    details.appendChild(summary);
    details.appendChild(opBody(op));
    details.dataset.search = (method + " " + path + " " + (op.operationId || "") + " " +
      ((op["x-gin-recon"] && op["x-gin-recon"].handler) || "")).toLowerCase();
    details.dataset.method = method;
    details.dataset.auth = (op["x-gin-recon"] && op["x-gin-recon"].authStatus) || "";
    return details;
  }

  function filterField(label, control) {
    var field = el("div");
    var id = control.getAttribute("id");
    field.appendChild(el("label", id ? { for: id } : null, label));
    field.appendChild(control);
    return field;
  }

  function selectControl(id, options) {
    var select = el("select", { id: id });
    options.forEach(function (option) { select.appendChild(el("option", { value: option[0] }, option[1])); });
    return select;
  }

  function render() {
    app.textContent = "";
    var hero = el("div", { class: "gr-hero" });
    hero.appendChild(el("p", { class: "gr-eyebrow" }, "API documentation"));
    var titleText = (spec.info && spec.info.title) || "API";
    var h1 = el("h1");
    if (app.dataset.repoUrl) {
      h1.appendChild(el("a", { href: app.dataset.repoUrl, target: "_blank", rel: "noopener noreferrer" }, titleText));
    } else {
      h1.textContent = titleText;
    }
    hero.appendChild(h1);
    var pathCount = Object.keys(spec.paths || {}).length;
    hero.appendChild(el("p", { class: "gr-lede" },
      "OpenAPI " + spec.openapi + " · version " + ((spec.info && spec.info.version) || "") +
      " · " + pathCount + " path(s)"));
    app.appendChild(hero);

    var panel = el("section", { class: "gr-panel" });
    panel.appendChild(el("h2", { class: "gr-panel__title" }, "Operations"));

    var filterInput = el("input", { id: "filter", type: "search", placeholder: "Path, method, or handler…" });
    var methodFilter = selectControl("method-filter", [["", "All methods"], ["get", "GET"], ["post", "POST"], ["put", "PUT"], ["patch", "PATCH"], ["delete", "DELETE"], ["options", "OPTIONS"], ["head", "HEAD"], ["trace", "TRACE"]]);
    var authFilter = selectControl("auth-filter", [["", "All auth evidence"], ["proven", "Proven"], ["public", "Public"], ["unknown", "Unknown"], ["unclassified", "No auth assertion"]]);
    var clearSearch = el("button", { type: "button", class: "gr-search-clear", "aria-label": "Clear operation search", hidden: "" }, "×");
    var filterCount = el("span", { class: "gr-result-count", role: "status", "aria-live": "polite" });
    var filters = el("div", { class: "gr-filters", role: "search", "aria-label": "Filter operations" });
    var searchField = filterField("Search", filterInput);
    var searchControl = el("div", { class: "gr-search-control" });
    searchControl.appendChild(filterInput);
    searchControl.appendChild(clearSearch);
    searchField.appendChild(searchControl);
    filters.appendChild(searchField);
    filters.appendChild(filterField("Method", methodFilter));
    filters.appendChild(filterField("Authentication", authFilter));
    filters.appendChild(filterCount);
    panel.appendChild(filters);

    var groups = {};
    var groupOrder = [];
    Object.keys(spec.paths || {}).sort().forEach(function (path) {
      var item = spec.paths[path];
      ["get", "put", "post", "delete", "options", "head", "patch", "trace"].forEach(function (method) {
        var op = item[method];
        if (!op) return;
        var tag = (op.tags && op.tags[0]) || tagFor(path);
        if (!groups[tag]) { groups[tag] = []; groupOrder.push(tag); }
        groups[tag].push(opRow(method, path, op));
      });
    });
    groupOrder.sort();

    var opsList = el("div", { class: "gr-ops-list" });
    var noRoutes = el("p", { class: "gr-empty" }, "No routes in this report.");
    var noMatches = el("p", { class: "gr-empty", hidden: "" }, "No operations match these filters.");
    if (groupOrder.length === 0) opsList.appendChild(noRoutes);

    var allRows = [];
    groupOrder.forEach(function (tag) {
      var rows = groups[tag];
      var details = el("details", { class: "tag-group", open: "" });
      details.dataset.tag = tag;
      var summary = el("summary");
      summary.appendChild(el("span", null, tag));
      summary.appendChild(el("span", { class: "count" }, rows.length + " operation(s)"));
      details.appendChild(summary);
      rows.forEach(function (row) { details.appendChild(row); allRows.push(row); });
      opsList.appendChild(details);
    });
    opsList.appendChild(noMatches);
    panel.appendChild(opsList);
    app.appendChild(panel);

    // Read the caveat from the spec's own info.description rather than
    // keeping a second hardcoded copy here — internal/format/openapi.go's
    // schemaInferenceNote is the single source of truth for this text, so
    // the JSON and this viewer can never say something different about the
    // same document.
    var footerText = "Generated by gin-recon.";
    if (spec.info && spec.info.description) footerText += " " + spec.info.description;
    var footer = el("p", { class: "gr-footer" }, footerText);
    app.appendChild(footer);

    function updateFilters() {
      var q = filterInput.value.trim().toLowerCase();
      var method = methodFilter.value;
      var auth = authFilter.value;
      var visible = 0;
      allRows.forEach(function (row) {
        var rowAuth = row.dataset.auth || "unclassified";
        var show = (!q || row.dataset.search.indexOf(q) >= 0) &&
          (!method || row.dataset.method === method) &&
          (!auth || rowAuth === auth);
        row.hidden = !show;
        if (show) visible++;
      });
      app.querySelectorAll("details.tag-group").forEach(function (group) {
        var visibleInGroup = Array.prototype.some.call(group.querySelectorAll("details.op-row"), function (row) { return !row.hidden; });
        group.hidden = !visibleInGroup;
      });
      filterCount.textContent = visible + " of " + allRows.length + " operations";
      clearSearch.hidden = filterInput.value.length === 0;
      noMatches.hidden = visible !== 0 || allRows.length === 0;
    }

    filterInput.addEventListener("input", updateFilters);
    methodFilter.addEventListener("change", updateFilters);
    authFilter.addEventListener("change", updateFilters);
    clearSearch.addEventListener("click", function () {
      filterInput.value = "";
      updateFilters();
      filterInput.focus();
    });
    updateFilters();

    // Deep linking: an operation's own URL fragment (set from its stable
    // opId) opens that operation — and every ancestor <details> it lives
    // in — directly, so a link to one specific route survives a page
    // reload or gets shared/bookmarked, the same expectation Swagger UI's
    // deepLinking option sets for its own users. Kept native (URL fragment
    // + <details open>) rather than a routing library, matching this
    // viewer's own no-framework, no-third-party-JS posture.
    function openDeepLink() {
      var id = location.hash.slice(1);
      if (!id) return;
      var target = document.getElementById(id);
      if (!target) return;
      for (var node = target; node; node = node.parentElement) {
        if (node.tagName === "DETAILS") node.open = true;
      }
      updateFilters();
      target.scrollIntoView({ block: "center" });
    }
    allRows.forEach(function (row) {
      row.addEventListener("toggle", function () {
        if (row.open) history.replaceState(null, "", "#" + row.id);
      });
    });
    window.addEventListener("hashchange", openDeepLink);
    openDeepLink();
  }

  render();
})();
`
