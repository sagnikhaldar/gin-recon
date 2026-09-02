package format

import (
	"strings"
	"testing"

	"github.com/sagnikhaldar/gin-recon/internal/config"
	"github.com/sagnikhaldar/gin-recon/internal/model"
)

func TestHTMLProducesWellFormedSelfContainedPage(t *testing.T) {
	rep := inventoryWithRoutes(routeAt("GET", "/users/:id"))
	data, diags, err := HTML(rep, nil)
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}
	if len(diags) != 0 {
		t.Fatalf("unexpected diagnostics: %+v", diags)
	}
	out := string(data)

	for _, want := range []string{
		"<!doctype html>",
		`<title>Gin Recon API</title>`,
		`id="gin-recon-spec" type="application/json"`,
		`"openapi": "3.1.0"`,
		"/users/{id}",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q; got:\n%s", want, out)
		}
	}
	// No external resource of any kind — the whole point of not following
	// express-recon's CDN-based Redoc precedent.
	for _, unwanted := range []string{"http://", "https://", "cdn.", "<link "} {
		if strings.Contains(out, unwanted) {
			t.Errorf("output must be fully self-contained; found %q in:\n%s", unwanted, out)
		}
	}
}

// TestHTMLFooterReadsNoteFromSpecNotAHardcodedCopy is the regression for a
// duplication bug: the footer used to hardcode its own copy of the
// schema-inference caveat, separate from and able to drift out of sync with
// the one on info.description. The viewer must read it from the embedded
// spec instead, and the page's static JS scaffold must not carry its own
// second copy of that sentence.
func TestHTMLFooterReadsNoteFromSpecNotAHardcodedCopy(t *testing.T) {
	rep := inventoryWithRoutes(routeAt("GET", "/x"))
	data, _, err := HTML(rep, nil)
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := string(data)

	if !strings.Contains(out, "spec.info.description") {
		t.Errorf("expected the viewer to read the footer note from spec.info.description dynamically; got:\n%s", out)
	}
	if strings.Contains(out, "does not yet infer request/response body schemas") &&
		strings.Count(out, "does not yet infer request/response body schemas") > 1 {
		t.Errorf("the caveat text appears more than once — a hardcoded copy has crept back in alongside the embedded spec's own copy")
	}
	if strings.Contains(out, "docs/openapi-strategy.md") {
		t.Errorf("must not reference a repo-relative doc path unreachable outside a gin-recon checkout:\n%s", out)
	}
}

// TestHTMLRendersSummaryDescriptionAndSchemaTreesWhenPresent is the
// regression for a real gap found comparing gin-recon's own viewer against
// an AI-enriched spec rendered by Redoc: even when an operation's summary,
// description, requestBody, and response schemas are genuinely present in
// the document (via the openapi-doc skill's enrichment pass, or a future
// static inference engine), gin-recon's own viewer used to ignore all of
// them entirely — only Redoc's rendering showed a "proper name," response
// schema, or response sample. format.HTML itself never populates these
// fields (that's the documented v1 scope in openapi.go), so this test
// exercises the viewer's rendering logic the only way possible without a
// real browser: confirming the emitted page's JS actually reads and reacts
// to op.summary/op.description/op.requestBody/op.responses[*].content,
// rather than only ever displaying the mechanical method+path it always
// showed before. The corresponding end-to-end browser verification (a real
// AI-enriched spec rendered by this exact viewer in headless Chromium) was
// done manually this session; see the doc comments on resolveSchema/
// exampleFor in html.go for the rendering algorithm itself.
// TestHTMLSecurityFieldReflectsAuthStatusNotHardcodedPublic is the
// regression for two real, user-visible bugs found reviewing a live
// api.html, the second found only after "fixing" the first:
//
//  1. A route matched a configured guard under assurance: attested (so its
//     authStatus is "proven" and the top badge correctly showed "proven"),
//     but the guard's canonical symbol had no openapiScheme mapped to a
//     securitySchemes entry, so the OpenAPI "security" array was empty —
//     and the viewer's "Security:" detail row read only that empty array,
//     unconditionally rendering "none (public)" directly underneath a
//     badge that said "proven."
//  2. The first fix only handled security being an empty array — but
//     format.OpenAPI actually *omits* the "security" key entirely (not []),
//     for exactly this "proven, no scheme mapped" case, which is the
//     common case (most audited services never configure openapiScheme at
//     all: 664 of 758 routes in the real report that surfaced this). The
//     original code's "if (security === undefined) return null" short-
//     circuited before the new fallback logic ever ran, so the whole
//     Security row silently disappeared instead of showing the explanatory
//     text — worse than the original bug, since now there was nothing to
//     read at all.
//
// Both cases (undefined key and empty array) must produce the same
// authStatus-derived fallback text, never a hardcoded "public", and never
// silently vanish while other x-gin-recon evidence (the badge, Middleware)
// is still shown on the same row.
func TestHTMLSecurityFieldReflectsAuthStatusNotHardcodedPublic(t *testing.T) {
	rep := inventoryWithRoutes(routeAt("GET", "/x"))
	data, _, err := HTML(rep, nil)
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := string(data)

	// "none (public)" is still a legitimate rendered string for a genuinely
	// public route — the regression is the unconditional, hardcoded return
	// of it regardless of authStatus, so check for that exact old pattern
	// rather than the substring, which a truly public route still produces.
	if strings.Contains(out, `if (security.length === 0) return el("code", null, "none (public)");`) {
		t.Errorf("securityList still unconditionally hardcodes \"none (public)\" for every empty security array regardless of authStatus:\n%s", out)
	}
	// The real bug: an early "security === undefined" return that hides
	// the whole row before authStatus is ever consulted. The fixed
	// function must treat "security" as absent-or-empty in one branch,
	// keyed off truthiness/length together, not gate on undefined alone.
	if strings.Contains(out, `if (security === undefined) return null;`) {
		t.Errorf("securityList still short-circuits on an absent \"security\" key before ever consulting authStatus — this hides the Security row entirely for the common case where format.OpenAPI omits the key rather than emitting []:\n%s", out)
	}
	if !strings.Contains(out, "securityList(op.security, ext.authStatus)") {
		t.Errorf("securityList is not called with the route's authStatus, so its fallback text cannot reflect it:\n%s", out)
	}
	if !strings.Contains(out, `authStatus === "proven"`) {
		t.Errorf("expected securityList to special-case a proven route with no configured openapiScheme:\n%s", out)
	}
}

func TestHTMLRendersSummaryDescriptionAndSchemaTreesWhenPresent(t *testing.T) {
	rep := inventoryWithRoutes(routeAt("GET", "/x"))
	data, _, err := HTML(rep, nil)
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := string(data)

	for _, want := range []string{
		"op.summary", "op.description",
		"op.requestBody", "op.responses",
		"function resolveSchema(", "function exampleFor(", "function schemaTree(",
		"schemaAndExampleSection(",
		`class: "op-summary"`, `class: "op-description"`,
		`class: "schema-section"`, "ul.schema-tree",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q — viewer must render summary/description/schema data when present, not just method+path; got:\n%s", want, out)
		}
	}
}

// TestHTMLResponseDescriptionAlwaysRendersEvenWithoutASchema is the
// regression for a real bug found running the viewer against gin-recon's
// own use-be-api report: every response gin-recon itself generates carries
// a description ("Unspecified response — schema not inferred; see the
// document description.") but no content/schema at all (v1 scope). The
// response section used to be built and then only appended to the DOM when
// a schema was actually found, silently dropping that description whenever
// there was nothing else to show — which is every response gin-recon's own
// formatter produces before any enrichment. A response must always render
// its heading and description; only the schema tree and example are
// conditional on a schema actually being present.
func TestHTMLResponseDescriptionAlwaysRendersEvenWithoutASchema(t *testing.T) {
	rep := inventoryWithRoutes(routeAt("GET", "/x"))
	data, _, err := HTML(rep, nil)
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := string(data)
	if !strings.Contains(out, `schemaAndExampleSection("Response " + code, resp.description, resp.content, true)`) {
		t.Errorf("responses must call schemaAndExampleSection with alwaysShow=true so the heading/description render even with no schema; got:\n%s", out)
	}
	if !strings.Contains(out, "if (!any && !alwaysShow) return null;") {
		t.Errorf("schemaAndExampleSection must only skip rendering when both no schema was found AND alwaysShow is false; got:\n%s", out)
	}
}

// TestHTMLExampleSynthesisIsPurelyMechanical documents (via the JS source
// itself, since Go tests cannot execute it without a browser) that example
// generation only ever uses explicit example/examples/default/enum values or
// a type-driven placeholder — the same technique Redoc/Swagger UI use — and
// never anything resembling a network call, AI request, or non-deterministic
// value (Math.random/Date.now), consistent with every other formatter in
// this package never fabricating evidence beyond what a schema itself
// already asserts.
func TestHTMLExampleSynthesisIsPurelyMechanical(t *testing.T) {
	rep := inventoryWithRoutes(routeAt("GET", "/x"))
	data, _, err := HTML(rep, nil)
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := string(data)
	for _, unwanted := range []string{"Math.random", "Date.now", "fetch(", "XMLHttpRequest", "WebSocket"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("viewer must stay fully offline and deterministic; found %q in:\n%s", unwanted, out)
		}
	}
}

func TestHTMLUsesConfiguredTitle(t *testing.T) {
	rep := inventoryWithRoutes()
	cfg := &config.Config{Version: 1, OpenAPI: &config.OpenAPIConfig{Title: "My Service API"}}
	data, _, err := HTML(rep, cfg)
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}
	if !strings.Contains(string(data), "<title>My Service API</title>") {
		t.Errorf("expected configured title in <title>; got:\n%s", data)
	}
}

func TestHTMLEscapesHostileTitle(t *testing.T) {
	rep := inventoryWithRoutes()
	cfg := &config.Config{Version: 1, OpenAPI: &config.OpenAPIConfig{Title: `</title><script>alert(1)</script>`}}
	data, _, err := HTML(rep, cfg)
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}
	if strings.Contains(string(data), "<script>alert(1)</script>") {
		t.Errorf("hostile config title was not escaped; got:\n%s", data)
	}
}

// TestHTMLEmbeddedSpecCannotBreakOutOfScriptTag is the regression for the
// exact threat docs/threat-model.md calls out for report content generally:
// a route whose path came from the scanned repository's own source could
// contain a literal "</script>" sequence. If the JSON embedding didn't
// neutralize that, the HTML parser would end the spec's <script> element
// early and treat the rest of the payload as page markup/script — this test
// proves the closing tag for the spec element is never split by embedded
// content and the page still renders exactly one spec script element.
func TestHTMLEmbeddedSpecCannotBreakOutOfScriptTag(t *testing.T) {
	line := 1
	route := model.Route{
		Method:             "GET",
		NormalizedPath:     "/x",
		GinPath:            "/x</script><script>alert(document.domain)</script>",
		SurfaceKind:        model.SurfaceRoute,
		FinalHandler:       model.Middleware{DisplayName: "h", CallableKind: model.CallableIdentifier, ResolutionStatus: model.Resolved},
		Source:             &model.Source{File: "r.go", Line: &line},
		PathConfidence:     model.ConfidenceHigh,
		AnalysisConfidence: model.ConfidenceHigh,
	}
	rep := inventoryWithRoutes(route)

	data, _, err := HTML(rep, nil)
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := string(data)

	if strings.Contains(out, "</script><script>alert") {
		t.Fatalf("hostile route path was not neutralized; raw script-closing sequence survived:\n%s", out)
	}
	if strings.Count(out, `id="gin-recon-spec"`) != 1 {
		t.Fatalf("expected exactly one spec script element, got %d; embedded content likely broke page structure:\n%s", strings.Count(out, `id="gin-recon-spec"`), out)
	}
}

func TestEscapeScriptCloseNeutralizesClosingSequence(t *testing.T) {
	in := []byte(`{"a":"</script><img onerror=alert(1)>"}`)
	got := escapeScriptClose(in)
	if strings.Contains(string(got), "</script>") {
		t.Errorf("escapeScriptClose left a literal </script> in output: %s", got)
	}
	if !strings.Contains(string(got), `<\/script>`) {
		t.Errorf("expected the escaped form <\\/script>, got: %s", got)
	}
}
