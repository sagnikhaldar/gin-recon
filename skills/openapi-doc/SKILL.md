---
name: openapi-doc
description: >-
  Generate an OpenAPI 3.1 (Swagger) spec and browsable HTML doc for a Gin
  (gin-gonic) codebase. Use when asked to "generate an OpenAPI/Swagger spec",
  "document the API", "produce API docs from the routes", or "describe each
  endpoint's request and response". Drives gin-recon to build a deterministic
  skeleton (paths, security, and a self-contained HTML viewer, generated with
  zero AI), then reviews each handler's Go code to fill in real
  request/response schemas.
---

# OpenAPI/Swagger documentation (gin-recon)

Turns a Gin codebase into a documented **OpenAPI 3.1** document in two
layers — the same shape as express-recon's equivalent skill, but the
deterministic layer covers more ground here because Go has real static types
to mine, where JS does not:

1. **Skeleton (deterministic, zero AI).** `gin-recon` emits paths, methods,
   path parameters, per-operation `security` (from audit classification), a
   `summary` on every operation (method, path, and resolved handler — so even
   a generic viewer like Redoc/Swagger UI shows something meaningful instead
   of a bare HTTP verb), and an `x-gin-recon` extension per operation carrying
   the handler's `source` file:line, `authStatus`, middleware chain, and
   `analysisConfidence`. It **also** always writes a self-contained,
   dependency-free `api.html` viewer alongside `openapi.json` — no CDN, no
   network access to view it, no separate flag needed. That viewer already
   knows how to render a full request/response schema tree and a
   synthesized JSON example per response; it just has nothing to show yet
   for a placeholder schema, since `type: {}` has no fields to walk. Once
   step 2 below adds real schemas, re-embedding them (step 3) is enough to
   see them rendered — the viewer's logic doesn't change.
2. **Enrichment (AI code review — this skill, for now).** You read each
   handler at its `source`, refine the placeholder request/response schemas
   into real JSON Schema, and write a human `summary`/`description` per
   operation. See "Why this step exists (and won't always)" at the end —
   this is scoped to fill a gap gin-recon's roadmap intends to close
   deterministically, not a permanent architecture choice.

The skeleton's request/response bodies are placeholders: every operation
carries a single generic `default` response, and `info.description` states
this explicitly (`"gin-recon does not yet infer request/response body
schemas from handler code..."`) — read that field rather than assuming
silence means nothing is missing.

## 0. Locate the tool

Same as the `gin-recon-audit` skill: `gin-recon` on PATH, else
`${CLAUDE_PLUGIN_ROOT}/bin/gin-recon`, else build from a checkout with
`go build -o /tmp/gin-recon ./cmd/gin-recon`.

## 1. Generate the skeleton

Run over `audit` (not `inventory`) so the `security` section is populated
from auth classification. Discover the auth allowlist first if you don't
have one — see the `gin-recon-audit` skill's step 1 for `suggest-auth` usage
and config authoring.

```bash
gin-recon audit --src <repoDir> --config <cfg.json> \
  --format openapi --out <outDir>
```

This writes `<outDir>/openapi.json` **and** `<outDir>/api.html` (the HTML
viewer is generated automatically whenever `openapi` is requested with
`--out` — there is no separate `--format html`). Open `api.html` first for a
quick visual pass grouped by path segment; use `openapi.json` for the actual
enrichment work below.

Read the skeleton. Each operation has:

- `operationId`, `summary`, `tags` (derived from the path's first segment),
  `parameters` (path params only, always required), `responses` (a single
  placeholder `default`), `security`.
- `x-gin-recon`: `{ method, ginPath, source: "file:line", handler,
  middleware[], authStatus, roles[], scopes[], analysisConfidence,
  registrationKind, catchAll, unrefined[], diagnosticCodes[] }`.
- `x-gin-recon.registrations` — present only when more than one source
  registration shares the same method+normalized path (e.g. two separate
  routers both registering `POST /webhook/hero/:path`, seen in practice on
  a real multi-tenant service). OpenAPI allows exactly one operation per
  method+path, so gin-recon picks the first registration as the
  operation's own `x-gin-recon` fields and lists **every** registration
  (the first included) in `registrations`, each with its own
  `source`/`handler`/`middleware`/`authStatus` — nothing is ever silently
  dropped. A matching stderr diagnostic (`openapi-multiple-registrations`)
  says whether the registrations are identical evidence (consistent with a
  build/deployment variant) or genuinely differ. When you see this field:
  document the operation using **all** of the listed registrations, not
  just the first — if they differ in auth or behavior, say so explicitly in
  the `description` rather than picking one and treating it as the whole
  story; a route documented as one call site when it's actually two, with
  two different handlers and possibly two different auth postures, is a
  worse gap than a placeholder schema.

An operation's `summary`/`description`/`tags`/`deprecated` may already carry
real, human- or code-derived content gin-recon merged into the skeleton
itself, from an evidence source ranked above this skill's own AI enrichment
pass in gin-recon's evidence precedence (analyzer-typed evidence > `swag` >
this skill fills whatever is still a placeholder — see
[docs/openapi.md](../../docs/openapi.md#evidence-precedence)):
`swag` is a handler's own swaggo/swag-style Go doc comment
(`@Summary`/`@Description`/`@Tags`/`@Deprecated`,
see [docs/openapi.md](../../docs/openapi.md#swaggoswag-doc-comment-annotations)).
It is already applied to the fields above before you ever open the
skeleton — you're reading its result, not a raw evidence blob you still
need to merge yourself.

## 2. Document each operation (the AI pass)

For every operation, open the handler at `x-gin-recon.handler` /
`x-gin-recon.source` (and any function it delegates to — follow the call).
Then produce:

- **Input structure** — refine `parameters` (query/header params gin-recon
  doesn't yet mine) and add a `requestBody` with real JSON Schema by reading
  the handler's `ShouldBind*`/`Bind*`/`c.Query`/`c.Param`/`c.GetHeader` calls
  and the bound Go struct's fields, tags (`json`, `binding`, `form`), and
  types directly — Go's static types mean you are transcribing a concrete
  struct definition here, not inferring from usage the way you would for a
  loosely-typed JS handler. Prefer the struct's own field types/tags over
  guessing from runtime behavior.
- **Output structure** — refine `responses` per status code with real body
  schemas, transcribed the same way from the handler's `c.JSON`/`c.XML`/etc.
  calls and the Go type passed to them. Capture every status the handler can
  return (validation errors, auth failures, not-found), not just the happy
  path.
- **Notes** — set the operation `description` (behavior, side effects, auth
  expectation, gotchas). Before writing `summary`/`description`/`tags`,
  check whether the field already holds real content rather than gin-recon's
  own generic filler: the mechanical `"METHOD /path -> handler"` summary
  (`internal/format/openapi.go`'s own placeholder), an unset/empty
  `description`, and the path-derived `tags` are the only gin-recon-authored
  defaults; anything else already got there via `swag` evidence per the note
  above step 1. Treat that as already-authored and
  leave it alone — overwriting it with AI-generated text would regress
  reviewed or code-colocated content back down to placeholder quality and
  invert gin-recon's own evidence precedence. Only fill in what is genuinely
  still a placeholder or empty; this has no bearing on request/response body
  schemas, which gin-recon never infers on its own and remain this pass's
  job regardless of the prose fields' state.

Finding the handler: `x-gin-recon.handler` is a Go identifier
(`pkgAlias.FuncName` or `pkgAlias.(*Type).MethodName` in display form) and
`x-gin-recon.source` is its exact file:line — open it directly, there is no
DisplayName-vs-handlerResolved ambiguity to resolve the way express-recon's
JS analysis sometimes has (Go's type system means gin-recon either resolves
a handler to a real symbol or marks it unresolved in `diagnosticCodes`, not
a partial state in between).

If `x-gin-recon.unrefined` lists `"security"`, the route's guard matched but
gin-recon could not map it to a declared `openapi.securitySchemes` entry (or
the route is `unknown`) — do not invent a security requirement; leave it
absent and note the uncertainty in the description instead.

Schema guidance:

- **Look for a shared response envelope first.** Many Gin services wrap every
  response in a helper (e.g. `httputils.RespondOkay(ctx, ...)` /
  `c.JSON(200, gin.H{"success": ..., "data": ...})`). Model it **once** as a
  `components/schemas` entry and `$ref` it, with the per-endpoint `data`
  shape as the only variable part — the single highest-leverage move on a
  large API, exactly as for Express.
- Resolve shared DTOs (a request/response struct reused across handlers,
  `binding:"required"` tags, custom validators registered via
  `httpvalidators.RegisterCustomValidators`) into reusable
  `components/schemas` and `$ref` them rather than re-inlining.
- **Ground every schema in code you actually read.** If a field's type isn't
  visible in the code, keep the property but leave its schema open and note
  the uncertainty in the `description` — do not invent types or fields. This
  matters more here than for Express: a fabricated schema for a Go handler
  actively contradicts information that genuinely was available to read,
  where in JS it might merely be a guess filling a real gap.
- Preserve `security`, `summary`, and the `x-gin-recon` extension from the
  skeleton unless you have concrete evidence they're wrong — you own schema
  bodies and `description`, the tool owns route identity, security, and
  traceability.

## 3. Merge, validate, render

- Merge your schemas/notes onto the skeleton: the skeleton owns paths,
  methods, `security`, `summary`, and `x-gin-recon`; you own schema bodies,
  `description`, and `components/schemas`.
- Once every operation you touched has a real `requestBody`/`responses`
  schema, update `info.description` to say so for the operations covered (or
  remove the caveat entirely once the whole document is enriched) — don't
  leave the "does not yet infer" note standing next to schemas that in fact
  now exist.
- Write the result to `<outDir>/openapi.json` (and `.yaml` if the user wants
  YAML — gin-recon's own output is always JSON).
- Validate it is well-formed OpenAPI 3.1 — parse the JSON, confirm
  `openapi: "3.1.0"`, every operation has at least one response, and every
  `$ref` resolves against `components/schemas`. If a validator CLI is
  available (e.g. `npx @redocly/cli lint`), run it and fix what it flags.
- **Refresh the HTML view over your enriched document.** `api.html` from
  step 1 embeds the pre-enrichment spec — it needs the new JSON re-embedded
  to show your schemas. gin-recon's own viewer (unlike express-recon's,
  which only ever showed placeholders) already renders `summary`,
  `description`, and a full response/request schema tree with a synthesized
  JSON example per response — the same information Redoc shows — whenever
  the document actually has them. Two ways to get there:

  1. **Splice the enriched spec back into gin-recon's own `api.html`
     (default choice — stays offline, zero new dependency).** The viewer's
     rendering logic is already in the page; only the embedded JSON needs
     updating:

     ```bash
     node -e '
     const fs = require("node:fs");
     const html = fs.readFileSync(process.argv[1], "utf8");
     const spec = fs.readFileSync(process.argv[2], "utf8").replace(/<\//g, "<\\/");
     const out = html.replace(
       /(<script id="gin-recon-spec" type="application\/json">)[\s\S]*?(<\/script>)/,
       (_m, open, close) => open + spec + close
     );
     fs.writeFileSync(process.argv[1], out);
     ' <outDir>/api.html <outDir>/openapi.json
     ```

     The `.replace(/<\//g, "<\\/")` step matters: it mirrors
     `internal/format/html.go`'s own `escapeScriptClose` — a route path or
     schema description that happens to contain a literal `</script>`
     sequence must not be able to break out of the embedding `<script>`
     element. Skipping it would reopen exactly the injection risk that
     function exists to close. The page's visible header re-reads
     `spec.info.title` at render time, so it updates correctly; only the
     browser tab's `<title>` element stays whatever the original generation
     set — cosmetic only, not worth fixing by hand.

  2. **Regenerate via Redoc instead**, for a very large API where a
     persistent sidebar with search genuinely earns its keep over a flat
     tag-grouped list — the zero-install path, pinned by version with a
     Subresource Integrity hash so a compromised CDN can't inject code. This
     is a deliberate, one-off human choice, not something gin-recon itself
     ever does by default — see
     [docs/openapi.md](../../docs/openapi.md#the-self-contained-html-viewer)
     for why `api.html` stays self-contained and offline by default:

     ```bash
     node -e 'const fs=require("node:fs");const spec=fs.readFileSync(process.argv[1],"utf8");
     const SRC="https://cdn.jsdelivr.net/npm/redoc@2.1.5/bundles/redoc.standalone.js";
     const SRI="sha384-0GrsyTQc9Oqd8h+b2dbc4XdR2T/DYpy0tLNNstyx+LBMUyiBbcWPbEs9aRmUcaxD";
     fs.writeFileSync(process.argv[2],`<!doctype html><html><head><meta charset="utf-8"/>
     <title>API</title><meta name="viewport" content="width=device-width,initial-scale=1"/></head>
     <body><div id="redoc"></div>
     <script src="${SRC}" integrity="${SRI}" crossorigin="anonymous"></script>
     <script>Redoc.init(${spec},{expandResponses:"200,201"},document.getElementById("redoc"))</script>
     </body></html>`)' <outDir>/openapi.json <outDir>/api.html
     ```

     Keep the `integrity`/`crossorigin` pair when bumping the Redoc version
     (recompute with `openssl dgst -sha384 -binary <file> | openssl base64
     -A` against the fetched bundle). This needs network access to load
     ~900KB of third-party JS every time someone opens it, versus zero
     external requests for option 1 (docs/threat-model.md's offline-by-
     default posture) — don't use it for an audience that can't allow the
     CDN fetch (an air-gapped environment, a security-sensitive internal
     doc).

  Default to option 1 unless the API is large enough that Redoc's sidebar
  navigation is worth the network dependency. Either way, tell the user
  explicitly which one they're getting and why.
- Report coverage to the user: operations documented vs. left as
  placeholders, which tags/areas are complete, and any handlers that
  couldn't be resolved (`diagnosticCodes` non-empty) so they know where the
  docs are weakest.

## Scaling to large APIs

For many routes, document operations in parallel with subagents — give each
a slice of the operation list plus the skeleton path, and have each **return
only its merged fragments** (operation objects + any `components/schemas` it
added), not the whole document, to keep orchestration context small. Merge
centrally, then validate once. Only fan out this way when the user has opted
into multi-agent orchestration or the route count clearly warrants it (this
session found a real 120-route service where the fix was a static-analysis
bug, not a documentation-scale problem — check `scanCoverage`/route counts
look right before assuming you need to fan out at all).

## Why this step exists (and won't always)

`docs/openapi-strategy.md` — gin-recon's own design spec — commits to
inferring request/response body schemas **statically**, by resolving typed
`ShouldBind*`/`c.JSON`/etc. calls through `go/packages`' type information,
the same zero-AI approach the rest of the tool uses. That engine is not
built yet; v1 only ships the route/security skeleton this skill starts from.
This is a real, load-bearing difference from express-recon's equivalent
skill: Express has no static type system to mine, so express-recon's AI
enrichment pass is permanent — there is no future version of it that
becomes unnecessary. Gin-recon's is a **stopgap for an explicitly planned
capability**, not a permanent design choice. Once that inference engine
ships, most of step 2 becomes unnecessary for ordinary typed-struct
handlers, and this skill's remaining job shrinks to handling what static
inference genuinely cannot resolve (dynamic `gin.H{}` literals, reflection-
built responses, handlers that branch across incompatible response shapes) —
exactly the same category of judgment call `gin-recon-audit`'s "AI's role"
section describes for opaque middleware. Until then, treat every schema you
write here as documentation *of* the code, produced *by* reading the code —
never as a substitute for the deterministic evidence gin-recon already
provides for everything else in the document (routes, security, source
locations), which this skill must never overwrite or contradict.
