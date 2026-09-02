# OpenAPI documentation

gin-recon emits deterministic OpenAPI 3.1 documents from the normalized route registry. OpenAPI is a first-class contract here, not an optimistic formatter: unresolved evidence stays visible and no schema detail is invented.

`inventory --format openapi` describes route and I/O evidence without security assertions. `audit --format openapi` additionally maps configured authentication evidence to security schemes and operation-level security.

## Route conversion

- Convert Gin `:name` segments to `{name}` path parameters.
- Convert Gin catch-all `*name` segments to `{name}` and mark them with `x-gin-recon-catch-all: true`.
- Expand Gin `Any` into GET, POST, PUT, PATCH, HEAD, OPTIONS, DELETE, CONNECT, and TRACE in the report. Emit all OpenAPI-representable operations, including TRACE; retain CONNECT only in the report and emit a non-representable-method diagnostic.
- Expand `Match` exactly as registered. Preserve other custom methods in the report and diagnose those that cannot be represented as OpenAPI Path Item operations.
- Generate stable operation IDs from method and normalized path, adding a deterministic suffix for collisions.
- When two or more `routes.json` entries share the exact same method and normalized path (observed in practice from separate routers mounted as build or deployment variants), emit exactly one OpenAPI operation for it, since OpenAPI permits no more, but never silently choose one registration over the others: every registration's evidence is preserved, under `x-gin-recon.registrations`, in encounter order. The collision is diagnosed at `info` severity when every registration's handler, middleware, and auth evidence agree (consistent with an intentional build/deployment variant) and at `warning` severity when they differ, so a genuine discrepancy is distinguishable from a harmless duplicate.

## Request inference

Request evidence is inferred from typed calls to `ShouldBind*`, `Bind*`, `MustBind*`, URI/query/header/form helpers, multipart/file access, and direct `gin.Context` request access. Bound Go types are resolved through package type information.

JSON, XML, YAML, TOML, BSON, form-urlencoded, multipart, URI, header, and validation tags are mapped conservatively. Explicit bind methods select their documented media type; generic `ShouldBind`/`Bind` driven by request Content-Type emits the supported candidate media types and an uncertainty marker unless the route constrains Content-Type. Named structs, embedded fields, pointers, slices, arrays, maps, scalar aliases, enums derived from typed constants, nullable values, and recursive types are all supported. Recursive and repeated structures become reusable `components/schemas` entries with deterministic names based on canonical package/type identity.

Path parameters are always required. Other fields are required only by resolved `binding:"required"` evidence or an explicit compatible reviewed schema; `json:"omitempty"` alone never decides request requiredness. Conflicting tag sources or unsupported custom unmarshalling produce diagnostics and explicit unrefined markers.

## Response inference

Typed Gin response APIs are recognized, including JSON, PureJSON, IndentedJSON, SecureJSON, AsciiJSON, JSONP, XML, YAML, TOML, ProtoBuf, BSON, HTML, Data, DataFromReader, String, File, FileAttachment, SSEvent, Stream, Render, Status, and redirects. Documented media types are mapped; file/data/stream output becomes a binary or streaming schema when supported. Custom renderers and unresolved content types remain explicit unrefined evidence. Constant status codes are evaluated and response value types resolved where possible.

Multiple response variants for the same status are represented with `oneOf` only when all variants are resolved. Conditional or unresolved variants remain documented with conservative placeholders and evidence diagnostics. Every operation includes a default response when the analyzer cannot prove exhaustive status behavior.

## Security mapping

Only audit evidence may create operation security. gin-recon never invents a security scheme. A `proven` route receives operation-level `security` only when every referenced scheme is explicitly declared and validated in configuration; otherwise auth evidence remains solely in `x-gin-recon` with a diagnostic. Public routes use `security: []`. Unknown routes omit a positive security claim and carry an uncertainty extension. Generated documents never set top-level global `security`, so omission cannot inherit a misleading assertion.

Roles and scopes are preserved in `x-gin-recon` unless their configured scheme has an explicit OpenAPI scope mapping.

## Evidence precedence

Analyzer-resolved evidence (route identity, method, path, handler, middleware, source, configured authentication) is always authoritative. Existing documentation and annotations can only enrich prose and schemas where code evidence is unresolved, in this order:

1. **Analyzer-typed evidence.** An actually-bound Go request/response struct.
2. **swag/swaggo doc-comment annotations** (`@Summary`, `@Description`, `@Tags`, `@Router`, `@Deprecated` above a handler). Parsed automatically on every scan, with no configuration required.
3. **AI-assisted enrichment.** The bundled [`skills/openapi-doc`](../skills/openapi-doc/SKILL.md) skill reads real handler code to fill in request/response schemas that gin-recon itself doesn't infer.

Existing Swagger annotations or an input OpenAPI document may supplement code-derived evidence this way too. User documentation may enrich summaries, descriptions, examples, tags, and schemas; it supplies a schema when code evidence is unresolved and may refine a code-derived schema only when structurally compatible with every resolved field, type, location, and requiredness constraint. A conflict retains the code-derived value, emits a structured diagnostic, marks the detail unrefined, and identifies both evidence origins. Manual security never overrides audit classification or configured scheme mapping.

This precedence exists because Go types, Gin binding/render calls, annotations, and existing OpenAPI documents may disagree, and a silent precedence rule could produce incorrect security or request/response documentation. Last-write-wins merging, trusting annotations over code, and inventing missing types are all deliberately rejected: they conceal uncertainty instead of surfacing it. The cost is that a user may need to resolve a conflict themselves rather than receive a superficially complete but misleading document; that trade is intentional.

### Swaggo/swag doc-comment annotations

A handler function's own swaggo/swag-style Go doc comment is parsed as supplementary evidence and recorded on the route as `swag` (`model.SwagInfo`, `internal/analyzer/gin.ParseSwagAnnotations`). Only five directives are recognized:

- `@Summary <text>`: single line.
- `@Description <text>`: may repeat across consecutive lines, concatenated with a space, matching swaggo's own convention.
- `@Tags <comma,separated,tags>`.
- `@Router <path> [<HTTP_METHOD>]`: parsed for cross-checking only, never for setting a route's actual path or method.
- `@Deprecated`: a bare marker line.

`@Param`/`@Success`/`@Failure` and swaggo's broader type-schema system are out of scope. A doc comment with no recognized directive yields no annotation at all, so this stays purely additive to the [report schema](reference.md#route-evidence)'s existing route shape.

`@Summary`, `@Description`, `@Tags`, and `@Deprecated`, when present, replace this formatter's own generic operation `summary`/`tags`/`deprecated` outright. This is a narrower rule than the general evidence-precedence ladder above specifically because these four fields have no analyzer-derived alternative worth preserving: the previous "summary" was a mechanically generated placeholder with zero authorial intent, not evidence a human reviewed. There is nothing to conflict with, so there is nothing to arbitrate.

`@Router`'s path and method are never used to set the route's actual `ginPath`/method; they are compared against the analyzer's own discovered route (after converting Gin's `:name`/`*name` syntax to swaggo's own `{name}` form), and a disagreement produces a `swag-router-mismatch` diagnostic at warning severity rather than a silent override. This is deliberately below error severity: a stale doc comment is a documentation-hygiene issue, not a defect in the scanned application's actual behavior, and it never marks `scanCoverage.complete` false, since the analyzer discovered the route completely and the annotation is merely out of date. A mismatch never suppresses the same comment's `@Summary`/`@Description`/`@Tags`/`@Deprecated`.

Each generated operation's `x-gin-recon` extension also gains an optional `evidenceSource` marker (currently only `"swag"`) whenever swag evidence actually replaced that operation's generic placeholder, never set for gin-recon's own placeholder and never for an operation where swag contributed nothing. `api.html` reads this marker to render a small badge next to Summary ("from code comment"), so a reader can tell at a glance which operations' prose came from outside gin-recon's own static analysis.

## Traceability

Every generated operation includes `x-gin-recon` metadata with route identity, source, handler symbol, middleware symbols, auth status when audited, analysis confidence, request/response inference status, registration kind, and relevant diagnostic codes. When more than one registration shares the operation (see Route Conversion above), the same fields for every registration, including the first (already mirrored at the top level for backward compatibility), are also listed under `x-gin-recon.registrations`, in encounter order. Extensions must not expose absolute checkout paths or source snippets.

## Validation

Generated documents are validated against OpenAPI 3.1 in tests using a pinned test-only `github.com/pb33f/libopenapi` dependency. Tests require deterministic key and array ordering, unique operation IDs, valid path parameters, resolvable component references, stable output across runs, and golden coverage for all supported binding/render patterns. Round-trip tests parse the emitted document independently from gin-recon's own formatter.

## The self-contained HTML viewer

`audit --format openapi` (and `inventory --format openapi`) always writes `api.html` alongside `openapi.json`: a human-browsable view of the exact same OpenAPI 3.1 document, generated with zero AI and zero extra flags. A reasonable question is why this isn't just a generic viewer like Redoc or Swagger UI loaded from a CDN, since Redoc in particular is a strong, polished, industry-standard renderer with persistent sidebar navigation and full-text search.

Two things make gin-recon's situation different from that comparison. First, gin-recon is offline-by-default as a load-bearing security property of the analyzer itself, not an incidental detail: no telemetry, no network egress during a scan unless a user explicitly opts in with `--allow-downloads`. Second, `api.html` is gin-recon's own output artifact, not a third-party rendering step a user separately chooses to run. A report from this tool can describe unreleased, internal, or otherwise sensitive API surface (route paths, handler names, auth requirements), so whether the viewer for that report reaches out to the network is the same trust boundary as whether the analyzer does, just crossed one step later, at the moment a human opens the file rather than the moment gin-recon ran. A CDN-loaded Redoc bundle would cross that boundary on every single viewing, from every machine that ever opens the file, not once at scan time: the CDN operator would learn, from request timing alone, that some organization is viewing an API surface document. Pinning the bundle by version and Subresource Integrity hash closes the tampering risk but not the network-egress-on-view one, and adds a second release cadence to track and re-pin.

So `api.html` stays a self-contained, dependency-free HTML page generated entirely from data gin-recon already computed for `openapi.json`: no external stylesheet, script, font, or CDN reference of any kind, and no network access required to open it, ever, on any machine. It's a hand-written, deliberately small vanilla-JS renderer (`internal/format/html.go`), not a Redoc/Swagger UI embed; that file also has to make sure a hostile scanned repository's own route/symbol text can never break out of the page's embedded `<script>` element.

Redoc (or Swagger UI, or any other CDN-hosted viewer) remains available, but only as an explicit, human-invoked choice documented in the [`openapi-doc` skill](../skills/openapi-doc/SKILL.md) as an alternative regeneration step for the specific case where a very large API's sidebar and search genuinely earn their keep over gin-recon's own flat, tag-grouped page. It is never a built-in `--format` value or CLI flag, deliberately: a flag would make the offline/online trade-off one keystroke away from becoming the path of least resistance in a security tool whose whole premise is that the safe path should be the only path unless you go out of your way.

The result: `api.html` opens correctly on an air-gapped machine, from a downloaded CI artifact, or on a machine actively scanning a hostile repository, with the same zero-network guarantee as the rest of the tool. In exchange, gin-recon carries its own small amount of view-layer code rather than depending on an upstream project, and that page's UX is capped at what this project chooses to build into it.

## The `render` command

`gin-recon render` re-runs gin-recon's own formatting layer over an already-produced `routes.json` (or an equivalent, schema-valid report JSON document) instead of scanning a source tree. Every format gin-recon can produce (`routes.md`/`routes.txt`, `openapi.json`/`api.html`, `results.sarif`) is a pure function of the same one canonical document: the report struct that `routes.json` serializes. Regenerating any of these files today otherwise means rerunning `inventory`/`audit` from scratch: reloading the Go module, redoing the full static analysis, and reclassifying every route, just to re-run the last, cheapest step of turning an already-computed report back into bytes. For a large repository that full reanalysis is the expensive part of a run by a wide margin; formatting is comparatively instant.

`render`'s only input is `--report <path>` (required), a `routes.json`-shaped file loaded and schema-validated with the same path `--baseline` already uses; a malformed or schema-incompatible input is a validation failure (exit `1`), not a best-effort attempt. `--format` and `--out` share identical semantics and companion-file rules with `inventory`/`audit`, including that `sarif` is only valid when the loaded report's `command` field is `audit`. `--config` applies only to the parts of configuration the formatting layer itself reads, such as `openapi.securitySchemes`/`openapi.title`; anything already reconciled into the loaded report is not re-resolved.

`render` accepts no source tree, no `--src`, and makes no network or `go/packages` call of any kind: it only ever touches the one JSON file named by `--report`, and the config file if `--config` is given. It never re-runs discovery, classification, reconciliation, or auto-detection, since those already happened when the input `routes.json` was produced; `render` reformats, it does not enrich, merge, or recompute anything the original run did not already decide. It is deliberately scoped smaller than a sibling tool's own `render` command, which additionally spans organizations, multiple applications, and a multi-page site: gin-recon has exactly one report kind and one repository per scan, so that generality has no present need here.

The trade-off is one clear caveat: `render`'s output reflects whatever the *current* gin-recon binary's formatters produce, over data captured by whatever *older* binary produced the input `routes.json`. A schema-compatible but semantically stale report (for example, reformatted after a classifier ruleset change) renders with new formatting over old evidence, not an equally fresh result.
