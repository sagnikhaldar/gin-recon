# OpenAPI Strategy

## Contract

Gin Recon emits deterministic OpenAPI 3.1 documents from the normalized route registry. OpenAPI is a first-class contract, not an optimistic formatter: unresolved evidence remains visible and no schema detail is invented.

`inventory --format openapi` describes route and I/O evidence without security assertions. `audit --format openapi` additionally maps configured authentication evidence to security schemes and operation-level security.

## Route Conversion

- Convert Gin `:name` segments to `{name}` path parameters.
- Convert Gin catch-all `*name` segments to `{name}` and mark them with `x-gin-recon-catch-all: true`.
- Expand Gin `Any` into GET, POST, PUT, PATCH, HEAD, OPTIONS, DELETE, CONNECT, and TRACE in the report. Emit all OpenAPI-representable operations, including TRACE; retain CONNECT only in the report and emit a non-representable-method diagnostic.
- Expand `Match` exactly as registered. Preserve other custom methods in the report and diagnose those that cannot be represented as OpenAPI Path Item operations.
- Generate stable operation IDs from method and normalized path, adding a deterministic suffix for collisions.
- When two or more `routes.json` entries share the exact same method and normalized path — observed in practice from separate routers mounted as build or deployment variants — emit exactly one OpenAPI operation for it (OpenAPI permits no more), but never silently choose one registration over the others: every registration's evidence is preserved, under `x-gin-recon.registrations`, in encounter order. Diagnose the collision at `info` severity when every registration's handler, middleware, and auth evidence agree (consistent with an intentional build/deployment variant) and at `warning` severity when they differ, so a genuine discrepancy is distinguishable from a harmless duplicate.

## Request Inference

Infer request evidence from typed calls to `ShouldBind*`, `Bind*`, `MustBind*`, URI/query/header/form helpers, multipart/file access, and direct `gin.Context` request access. Resolve bound Go types through package type information.

Map JSON, XML, YAML, TOML, BSON, form-urlencoded, multipart, URI, header, and validation tags conservatively. Explicit bind methods select their documented media type; generic `ShouldBind`/`Bind` driven by request Content-Type emits the supported candidate media types and an uncertainty marker unless the route constrains Content-Type. Support named structs, embedded fields, pointers, slices, arrays, maps, scalar aliases, enums derived from typed constants, nullable values, and recursive types. Recursive and repeated structures become reusable `components/schemas` entries with deterministic names based on canonical package/type identity.

Path parameters are always required. Other fields are required only by resolved `binding:"required"` evidence or an explicit compatible reviewed schema; `json:"omitempty"` alone never decides request requiredness. Conflicting tag sources or unsupported custom unmarshalling produce diagnostics and explicit unrefined markers.

## Response Inference

Recognize typed Gin response APIs including JSON, PureJSON, IndentedJSON, SecureJSON, AsciiJSON, JSONP, XML, YAML, TOML, ProtoBuf, BSON, HTML, Data, DataFromReader, String, File, FileAttachment, SSEvent, Stream, Render, Status, and redirects. Map documented media types; file/data/stream output becomes a binary or streaming schema when supported. Custom renderers and unresolved content types remain explicit unrefined evidence. Evaluate constant status codes and resolve response value types where possible.

Multiple response variants for the same status are represented with `oneOf` only when all variants are resolved. Conditional or unresolved variants remain documented with conservative placeholders and evidence diagnostics. Every operation includes a default response when the analyzer cannot prove exhaustive status behavior.

## Security Mapping

Only audit evidence may create operation security. Gin Recon never invents a security scheme. A `proven` route receives operation-level `security` only when every referenced scheme is explicitly declared and validated in configuration; otherwise auth evidence remains solely in `x-gin-recon` with a diagnostic. Public routes use `security: []`. Unknown routes omit a positive security claim and carry an uncertainty extension. Generated documents never set top-level global `security`, so omission cannot inherit a misleading assertion.

Roles and scopes are preserved in `x-gin-recon` unless their configured scheme has an explicit OpenAPI scope mapping.

## Existing Documentation

Existing Swagger annotations or an input OpenAPI document may supplement code-derived evidence. Analyzer evidence remains authoritative for route existence, method, path, handler, middleware, and source.

User documentation may enrich summaries, descriptions, examples, tags, and schemas. It supplies a schema when code evidence is unresolved and may refine a code-derived schema only when structurally compatible with every resolved field, type, location, and requiredness constraint. A conflict retains the code-derived value, emits a structured diagnostic, marks the detail unrefined, and identifies both evidence origins. Manual security never overrides audit classification or configured scheme mapping.

### Swaggo/Swag Doc-Comment Annotations

Per `docs/adr/0012-swag-annotation-evidence.md`, a handler function's own swaggo/swag-style Go doc comment (`@Summary`, `@Description`, `@Tags`, `@Router`, `@Deprecated`) is parsed as supplementary evidence and recorded on the route as `swag` (`model.SwagInfo`, `internal/analyzer/gin.ParseSwagAnnotations`). `@Param`/`@Success`/`@Failure` and swaggo's broader type-schema system are out of scope; only the five directives above are recognized.

`@Summary`, `@Description`, `@Tags`, and `@Deprecated` — when present — replace this formatter's own generic operation `summary`/`tags`/`deprecated` outright, since gin-recon has no other authored prose to preserve for these fields (they were previously a mechanically generated placeholder, not reviewed content). `@Router`'s path and method are never used to set the route's actual `ginPath`/method; they are compared against the analyzer's own discovered route, and a disagreement produces a `swag-router-mismatch` diagnostic at warning severity rather than a silent override, per ADR 0007's evidence-precedence rule. A mismatch never suppresses the same comment's `@Summary`/`@Description`/`@Tags`/`@Deprecated`.

### Existing OpenAPI Document Reconciliation

Per `docs/adr/0013-existing-openapi-document-reconciliation.md`, a reviewer may name a pre-existing OpenAPI 3.0/3.1 *or Swagger 2.0* document via `analysis.existingOpenAPIDocument` (`internal/analyzer.ReconcileExistingDocument`, parsed with the already-present `github.com/pb33f/libopenapi` dependency). `internal/analyzer.loadExistingDocument` tries `BuildV3Model()` first and falls back to `BuildV2Model()` only if that fails, so a genuinely Swagger 2.0 document (top-level `swagger: "2.0"`) is recognized and reconciled identically to an OpenAPI 3.x one — same matching, merge/precedence, and diagnostic rules, regardless of which format the document is written in. Explicit configuration is opt-in — no implicit discovery of an arbitrary file by name — and fails soft: a missing file produces `openapi-spec-not-found`, a document that fails to build under either format produces `openapi-spec-invalid`, both at warning severity, and the scan proceeds exactly as if the field were unset.

Per `docs/adr/0014-auto-detect-existing-openapi-document.md`, when `analysis.existingOpenAPIDocument` is not set, gin-recon additionally auto-detects a document at one of 16 fixed conventional paths relative to `--src` (`internal/analyzer.ExistingDocumentCandidates`, checked in the documented order via `internal/analyzer.ResolveAndReconcileExistingDocument`) — the first candidate that both exists and parses into a document with at least one path item is used exactly as if explicitly configured. This is a fixed allowlist, never a recursive or broad glob: `.gin-recon/` output and any `*.base.*` filename (swaggo's partial-template convention) are simply never on the list. `analysis.disableExistingOpenAPIAutoDetect: true` restores the pre-ADR-0014, opt-in-only behavior exactly. Explicit configuration always wins outright; auto-detection never runs once it is set.

Matching is by exact (HTTP method, normalized path), where Gin's `:name`/`*name` and OpenAPI's `{name}` path-parameter syntaxes are both normalized to one comparable, parameter-name-erased shape — no fuzzy or prefix matching. Precedence for prose/schema content is, highest first: analyzer-typed evidence, `swag` annotations (ADR 0012), this document, then gin-recon's own generic placeholder; a lower-precedence source only fills a field a higher one left empty, recorded as `model.Route.ExistingDocument` (`summary`, `description`, `tags`, `deprecated`, plus per-path-parameter `description`s).

Before a matched document operation's path-parameter content is accepted, its parameter names must agree, in order, with the route's own discovered Gin path-parameter names — the structural-compatibility check ADR 0007/0013 require. A disagreement produces `openapi-spec-conflict` at warning severity, sets `existingDocument.paramConflict: true`, and marks the generated operation unrefined for `"parameters"` via the same `x-gin-recon.unrefined` mechanism already used for `"security"`, keeping gin-recon's own path-parameter derivation exactly as it already was. Prose fields (`summary`/`description`/`tags`/`deprecated`) are never gated by this check — like swag annotations, there is no analyzer-derived prose for them to conflict with.

A document operation with no matching discovered route is never synthesized into `routes[]`; it is surfaced instead in `existingDocumentReconciliation.orphanedOperations` (method, path, and the document's own summary) plus one `openapi-spec-orphan-operation` diagnostic at info severity per orphan — often normal (an intentionally undocumented route, or a stale document), not necessarily a defect. This feature never reads or applies a document's `security`/`securitySchemes` in any way: manual security assertions never override audit classification or configured scheme mapping, per this section's own opening rule above.

This same orphan list is also mirrored one layer further, into `openapi.json`/`api.html` themselves: `internal/format/openapi.go` reads `rep.ExistingDocumentReconciliation` (already computed by the time `format.OpenAPI` runs) and, only when it is non-nil with at least one orphan, sets a document-root `x-gin-recon-existing-document-reconciliation` extension (`{"orphanedOperations": [...]}`, same shape as the report field). The key is entirely absent — never an empty object — when reconciliation never ran or found nothing, matching `ExistingDocumentReconciliation`'s own "present only when configured" rule. `api.html` renders this as a distinct "Existing Document: Orphaned Operations" section (method, path, summary per orphan) beneath the main operations list, so a reviewer opening only the OpenAPI artifacts — not `routes.json`/`routes.md`/`results.sarif` — still sees which operations the existing document names that gin-recon never discovered in code. A report with no configured/auto-detected document renders no such section at all.

Separately, each generated operation's `x-gin-recon` extension gains an optional `evidenceSource` marker (`"swag"` or `"existingDocument"`) whenever `applySwagEvidence`/`applyExistingDocEvidence` actually replaced that operation's generic `summary`/`description`/`tags`/`deprecated` placeholder with prose from one of those two sources — never set for gin-recon's own placeholder, and never for an operation where neither source contributed anything. `api.html` reads this marker to render a small badge next to Summary ("from code comment" for swag, "from existing OpenAPI document" for this section's evidence), visually consistent with the existing auth-status badges, so a reader can tell at a glance which operations' prose came from outside gin-recon's own static analysis.

## Traceability

Every generated operation includes `x-gin-recon` metadata with route identity, source, handler symbol, middleware symbols, auth status when audited, analysis confidence, request/response inference status, registration kind, and relevant diagnostic codes. When more than one registration shares the operation (see Route Conversion above), the same fields for every registration — including the first, already mirrored at the top level for backward compatibility — are also listed under `x-gin-recon.registrations`, in encounter order. Extensions must not expose absolute checkout paths or source snippets.

## Validation

Validate generated documents against OpenAPI 3.1 in tests using a pinned test-only `github.com/pb33f/libopenapi` dependency. Require deterministic key and array ordering, unique operation IDs, valid path parameters, resolvable component references, stable output across runs, and golden coverage for all supported binding/render patterns. Round-trip tests parse the emitted document independently from Gin Recon's formatter.
