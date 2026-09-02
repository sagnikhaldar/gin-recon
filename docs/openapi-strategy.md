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

Separately, each generated operation's `x-gin-recon` extension gains an optional `evidenceSource` marker (currently only `"swag"`) whenever `applySwagEvidence` actually replaced that operation's generic `summary`/`description`/`tags`/`deprecated` placeholder with prose from a handler's doc comment — never set for gin-recon's own placeholder, and never for an operation where swag contributed nothing. `api.html` reads this marker to render a small badge next to Summary ("from code comment"), visually consistent with the existing auth-status badges, so a reader can tell at a glance which operations' prose came from outside gin-recon's own static analysis.

## Traceability

Every generated operation includes `x-gin-recon` metadata with route identity, source, handler symbol, middleware symbols, auth status when audited, analysis confidence, request/response inference status, registration kind, and relevant diagnostic codes. When more than one registration shares the operation (see Route Conversion above), the same fields for every registration — including the first, already mirrored at the top level for backward compatibility — are also listed under `x-gin-recon.registrations`, in encounter order. Extensions must not expose absolute checkout paths or source snippets.

## Validation

Validate generated documents against OpenAPI 3.1 in tests using a pinned test-only `github.com/pb33f/libopenapi` dependency. Require deterministic key and array ordering, unique operation IDs, valid path parameters, resolvable component references, stable output across runs, and golden coverage for all supported binding/render patterns. Round-trip tests parse the emitted document independently from Gin Recon's formatter.
