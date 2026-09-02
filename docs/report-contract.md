# Report Contract

## Versioning

Gin Recon reports begin at schema version `1.0`. The schema is owned and versioned independently from Express Recon, while framework-neutral concepts retain compatible meanings. Additive optional fields may be introduced in a minor schema revision; removals, renamed meanings, or changed required fields require a major revision.

## Report Envelope

Every report contains:

- `schemaVersion`, `tool`, `toolVersion`, `classifierRulesetVersion`, `command`, and `analysisProfile`.
- `target` with module/workspace identity and sanitized single build context (`goos`, `goarch`, sorted tags, workspace mode, module mode, and profile).
- Deterministically ordered `routes`, `globalMiddleware`, and `fallbackSurfaces`.
- `scanCoverage` and bounded `diagnostics`.
- For audits: `summary`, `findings`, evaluated policy metadata, and active exceptions.
- When a baseline is supplied: `delta` with route, auth, and finding changes.

Inventory reports omit authentication judgment, policy results, summary, and findings.

## Route Evidence

A route contains method, Gin path, normalized path, surface kind, middleware chain, final handler, source, path confidence, analysis confidence, build context, and evidence origins. Optional I/O evidence records request bindings, parameters, response variants, and resolved Go types.

A route optionally carries `swag`: best-effort evidence parsed from a swaggo/swag-style doc comment above its handler function (`@Summary`, `@Description`, `@Tags`, `@Router`, `@Deprecated`), per `docs/adr/0012-swag-annotation-evidence.md`. It is present only when the handler's doc comment contains at least one recognized directive. It never affects route identity or auth classification; a disagreement between `@Router` and the route's own discovered method/path produces a `swag-router-mismatch` diagnostic rather than changing either.

A route optionally carries `existingDocument`: best-effort evidence (`summary`, `description`, `tags`, `deprecated`, `paramDescriptions`, `paramConflict`) matched from a pre-existing OpenAPI document, either named explicitly via `analysis.existingOpenAPIDocument` or auto-detected at one of the fixed conventional paths per `docs/adr/0014-auto-detect-existing-openapi-document.md` (unless `analysis.disableExistingOpenAPIAutoDetect: true`), per `docs/adr/0013-existing-openapi-document-reconciliation.md`. It is present only when a document was resolved (explicit or auto-detected), the document parsed successfully, and a document operation matched this route by normalized (method, path). It ranks below analyzer-typed evidence and `swag` in prose/schema precedence and never affects route identity or auth classification. A structural disagreement on path parameter names produces an `openapi-spec-conflict` diagnostic, sets `paramConflict: true`, and leaves `paramDescriptions` empty; a document operation with no matching route is never added to `routes[]` — see `existingDocumentReconciliation` below.

Canonical route identity is the uppercase method plus normalized Gin path. `Any` and `Match` are expanded into concrete operations while retaining registration metadata. `NoRoute` and `NoMethod` are fallback surfaces and do not collide with normal route identities.

Middleware entries contain a display name, canonical package symbol when resolved, callable kind, source, registration scope (`global`, `group`, or `route`), ordering index, and resolution status. Raw argument values and arbitrary source text are excluded.

## Authentication

Audit routes use:

- `proven`: at least one canonical configured guard matched and satisfied its configured assurance mode without contradictory enforcement evidence.
- `public`: no configured guard matched and all relevant middleware evidence is resolved and non-opaque.
- `unknown`: middleware, control flow, route propagation, or analysis evidence is opaque or incomplete.

Each classification includes `classificationBasis`, `assurance`, `enforcementAnalysis` (`confirmed-shape`, `unresolved`, or `contradicted`), matched evidence, confidence, tags, roles, and scopes. Under `analyze`, confirmed shape is required. Under `attested`, unresolved shape is allowed. Contradicted evidence always yields `unknown`. `proven` remains a reviewer-backed assertion, not formal verification.

Because `attested` plus `unresolved` proves a route on configuration alone, without confirmed control-flow evidence, `summary` reports `provenByConfirmedShape` and `provenByAttestedUnresolved` as separate counts rather than a single `proven` total. This keeps analyzer-confirmed enforcement distinguishable from reviewer-trusted enforcement at a glance, without requiring a consumer to scan per-route evidence.

An accepted-public entry keeps the route `public`, sets `accepted: true`, suppresses its public-route finding, and produces a stale-baseline finding if it no longer matches a public route.

## Findings and Policies

Built-in findings include `public-route`, `opaque-middleware`, `matched-but-unenforced`, `stale-auth-config`, `per-verb-gap`, `stale-baseline`, `incomplete-analysis`, `gin-explicit-trust-all-proxies`, and `gin-explicit-debug-mode`. Configured policies emit `policy-violation` findings. Engine findings never alter route authentication.

`stale-auth-config` fires once per configured `authMiddleware`/`authWrappers` canonical symbol that is never matched against any resolved call site in the scanned code, so a rename or removal in the target repository is visible as a distinct finding rather than surfacing only as routes silently becoming `unknown`. It is suppressed only when the profile is `syntax-only` and canonical resolution itself is unavailable, in which case the corresponding coverage diagnostic applies instead.

Every finding has `id`, `ruleId`, stable `fingerprint`, severity, confidence, route identity where applicable, source, detail, recommendation, and structured evidence. Fingerprints hash rule identity, normalized method/path, and stable discriminator fields; they exclude source line and absolute checkout path.

Policies may select method, path, status, tag, role, scope, package, or surface kind. Requirements support authentication, middleware presence/absence/order, tags, roles, scopes, and nested `all`/`any`/`not`. Exceptions require an ID, reason, route selector, and valid ISO expiry date.

## Coverage and Diagnostics

Coverage records discovered/analyzed/failed packages and files, unresolved registrations, reached limits, exact build context, profile, and a boolean `complete`. `complete` means complete only for the recorded context and documented supported patterns; it never claims alternate operating systems, architectures, tags, or workspaces. A report may be operationally successful while incomplete, but `--fail-on incomplete` exits 2. Fatal inability to load the requested root or parse configuration exits 1.

Diagnostics use stable codes, severity, sanitized message, optional source, and affected route/package identity. They must be bounded and deterministically ordered.

## Existing OpenAPI Document Reconciliation

When a document is resolved — either `analysis.existingOpenAPIDocument` is configured, or it is auto-detected per `docs/adr/0014-auto-detect-existing-openapi-document.md` — and the document parses successfully, a report carries `existingDocumentReconciliation.orphanedOperations`: an array of `{ method, path, summary }` entries for every document operation that did not match any discovered route (`docs/adr/0013-existing-openapi-document-reconciliation.md`). The section is entirely absent — not present with an empty array — when no document was resolved at all (nothing configured and no auto-detection candidate matched, or `analysis.disableExistingOpenAPIAutoDetect: true` with nothing configured), the file could not be read (`openapi-spec-not-found`), or the document failed to parse (`openapi-spec-invalid`); both of those diagnostics are `warning` severity and the scan proceeds exactly as if no document had been resolved. Each orphan also produces an `openapi-spec-orphan-operation` diagnostic at `info` severity, since an intentionally undocumented-in-the-spec-but-real, or documented-but-removed, route is often normal rather than a defect. A structural conflict between a matched route's and document's path parameter names produces `openapi-spec-conflict` at `warning` severity (see Route Evidence above).

## Baselines and Exit Codes

Delta output includes added/removed routes, authentication regressions/improvements, new/resolved findings, and structured explanations of middleware/evidence changes. Fingerprint comparison remains stable across source-line moves.

Baseline comparison requires the same schema major, analysis profile, normalized build context, and route-normalization version. A mismatch is an operational error rather than a misleading delta.

- Exit `0`: command completed and no requested gate matched.
- Exit `1`: invalid arguments/configuration, unreadable target, schema failure, or other operational error.
- Exit `2`: one or more requested security, policy, regression, or completeness gates matched.

## Output Guarantees

JSON is the canonical representation. Pretty, Markdown, SARIF, OpenAPI, and MCP responses derive from the same immutable report or registry. Formatters must not mutate, reclassify, or silently discard evidence.
