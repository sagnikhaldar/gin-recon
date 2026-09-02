# Gin Recon

Inventory and audit tool for Gin route surfaces — for humans, CI, and AI agents. Statically discovers routes, middleware chains, and authentication evidence, and flags routes that are public, unknown, or inconsistently guarded.

Version 1 is static-first: it never executes the target application. See [PLAN.md](PLAN.md) for the full architecture and delivery plan, and [docs/](docs/) for the ADRs and contracts that govern this project's behavior.

## Status

Pre-release. No stable binary yet — see [PLAN.md](PLAN.md#delivery-phases) for the current phase and [PLAN.md](PLAN.md#release-criteria) for what "stable" means at each stage. Both the `typed` and `syntax-only` analysis profiles and the commands below are implemented and tested; the MCP server (`cmd/gin-recon-mcp`) is planned but not yet built — see [docs/mcp-security.md](docs/mcp-security.md) and [PLAN.md](PLAN.md#delivery-phases).

## Commands

- `gin-recon inventory` — raw route, middleware, and source evidence with no security judgment.
- `gin-recon audit` — authentication classification, policy evaluation, findings, and baseline comparison (`--baseline`/`--fail-on new,regression`).
- `gin-recon suggest-auth` — ranked canonical middleware candidates to help write configuration; suggestions never affect classification.
- `gin-recon schema` — emit the versioned report or configuration JSON Schema.

`--format openapi --out <dir>` (either command) additionally writes a versioned OpenAPI 3.1 document (`openapi.json`) and a self-contained, dependency-free HTML viewer (`api.html`) alongside the other report files — see [docs/adr/0009-self-contained-html-viewer.md](docs/adr/0009-self-contained-html-viewer.md) for why it isn't a CDN-loaded Redoc/Swagger UI embed.

Full CLI surface: [docs/cli-contract.md](docs/cli-contract.md). Configuration format: [docs/configuration-contract.md](docs/configuration-contract.md).

## OpenAPI evidence sources

Generated OpenAPI documents are never invented — see [docs/adr/0007-openapi-evidence-precedence.md](docs/adr/0007-openapi-evidence-precedence.md). Analyzer-resolved evidence (route identity, method, path, auth) is always authoritative; the following sources may only enrich prose/schemas where code evidence is unresolved, in this precedence order:

1. **Analyzer-typed evidence** — an actually-bound Go request/response struct.
2. **swag/swaggo doc-comment annotations** (`@Summary`, `@Description`, `@Tags`, `@Router`, `@Deprecated` above a handler) — parsed automatically on every scan, no configuration required. A `@Router` line that disagrees with the route gin-recon actually discovered produces a `swag-router-mismatch` diagnostic rather than being trusted. See [docs/adr/0012-swag-annotation-evidence.md](docs/adr/0012-swag-annotation-evidence.md).
3. **A pre-existing OpenAPI/Swagger document already in the repo** — matched to routes by exact (method, normalized path), never fuzzy-matched. Auto-detected by default at one of 16 fixed, conventional paths (`openapi.yaml`, `docs/swagger.yaml`, `swagger.json`, etc. — see `ExistingDocumentCandidates` in `internal/analyzer/existingspec.go` for the exact, ordered list); an explicit `analysis.existingOpenAPIDocument` path always overrides auto-detection, and `analysis.disableExistingOpenAPIAutoDetect: true` turns auto-detection off entirely. Both OpenAPI 3.x and Swagger 2.0 documents are supported. A document operation with no matching discovered route is never fabricated into the route inventory — it's surfaced in `existingDocumentReconciliation.orphanedOperations` plus an `openapi-spec-orphan-operation` diagnostic instead. A structural disagreement (e.g. a conflicting path-parameter name) produces `openapi-spec-conflict` and keeps the code-derived value. The document's own `security`/`securitySchemes` are never consulted for auth classification, under any circumstance. See [docs/adr/0013-existing-openapi-document-reconciliation.md](docs/adr/0013-existing-openapi-document-reconciliation.md) and [docs/adr/0014-auto-detect-existing-openapi-document.md](docs/adr/0014-auto-detect-existing-openapi-document.md).
4. **AI-assisted enrichment** — the bundled [`skills/openapi-doc`](skills/openapi-doc/SKILL.md) skill reads real handler code to fill in request/response schemas gin-recon itself doesn't infer, skipping any field already populated by sources 1–3 above.

## Design principles

- A route is never treated as authenticated because analysis is incomplete, a middleware name looks security-related, or evidence is missing.
- Configured authentication evidence is a reviewer-backed assertion, not formal verification — see [docs/adr/0005-conservative-classification.md](docs/adr/0005-conservative-classification.md).
- No `unsafe`, `go:linkname`, or private Gin internals — see [docs/adr/0006-no-unsafe-runtime-introspection.md](docs/adr/0006-no-unsafe-runtime-introspection.md).
- Semantic versioning across releases, report schema, config schema, and CLI/MCP contract — see [PLAN.md](PLAN.md#versioning).

## Known boundaries

- One `--src` module scan produces one inventory — gin-recon does not detect or partition multiple distinct `*gin.Engine` applications within a single repository, and has no stable per-service identifier beyond the scanned Go module path. Both are deliberately unbuilt roadmap items, not gaps: see [docs/adr/0011-multi-app-service-identity-and-spec-reconciliation.md](docs/adr/0011-multi-app-service-identity-and-spec-reconciliation.md).
- Registrar-following never crosses into a dependency module unless that module is explicitly named in `analysis.followModules` — see [docs/adr/0010-opt-in-cross-module-registrar-following.md](docs/adr/0010-opt-in-cross-module-registrar-following.md). An unresolved cross-module registrar is reported (`gin-unresolved-registrar`), not silently skipped.
- Auth classification is only as sound as the reviewed `authMiddleware` configuration — see [docs/adr/0005-conservative-classification.md](docs/adr/0005-conservative-classification.md).
- OpenAPI request/response schemas remain generic placeholders until grounded by one of the evidence sources above; the AI-assisted `openapi-doc` skill is the intended way to close that gap for real handler code, not gin-recon's static analysis alone.

## License

MIT — see [LICENSE](LICENSE).
