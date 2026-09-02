# Gin Recon

An inventory and audit tool for Gin route surfaces, built for humans, CI, and AI agents. It statically discovers routes, middleware chains, and authentication evidence, then flags routes that are public, unknown, or inconsistently guarded.

Version 1 is static-first, so it never executes the target application. See [PLAN.md](PLAN.md) for the full architecture and delivery plan, and [docs/](docs/) for the ADRs and contracts that govern this project's behavior.

## Status

Pre-release, with no stable binary yet. See [PLAN.md](PLAN.md#delivery-phases) for the current phase and [PLAN.md](PLAN.md#release-criteria) for what "stable" means at each stage. Both the `typed` and `syntax-only` analysis profiles and the commands below are implemented and tested. The MCP server (`cmd/gin-recon-mcp`) is planned but not yet built; see [docs/mcp-security.md](docs/mcp-security.md) and [PLAN.md](PLAN.md#delivery-phases).

## Commands

- `gin-recon inventory` - raw route, middleware, and source evidence with no security judgment.
- `gin-recon audit` - authentication classification, policy evaluation, findings, and baseline comparison (`--baseline`/`--fail-on new,regression`).
- `gin-recon suggest-auth` - ranked canonical middleware candidates to help write configuration. Suggestions never affect classification.
- `gin-recon schema` - emit the versioned report or configuration JSON Schema.

Adding `--format openapi --out <dir>` to either command also writes a versioned OpenAPI 3.1 document (`openapi.json`) and a self-contained, dependency-free HTML viewer (`api.html`) alongside the other report files. See [docs/adr/0009-self-contained-html-viewer.md](docs/adr/0009-self-contained-html-viewer.md) for why it isn't a CDN-loaded Redoc/Swagger UI embed.

Full CLI surface: [docs/cli-contract.md](docs/cli-contract.md). Configuration format: [docs/configuration-contract.md](docs/configuration-contract.md).

## OpenAPI evidence sources

Generated OpenAPI documents are never invented; see [docs/adr/0007-openapi-evidence-precedence.md](docs/adr/0007-openapi-evidence-precedence.md). Analyzer-resolved evidence (route identity, method, path, auth) is always authoritative. The following sources can only enrich prose and schemas where code evidence is unresolved, in this order:

1. **Analyzer-typed evidence** - an actually-bound Go request/response struct.
2. **swag/swaggo doc-comment annotations** (`@Summary`, `@Description`, `@Tags`, `@Router`, `@Deprecated` above a handler) - parsed automatically on every scan, with no configuration required. If a `@Router` line disagrees with the route gin-recon actually discovered, that produces a `swag-router-mismatch` diagnostic instead of being trusted outright. See [docs/adr/0012-swag-annotation-evidence.md](docs/adr/0012-swag-annotation-evidence.md).
3. **AI-assisted enrichment** - the bundled [`skills/openapi-doc`](skills/openapi-doc/SKILL.md) skill reads real handler code to fill in request/response schemas that gin-recon itself doesn't infer, skipping any field already populated by the sources above.

## Design principles

- A route is never treated as authenticated just because analysis is incomplete, a middleware name sounds security-related, or evidence is missing.
- Configured authentication evidence is a reviewer-backed assertion, not formal verification. See [docs/adr/0005-conservative-classification.md](docs/adr/0005-conservative-classification.md).
- No `unsafe`, `go:linkname`, or private Gin internals. See [docs/adr/0006-no-unsafe-runtime-introspection.md](docs/adr/0006-no-unsafe-runtime-introspection.md).
- Semantic versioning applies across releases, the report schema, the config schema, and the CLI/MCP contract together. See [PLAN.md](PLAN.md#versioning).

## Known boundaries

- One `--src` module scan produces one inventory. Gin Recon does not detect or partition multiple distinct `*gin.Engine` applications within a single repository, and has no stable per-service identifier beyond the scanned Go module path. Both are deliberately unbuilt roadmap items, not gaps; see [docs/adr/0011-multi-app-service-identity-and-spec-reconciliation.md](docs/adr/0011-multi-app-service-identity-and-spec-reconciliation.md).
- Registrar-following never crosses into a dependency module unless that module is explicitly named in `analysis.followModules`. See [docs/adr/0010-opt-in-cross-module-registrar-following.md](docs/adr/0010-opt-in-cross-module-registrar-following.md). An unresolved cross-module registrar is reported (`gin-unresolved-registrar`), not silently skipped.
- Auth classification is only as sound as the reviewed `authMiddleware` configuration. See [docs/adr/0005-conservative-classification.md](docs/adr/0005-conservative-classification.md).
- OpenAPI request/response schemas stay as generic placeholders until grounded by one of the evidence sources above. The AI-assisted `openapi-doc` skill is the intended way to close that gap for real handler code; gin-recon's static analysis alone won't do it.

## License

MIT. See [LICENSE](LICENSE).
