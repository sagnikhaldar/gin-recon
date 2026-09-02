# gin-recon

Offline-first route inventory, authentication audit, and OpenAPI documentation for Gin. It parses Go source without executing the target application, and gives developers, CI jobs, and AI agents the same versioned evidence contract.

> `public` means no authentication middleware recognized by the supplied configuration. It does not prove a route is internet-reachable. `proven` is also configuration-relative: it means a known guard is present, not that the guard's implementation is correct.

## Install

```sh
go install github.com/sagnikhaldar/gin-recon/cmd/gin-recon@latest
```

Requires Go 1.25 or newer. This builds from source rather than downloading a pre-built binary; see [Status](#status) for why.

## Start here

### 1. Build a judgment-free route inventory

```sh
gin-recon inventory --src . --format json,md --out .gin-recon
```

This writes `routes.json` and `routes.md`: every route, its full middleware chain, source location, and scan coverage, with no security judgment attached. Check `scanCoverage.complete` and the diagnostics list before treating the inventory as final.

### 2. Identify real authentication guards

```sh
gin-recon suggest-auth --src . > .gin-recon/auth-candidates.json
```

Suggestions are candidates, not security decisions. Verify each middleware's actual implementation, then write a reviewed, data-only config:

```json
{
  "authMiddleware": {
    "github.com/you/app/internal/auth.RequireAuth": { "tags": ["authenticated"] }
  }
}
```

### 3. Audit and gate the result

```sh
gin-recon audit --src . --config gin-recon.json \
  --format json,md --out .gin-recon \
  --fail-on public,unknown
```

Exit code `2` means the requested gate matched: an expected policy result, not a scanner crash. Exit code `1` means invalid input or an operational failure.

## Commands

| Command | What it does |
| --- | --- |
| `inventory` | Raw route, middleware, and source evidence. No security judgment. |
| `audit` | Authentication classification, policy evaluation, findings, and baseline comparison (`--baseline`, `--fail-on new,regression`). |
| `suggest-auth` | Ranked canonical middleware candidates to help write configuration. Never affects classification. |
| `render` | Regenerates any output format from an already-saved `routes.json`, with no re-analysis: no source tree, no network, and typically well under a second even on a large repository. |
| `schema` | Emits the versioned report or configuration JSON Schema. |

Full reference: [docs/reference.md](docs/reference.md) for every flag and the config format.

## The evidence model

gin-recon separates facts from decisions:

- `inventory` records observed routes, middleware chains, source locations, and coverage. It makes no security judgment.
- `audit` applies a reviewed `authMiddleware` allowlist and optional policies to that inventory, producing `proven`, `public`, or `unknown` per route.
- A route is never treated as authenticated just because analysis is incomplete, a middleware name sounds security-related, or evidence is missing. This conservative-classification stance is deliberate: a silently-optimistic guess is worse than a route reported `unknown`.
- Configured authentication evidence is a reviewer-backed assertion, not formal verification.

Every JSON report is deterministic and versioned. Run `gin-recon schema` for its JSON Schema.

## OpenAPI documentation

```sh
gin-recon audit --src . --format openapi --out .gin-recon
```

This writes a versioned OpenAPI 3.1 document (`openapi.json`) alongside a self-contained, dependency-free HTML viewer (`api.html`), generated entirely offline with no CDN and no network access at view time. That's a deliberate choice, not an omission: see [docs/openapi.md](docs/openapi.md#the-self-contained-html-viewer) for why.

Generated documents are never invented. Analyzer-resolved evidence (route identity, method, path, auth) is always authoritative; the following sources can only enrich prose and schemas where code evidence is unresolved, in this order:

1. **Analyzer-typed evidence** - an actually-bound Go request/response struct.
2. **swag/swaggo doc-comment annotations** (`@Summary`, `@Description`, `@Tags`, `@Router`, `@Deprecated` above a handler) - parsed automatically on every scan, with no configuration required.
3. **AI-assisted enrichment** - the bundled [`skills/openapi-doc`](skills/openapi-doc/SKILL.md) skill reads real handler code to fill in request/response schemas that gin-recon itself doesn't infer.

See [docs/openapi.md](docs/openapi.md) for the full precedence rules and the swag annotation format.

## Pull-request gates

```sh
# Produce a baseline from the base revision.
gin-recon audit --src ./base --config gin-recon.json --format json --out ./base-results

# Compare the full PR inventory and gate only new findings/regressions.
gin-recon audit --src ./current --config gin-recon.json \
  --baseline ./base-results/routes.json \
  --format json,md --out ./current-results \
  --fail-on new,regression
```

Baseline comparison fails when the two reports carry different scan-scope fingerprints; scan both revisions with the same policy.

## Known boundaries

- One `--src` module scan produces one inventory. gin-recon does not detect or partition multiple distinct `*gin.Engine` applications within a single repository, and has no stable per-service identifier beyond the scanned Go module path. Both are deliberate, unbuilt roadmap items, not gaps.
- Registrar-following never crosses into a dependency module unless that module is explicitly named in `analysis.followModules`. An unresolved cross-module registrar is reported (`gin-unresolved-registrar`), not silently skipped. See [docs/reference.md](docs/reference.md#top-level-shape) for how to opt specific modules in.
- Auth classification is only as sound as the reviewed `authMiddleware` configuration.
- OpenAPI request/response schemas stay as generic placeholders until grounded by one of the evidence sources above.
- Static analysis cannot fully recover data-driven route registration or every dynamic dispatch pattern. It retains partial evidence and diagnostics instead of silently dropping it.

## Documentation

- [CLI, configuration, and report reference](docs/reference.md)
- [OpenAPI documentation](docs/openapi.md)
- [Security and threat model](docs/threat-model.md)

## Status

Pre-release, with no distributed binary yet. Both the `typed` and `syntax-only` analysis profiles and the commands above are implemented and tested. Source tags precede binary distribution, since signed binaries with provenance aren't operational yet, which is why `go install` builds from source above.

MIT licensed. Security issues should be reported privately as described in [SECURITY.md](SECURITY.md).
