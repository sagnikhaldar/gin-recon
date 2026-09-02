# Configuration Contract

## Format and Validation

Configuration schema version `1` is accepted as strict JSON or YAML. The top-level object must contain `version: 1`. Unknown fields, duplicate mapping keys, type coercion, non-finite numbers, invalid UTF-8, malformed dates, and invalid nested policy expressions fail before scanning. YAML aliases are bounded and resolved to the same data model as JSON; custom tags are rejected.

Scalar CLI values override configuration. Repeatable CLI include/exclude values append as specified by the [CLI contract](cli-contract.md). Security caps cannot be exceeded by configuration.

## Canonical Symbols and Assurance

Middleware keys use Go canonical identities independent of import aliases:

- Function or factory: `example.com/project/internal/auth.RequireUser`
- Method: `example.com/project/internal/auth.(*Guard).RequireUser`
- Value with function type: `example.com/project/internal/auth.RequireUserMiddleware`

Generic instantiation arguments and source positions are not part of identity. A configured factory matches the call producing the `gin.HandlerFunc`; its arguments are never recorded. `authWrappers` contains canonical factories proven by review to preserve and always invoke a nested middleware argument.

Each `authMiddleware` entry contains:

- `assurance`: `analyze` (default) or `attested`.
- Optional non-empty `tags`, `roles`, and `scopes` arrays with duplicate rejection.
- Optional `openapiScheme` naming a validated configured scheme.

`analyze` requires a resolved supported enforcement shape. `attested` allows unresolved enforcement, but a proven contradiction always produces `unknown`.

## Top-Level Shape

```yaml
version: 1
authMiddleware:
  example.com/project/internal/auth.RequireUser:
    assurance: analyze
    tags: [authenticated]
    roles: [member]
    openapiScheme: bearerAuth
authWrappers: []
acceptedPublic: ["GET /health"]
policies: []
scan:
  include: ["**/*.go"]
  exclude: ["**/generated/**"]
  ignoreFile: ".gin-reconignore"
analysis:
  profile: typed
  allowDownloads: false
  workspace: off
  moduleMode: readonly
  goos: linux
  goarch: amd64
  tags: []
  followModules: []
limits:
  timeout: 30s
  maxFiles: 20000
  maxPackages: 5000
  maxFileBytes: 2097152
  maxDiagnostics: 1000
  maxOutputBytes: 26214400
  maxCallDepth: 32
openapi:
  title: "Service API"
  version: "0.0.0"
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT
```

`scan`, `analysis`, `limits`, and `openapi` are optional. CLI-only write controls such as `--out` and `--force` are never accepted in configuration.

`analysis.followModules` is a list of Go module import-path glob patterns (matched against a dependency's own module path, e.g. `github.com/myorg/**`) that registrar-following is explicitly permitted to cross into, beyond the target module's own source. Empty by default — no module boundary is ever crossed unless named here. Config-only: there is no `--follow-modules` CLI flag, the same deliberate pattern `authMiddleware`/`authWrappers`/`policies` already use for settings that widen trust and must come from a reviewed config file, not a one-off command-line argument. Rejected together with `analysis.profile: syntax-only`, which never resolves canonical symbols at all. See [docs/adr/0010-opt-in-cross-module-registrar-following.md](adr/0010-opt-in-cross-module-registrar-following.md) for the full rationale, including how a resolved cross-module route's `source.file` is represented (`<module path>@<version>/<path within the module>`, never an absolute filesystem path).

## Policies and Baselines

Policy selectors may use methods, path globs, auth statuses, tags, roles, scopes, canonical package prefixes, and surface kinds. Requirements support auth, any/all/no middleware, middleware order, any/all/no tags, roles, scopes, and recursive `all`, `any`, and `not`. Recursion is limited by `maxCallDepth`. Duplicate policy or exception IDs are rejected.

Every exception requires an ID, non-empty reason, route selector, and strict `YYYY-MM-DD` expiry. Expiry is evaluated in UTC and included in deterministic evidence. `acceptedPublic` entries use uppercase method plus normalized Gin path and reject duplicates.

## OpenAPI Schemes

Security schemes support valid OpenAPI 3.1 `http`, `apiKey`, `oauth2`, and `openIdConnect` shapes. Required fields are validated by type; OAuth URLs must be absolute HTTPS unless an explicit test-only mode is active. Middleware may reference only a declared scheme. No scheme is inferred from a middleware name or tag.

## Resource Defaults and Caps

Defaults are shown above. Hard caps are five minutes, 200,000 files, 20,000 packages, 20 MiB per file, 10,000 diagnostics, 100 MiB output, and call depth 128. Zero and negative values are invalid. Reaching a limit records a stable diagnostic and makes coverage incomplete; exceeding output capacity fails before emitting a truncated canonical JSON report.
