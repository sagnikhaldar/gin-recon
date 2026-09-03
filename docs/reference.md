# Reference

This is the durable reference for gin-recon's CLI, configuration format, and
report schema. Start with the [README](../README.md) if you haven't run the
tool yet.

## Contents

- [CLI](#cli)
  - [Commands and exit codes](#commands-and-exit-codes)
  - [Common options](#common-options)
  - [Output and audit options](#output-and-audit-options)
  - [Render options](#render-options)
  - [Precedence and validation](#precedence-and-validation)
- [Configuration](#configuration)
  - [Format and validation](#format-and-validation)
  - [Canonical symbols and assurance](#canonical-symbols-and-assurance)
  - [Top-level shape](#top-level-shape)
  - [Policies and baselines](#policies-and-baselines)
  - [OpenAPI schemes](#openapi-schemes)
  - [Resource defaults and caps](#resource-defaults-and-caps)
- [Report schema](#report-schema)
  - [Versioning](#versioning)
  - [Report envelope](#report-envelope)
  - [Route evidence](#route-evidence)
  - [Authentication](#authentication)
  - [Findings and policies](#findings-and-policies)
  - [Coverage and diagnostics](#coverage-and-diagnostics)
  - [Baselines and exit codes](#baselines-and-exit-codes)
  - [Output guarantees](#output-guarantees)

## CLI

### Commands and exit codes

The executable is `gin-recon <command> [options]`.

- `inventory`: emit route, middleware, source, coverage, and optional I/O evidence without security judgment.
- `audit`: classify inventory, evaluate policies, compare an optional baseline, and emit findings.
- `suggest-auth`: emit ranked canonical middleware candidates as JSON; suggestions never change classification.
- `schema`: emit either the report or configuration JSON Schema.
- `render`: re-run formatting only, over an already-produced report; never scans a source tree.
- `fleet`: run `audit` once per target in a manifest, aggregating results with checkpointed resume.

Exit `0` means successful with no requested gate, `1` means argument/configuration/operational failure, and `2` means an audit gate matched. Help and version requests exit `0`.

### Common options

- `--src <dir>`: scan root; default is the current directory. Resolved once to an absolute real path.
- `--profile typed|syntax-only`: default `typed`.
- `--config <file>`: strict JSON/YAML configuration. Applicable to `inventory`, `audit`, and `suggest-auth`, since scan and analysis settings may be shared.
- `--include <glob>` / `--exclude <glob>`: repeatable root-relative source scope additions.
- `--ignore-file <path|none>`: default `.gin-reconignore`; the path must remain under `--src`.
- `--include-tests`: include `_test.go` files and test packages; default false.
- `--goos <value>` / `--goarch <value>`: typed-profile build context; defaults to the running tool's own values.
- `--tags <comma-list>`: build tags for the single report context; default empty.
- `--workspace off|<path>`: default `off`; an explicit path must resolve beneath `--src`.
- `--module-mode readonly|vendor`: default `vendor` when a valid root-contained vendor tree exists, otherwise `readonly`.
- `--allow-downloads`: typed mode only; default false. Without it, module and toolchain network access is disabled.
- `--timeout <duration>`: default 30 seconds, bounded by configuration limits.

One report represents exactly one GOOS/GOARCH/tag/workspace context. Multi-platform coverage is produced by running a CI matrix and retaining each report; `complete` never claims other build contexts.

### Output and audit options

- `--format pretty|json|md|openapi|sarif`: repeatable or comma-separated. Default `pretty`. `html` is not itself a selectable value (see below).
- `--out <dir>`: required when more than one format is selected. Files are `routes.json`, `routes.md`, `openapi.json`, `results.sarif`, and `routes.txt`. Requesting `openapi` with `--out` also always writes `api.html` alongside `openapi.json`, with no separate opt-in.
- `--force`: permit replacement of those exact output files; default is to fail before writing if any target exists.
- `--baseline <report.json>`: audit only; the baseline must pass compatible-schema validation.
- `--fail-on <selectors>`: audit only, comma-separated/repeatable. Supported selectors are `public`, `unknown`, `attested-unresolved`, `policy`, `policy:<id>`, `new`, `regression`, and `incomplete`. `new` and `regression` require `--baseline`. `attested-unresolved` matches any route `proven` solely through `assurance: attested` with `enforcementAnalysis: unresolved`, for teams that want confirmed-shape-only enforcement in CI even though attestation remains available for configuration.

SARIF is audit-only. Inventory OpenAPI contains no authentication assertions. `api.html` renders the exact same document as its accompanying `openapi.json`, never independently and never as a standalone format a user can request without `openapi` or omit while keeping `openapi`, as a single self-contained, dependency-free browsable page (no CDN, no external network access at view time, consistent with this tool's offline-by-default posture). See [OpenAPI documentation](openapi.md) for why. It is not written when `--out` is absent, since stdout carries only one file. When `--out` is absent, exactly one format is written to stdout; warnings and diagnostics intended for humans go to stderr. Canonical JSON report content is never mixed with logs.

`schema --kind report|config` defaults to `report`, accepts no scan/config/output options, and writes JSON to stdout. `suggest-auth` writes JSON to stdout unless `--out` is supplied, and does not accept baseline, fail-on, SARIF, or OpenAPI options.

### Render options

`render` re-runs gin-recon's formatting layer over an already-produced report instead of scanning a source tree: it accepts no `--src` and none of the other scan/analysis options above, and never calls `internal/analyzer` or `go/packages`. See [OpenAPI documentation](openapi.md#the-render-command) for the reasoning behind adding it as a separate command instead of a flag on `inventory`/`audit`.

- `--report <path>` (required): a `routes.json`-shaped file, loaded with the same load path `--baseline` uses. A missing, malformed, or schema-incompatible file fails with exit `1`.
- `--format` / `--out` / `--force`: follow the identical rules documented above, including the `api.html` companion file, except `sarif` is valid only when the loaded report's `command` is `audit`, checked against that document once it is loaded, not against `render` itself.
- `--config`: applies only to what the formatting layer itself reads (`openapi.title`/`openapi.securitySchemes`), not to any `analysis.*` setting, since no analysis runs.

### Fleet options

`fleet` orchestrates one `audit` subprocess per target in a manifest instead of scanning a single `--src`. It accepts none of the scan/analysis options above — each target supplies its own source, resolved from the manifest, not from a flag on this command. Each target's `audit` runs in its own subprocess rather than in-process, so one hostile or resource-exhausting target is contained by the same process boundary an ordinary single-repo scan already has.

- `--targets <file>` (required): a strict JSON manifest, `{"version": 1, "targets": [{"name": "...", "src": "..."}]}`. `name` becomes that target's output subdirectory name and must match `^[A-Za-z0-9._-]+$`; `src` is a local directory, resolved relative to the manifest file's own directory when not absolute.
- `--config <file>`: applied identically to every target's own `audit` invocation.
- `--out <dir>` (required): `fleet.json` (the aggregate) is written here, alongside each target's full, untouched report under `targets/<name>/`.
- `--force`: required to overwrite an existing `fleet.json`, same convention as every other command's output — unless `--resume` is also given.
- `--concurrency <n>`: default `1`, must be between `1` and `8`.
- `--resume`: skip any target already recorded as complete in `--out`'s checkpoint. Refused with an explanation, not silently ignored, if the targets file, `--config`, or `--format` no longer matches what the checkpoint was written under.
- `--format`: only `json` exists today.
- `--fail-on incomplete`: exits `2` when the aggregate's `coverage.complete` is false — any target failed, or any target's own `scanCoverage.complete` came back false. No other `--fail-on` selector is supported yet.

A target with no `go.mod` at all is recorded as `not-go-module`, distinct from `failed` — it never counts as a scan failure. A target whose `audit` subprocess actually errors is `failed` and is retried on the next `--resume`; a target that completed (even with incomplete internal coverage) is `ok` and is never retried.

### Precedence and validation

Precedence is scalar CLI option, configuration value, then documented default. Repeatable CLI include/exclude patterns append after configured patterns so explicit CLI exclusions are applied last; ignore-file negation rules are evaluated before explicit excludes. Unknown commands/options, duplicate scalar options, missing values, invalid durations, path escapes, inapplicable options, and conflicting formats fail with exit `1` before analysis or output writes.

All paths are resolved relative to `--src` except `--src` itself. Reports store root-relative slash-separated paths, never absolute checkout paths.

## Configuration

### Format and validation

Configuration schema version `1` is accepted as strict JSON or YAML. The top-level object must contain `version: 1`. Unknown fields, duplicate mapping keys, type coercion, non-finite numbers, invalid UTF-8, malformed dates, and invalid nested policy expressions fail before scanning. YAML aliases are bounded and resolved to the same data model as JSON; custom tags are rejected.

Scalar CLI values override configuration. Repeatable CLI include/exclude values append as specified by the [CLI section](#common-options) above. Security caps cannot be exceeded by configuration.

### Canonical symbols and assurance

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

### Top-level shape

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

`analysis.followModules` is a list of Go module import-path glob patterns (matched against a dependency's own module path, e.g. `github.com/myorg/**`) that registrar-following is explicitly permitted to cross into, beyond the target module's own source. It is empty by default: no module boundary is ever crossed unless named here. This is config-only, deliberately: there is no `--follow-modules` CLI flag, the same pattern `authMiddleware`/`authWrappers`/`policies` already use for settings that widen trust, so they come from a reviewed config file rather than a one-off command-line argument. It is rejected together with `analysis.profile: syntax-only`, which never resolves canonical symbols at all. A resolved cross-module route's `source.file` is represented as `<module path>@<version>/<path within the module>`, never an absolute filesystem path.

### Policies and baselines

Policy selectors may use methods, path globs, auth statuses, tags, roles, scopes, canonical package prefixes, and surface kinds. Requirements support auth, any/all/no middleware, middleware order, any/all/no tags, roles, scopes, and recursive `all`, `any`, and `not`. Recursion is limited by `maxCallDepth`. Duplicate policy or exception IDs are rejected.

Every exception requires an ID, non-empty reason, route selector, and strict `YYYY-MM-DD` expiry. Expiry is evaluated in UTC and included in deterministic evidence. `acceptedPublic` entries use uppercase method plus normalized Gin path and reject duplicates.

### OpenAPI schemes

Security schemes support valid OpenAPI 3.1 `http`, `apiKey`, `oauth2`, and `openIdConnect` shapes. Required fields are validated by type; OAuth URLs must be absolute HTTPS unless an explicit test-only mode is active. Middleware may reference only a declared scheme. No scheme is inferred from a middleware name or tag.

### Resource defaults and caps

Defaults are shown above. Hard caps are five minutes, 200,000 files, 20,000 packages, 20 MiB per file, 10,000 diagnostics, 100 MiB output, and call depth 128. Zero and negative values are invalid. Reaching a limit records a stable diagnostic and makes coverage incomplete; exceeding output capacity fails before emitting a truncated canonical JSON report.

## Report schema

### Versioning

Gin Recon reports begin at schema version `1.0`. The schema is owned and versioned independently from Express Recon, while framework-neutral concepts retain compatible meanings. Additive optional fields may be introduced in a minor schema revision; removals, renamed meanings, or changed required fields require a major revision.

### Report envelope

Every report contains:

- `schemaVersion`, `tool`, `toolVersion`, `classifierRulesetVersion`, `command`, and `analysisProfile`.
- `target` with module/workspace identity and sanitized single build context (`goos`, `goarch`, sorted tags, workspace mode, module mode, and profile).
- Deterministically ordered `routes`, `globalMiddleware`, and `fallbackSurfaces`.
- `scanCoverage` and bounded `diagnostics`.
- For audits: `summary`, `findings`, evaluated policy metadata, and active exceptions.
- When a baseline is supplied: `delta` with route, auth, and finding changes.

Inventory reports omit authentication judgment, policy results, summary, and findings.

### Route evidence

A route contains method, Gin path, normalized path, surface kind, middleware chain, final handler, source, path confidence, analysis confidence, build context, and evidence origins. Optional I/O evidence records request bindings, parameters, response variants, and resolved Go types.

A route optionally carries `swag`: best-effort evidence parsed from a swaggo/swag-style doc comment above its handler function (`@Summary`, `@Description`, `@Tags`, `@Router`, `@Deprecated`). See [OpenAPI documentation](openapi.md#swaggoswag-doc-comment-annotations) for the full parsing and precedence rules. It is present only when the handler's doc comment contains at least one recognized directive. It never affects route identity or auth classification; a disagreement between `@Router` and the route's own discovered method/path produces a `swag-router-mismatch` diagnostic rather than changing either.

Canonical route identity is the uppercase method plus normalized Gin path. `Any` and `Match` are expanded into concrete operations while retaining registration metadata. `NoRoute` and `NoMethod` are fallback surfaces and do not collide with normal route identities.

Middleware entries contain a display name, canonical package symbol when resolved, callable kind, source, registration scope (`global`, `group`, or `route`), ordering index, and resolution status. Raw argument values and arbitrary source text are excluded.

### Authentication

Audit routes use:

- `proven`: at least one canonical configured guard matched and satisfied its configured assurance mode without contradictory enforcement evidence.
- `public`: no configured guard matched and all relevant middleware evidence is resolved and non-opaque.
- `unknown`: middleware, control flow, route propagation, or analysis evidence is opaque or incomplete.

Each classification includes `classificationBasis`, `assurance`, `enforcementAnalysis` (`confirmed-shape`, `unresolved`, or `contradicted`), matched evidence, confidence, tags, roles, and scopes. Under `analyze`, confirmed shape is required. Under `attested`, unresolved shape is allowed. Contradicted evidence always yields `unknown`. `proven` remains a reviewer-backed assertion, not formal verification.

Because `attested` plus `unresolved` proves a route on configuration alone, without confirmed control-flow evidence, `summary` reports `provenByConfirmedShape` and `provenByAttestedUnresolved` as separate counts rather than a single `proven` total. This keeps analyzer-confirmed enforcement distinguishable from reviewer-trusted enforcement at a glance, without requiring a consumer to scan per-route evidence.

An accepted-public entry keeps the route `public`, sets `accepted: true`, suppresses its public-route finding, and produces a stale-baseline finding if it no longer matches a public route.

### Findings and policies

Built-in findings include `public-route`, `opaque-middleware`, `matched-but-unenforced`, `stale-auth-config`, `per-verb-gap`, `stale-baseline`, `incomplete-analysis`, `gin-explicit-trust-all-proxies`, and `gin-explicit-debug-mode`. Configured policies emit `policy-violation` findings. Engine findings never alter route authentication.

`stale-auth-config` fires once per configured `authMiddleware`/`authWrappers` canonical symbol that is never matched against any resolved call site in the scanned code, so a rename or removal in the target repository is visible as a distinct finding rather than surfacing only as routes silently becoming `unknown`. It is suppressed only when the profile is `syntax-only` and canonical resolution itself is unavailable, in which case the corresponding coverage diagnostic applies instead.

Every finding has `id`, `ruleId`, stable `fingerprint`, severity, confidence, route identity where applicable, source, detail, recommendation, and structured evidence. Fingerprints hash rule identity, normalized method/path, and stable discriminator fields; they exclude source line and absolute checkout path.

Policies may select method, path, status, tag, role, scope, package, or surface kind. Requirements support authentication, middleware presence/absence/order, tags, roles, scopes, and nested `all`/`any`/`not`. Exceptions require an ID, reason, route selector, and valid ISO expiry date.

### Coverage and diagnostics

Coverage records discovered/analyzed/failed packages and files, unresolved registrations, reached limits, exact build context, profile, and a boolean `complete`. `complete` means complete only for the recorded context and documented supported patterns; it never claims alternate operating systems, architectures, tags, or workspaces. A report may be operationally successful while incomplete, but `--fail-on incomplete` exits 2. Fatal inability to load the requested root or parse configuration exits 1.

Diagnostics use stable codes, severity, sanitized message, optional source, and affected route/package identity. They must be bounded and deterministically ordered.

### Baselines and exit codes

Delta output includes added/removed routes, authentication regressions/improvements, new/resolved findings, and structured explanations of middleware/evidence changes. Fingerprint comparison remains stable across source-line moves.

Baseline comparison requires the same schema major, analysis profile, normalized build context, and route-normalization version. A mismatch is an operational error rather than a misleading delta.

- Exit `0`: command completed and no requested gate matched.
- Exit `1`: invalid arguments/configuration, unreadable target, schema failure, or other operational error.
- Exit `2`: one or more requested security, policy, regression, or completeness gates matched.

### Output guarantees

JSON is the canonical representation. Pretty, Markdown, SARIF, OpenAPI, and MCP responses derive from the same immutable report or registry. Formatters must not mutate, reclassify, or silently discard evidence.
