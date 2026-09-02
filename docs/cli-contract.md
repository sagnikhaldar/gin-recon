# CLI Contract

## Commands and Exit Codes

The executable is `gin-recon <command> [options]`.

- `inventory`: emit route, middleware, source, coverage, and optional I/O evidence without security judgment.
- `audit`: classify inventory, evaluate policies, compare an optional baseline, and emit findings.
- `suggest-auth`: emit ranked canonical middleware candidates as JSON; suggestions never change classification.
- `schema`: emit either the report or configuration JSON Schema.
- `render`: re-run formatting only, over an already-produced report; never scans a source tree.

Exit `0` means successful with no requested gate, `1` means argument/configuration/operational failure, and `2` means an audit gate matched. Help and version requests exit `0`.

## Common Options

- `--src <dir>`: scan root; default is the current directory. Resolve once to an absolute real path.
- `--profile typed|syntax-only`: default `typed`.
- `--config <file>`: strict JSON/YAML configuration. Applicable to inventory, audit, and suggest-auth because scan and analysis settings may be shared.
- `--include <glob>` / `--exclude <glob>`: repeatable root-relative source scope additions.
- `--ignore-file <path|none>`: default `.gin-reconignore`; the path must remain under `--src`.
- `--include-tests`: include `_test.go` files and test packages; default false.
- `--goos <value>` / `--goarch <value>`: typed-profile build context; defaults to the running tool's values.
- `--tags <comma-list>`: build tags for the single report context; default empty.
- `--workspace off|<path>`: default `off`; an explicit path must resolve beneath `--src`.
- `--module-mode readonly|vendor`: default `vendor` when a valid root-contained vendor tree exists, otherwise `readonly`.
- `--allow-downloads`: typed mode only; default false. Without it, module and toolchain network access is disabled.
- `--timeout <duration>`: default 30 seconds, bounded by configuration limits.

One report represents exactly one GOOS/GOARCH/tag/workspace context. Multi-platform coverage is produced by running a CI matrix and retaining each report; `complete` never claims other build contexts.

## Output and Audit Options

- `--format pretty|json|md|openapi|sarif`: repeatable or comma-separated. Default `pretty`. `html` is not itself a selectable value (see below).
- `--out <dir>`: required when more than one format is selected. Files are `routes.json`, `routes.md`, `openapi.json`, `results.sarif`, and `routes.txt`. Requesting `openapi` with `--out` also always writes `api.html` alongside `openapi.json`, with no separate opt-in. Requesting `json` with `--out` also always writes `audit.html` alongside `routes.json`, with no separate opt-in.
- `--force`: permit replacement of those exact output files; default is to fail before writing if any target exists.
- `--baseline <report.json>`: audit only; the baseline must pass compatible-schema validation.
- `--fail-on <selectors>`: audit only, comma-separated/repeatable. Supported selectors are `public`, `unknown`, `attested-unresolved`, `policy`, `policy:<id>`, `new`, `regression`, and `incomplete`. `new` and `regression` require `--baseline`. `attested-unresolved` matches any route `proven` solely through `assurance: attested` with `enforcementAnalysis: unresolved`, for teams that want confirmed-shape-only enforcement in CI even though attestation remains available for configuration.

SARIF is audit-only. Inventory OpenAPI contains no authentication assertions. `api.html` renders the exact same document as its accompanying `openapi.json` — never independently, never as a standalone format a user can request without `openapi` or omit while keeping `openapi` — as a single self-contained, dependency-free browsable page (no CDN, no external network access at view time, consistent with this tool's offline-by-default posture); it is not written when `--out` is absent, since stdout carries only one file. `audit.html` is the same kind of fixed companion for `json`: it renders the exact same document as its accompanying `routes.json` — never independently, never as a standalone format, never written when `--out` is absent — as a single self-contained, dependency-free browsable page over the report itself (routes, auth classification, middleware chains, scan coverage, diagnostics, and, for `audit`, `Summary`/`Findings`). Both companion pages can be produced in the same run (`--format json,openapi --out <dir>` yields `routes.json`, `openapi.json`, `api.html`, and `audit.html`) since they read disjoint source documents. When `--out` is absent, exactly one format is written to stdout; warnings and diagnostics intended for humans go to stderr. Canonical JSON report content is never mixed with logs.

`schema --kind report|config` defaults to `report`, accepts no scan/config/output options, and writes JSON to stdout. `suggest-auth` writes JSON to stdout unless `--out` is supplied and does not accept baseline, fail-on, SARIF, or OpenAPI options.

## Render Options

`render` (docs/adr/0016-render-command-decouples-formatting-from-analysis.md) re-runs gin-recon's formatting layer over an already-produced report instead of scanning a source tree: it accepts no `--src` and none of the other scan/analysis options above, and never calls `internal/analyzer` or `go/packages`. `--report <path>` (required) is a `routes.json`-shaped file, loaded with the same load path `--baseline` uses; a missing, malformed, or schema-incompatible file fails with exit `1`. `--format`/`--out`/`--force` follow the identical rules documented above, including both companion files, except `sarif` is valid only when the loaded report's `command` is `audit` — checked against that document, not against `render` itself, once it is loaded. `--config` applies only to what the formatting layer itself reads (`openapi.title`/`openapi.securitySchemes`), not to any `analysis.*` setting, since no analysis runs.

## Precedence and Validation

Precedence is scalar CLI option, configuration value, then documented default. Repeatable CLI include/exclude patterns append after configured patterns so explicit CLI exclusions are applied last; ignore-file negation rules are evaluated before explicit excludes. Unknown commands/options, duplicate scalar options, missing values, invalid durations, path escapes, inapplicable options, and conflicting formats fail with exit `1` before analysis or output writes.

All paths are resolved relative to `--src` except `--src` itself. Reports store root-relative slash-separated paths, never absolute checkout paths.
