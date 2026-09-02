# Gin Recon Architecture and Delivery Plan

## Purpose

Gin Recon will inventory and audit Gin route surfaces for humans, CI, and AI agents. It will preserve the useful product contracts of Express Recon while using Go-aware analysis rather than porting JavaScript implementation techniques. Version 1 is static-first: it must not execute the target application.

The primary security invariant is conservative evidence handling. A route is never considered authenticated merely because analysis is incomplete, a middleware name looks security-related, or runtime metadata omits its middleware chain.

Supporting decisions are recorded in the [ADRs](docs/adr/) — including the [bounded enforcement-shape boundary](docs/adr/0008-bounded-enforcement-shape-analysis.md) that scopes exactly which control-flow shapes can reach `confirmed-shape`, [why `api.html` is a self-contained viewer rather than a CDN-loaded Redoc/Swagger UI embed](docs/adr/0009-self-contained-html-viewer.md), and [why registrar-following may cross a module boundary only into an explicitly opted-in dependency](docs/adr/0010-opt-in-cross-module-registrar-following.md) — with detailed requirements in the [parity matrix](docs/express-parity-matrix.md), [CLI contract](docs/cli-contract.md), [configuration contract](docs/configuration-contract.md), [threat model](docs/threat-model.md), [report contract](docs/report-contract.md), [OpenAPI strategy](docs/openapi-strategy.md), [accuracy strategy](docs/accuracy-strategy.md), [Gin security rules](docs/gin-security-rules.md), [auth catalog governance](docs/auth-catalog.md), and [MCP security contract](docs/mcp-security.md).

## Product Scope

Version 1 will provide:

- `inventory`, `audit`, `suggest-auth`, and `schema` commands.
- A maintained, versioned reference catalog of known Gin auth-adjacent middleware symbols, governed by reviewed evidence and used only to rank `suggest-auth` output—never to classify a route.
- Static discovery of Gin engines, groups, routes, middleware, handlers, and source locations.
- Authentication classification, accepted-public baselines, route policies, stable findings, and report comparison.
- Pretty, JSON, Markdown, OpenAPI 3.1 (always paired with a self-contained HTML viewer over the same document), and SARIF output.
- Deterministic CI gates for public, unknown, policy, new, regression, and incomplete results.
- A static-only MCP server after the core report contract stabilizes.

Runtime and hybrid evidence are post-v1. They must use an explicit, target-provided probe protocol and remain opt-in for trusted code. Access to Gin internals through `unsafe` or `go:linkname` is prohibited.

## Technical Architecture

Use Go 1.25 as the minimum supported version and test on Go 1.25 and 1.26. Keep the trusted dependency surface small:

- Standard-library subcommand and flag parsing for the CLI.
- `golang.org/x/tools/go/packages` for typed package loading.
- `go/ast`, `go/types`, `go/constant`, and bounded SSA analysis for semantics.
- Strict JSON and YAML configuration using `encoding/json` and `go.yaml.in/yaml/v3`; never load executable Go configuration.
- Standard `testing`, golden tests, fuzzing, `go vet`, the race detector, pinned Staticcheck, and pinned `govulncheck`.
- The official Go MCP SDK when MCP work begins.

Organize implementation by responsibility:

```text
cmd/gin-recon/          CLI entry point
cmd/gin-recon-mcp/      static-only MCP entry point
internal/analyzer/      package loading and orchestration
internal/analyzer/gin/  Gin route and middleware semantics
internal/analyzer/io/   request and response evidence
internal/model/         normalized registry and findings
internal/classify/      authentication classification
internal/policy/        deterministic policy evaluation
internal/compare/       baseline and regression comparison
internal/report/        schema and report construction
internal/format/        output formats
internal/config/        strict configuration
schema/                 versioned JSON Schema
testdata/               fixture Go modules
examples/               CI and policy examples
```

The data flow is:

```text
source/packages → typed Gin model → route registry → classification
                → policies/findings → versioned report → formatters/MCP/CI
```

## Analyzer Design

Recognize Gin APIs through type and package identity, not local variable names. Support `gin.New`, `gin.Default`, `Use`, `Group`, standard verb helpers, `Handle`, `Any`, `Match`, static-file helpers, and `NoRoute`/`NoMethod`. Preserve global, group, and per-route middleware in execution order; middleware registered after a route must not be attributed retroactively.

Resolve constants, concatenated paths, aliases, embedded groups, and bounded registrar functions receiving `*gin.Engine`, `*gin.RouterGroup`, `gin.IRouter`, or compatible interfaces, including generic helpers and functions that receive the router as a parameter rather than a literal. Also resolve a wrapping factory function that constructs and returns an engine/group value (`func NewEngine() *gin.Engine { r := gin.New(); ...; return r }`) whenever every one of its return statements agrees on which tracked value comes back, including any middleware or routes it applied before returning; a factory whose returns disagree on that point is left explicitly untracked rather than guessed at. Add SSA only for interprocedural cases that cannot be represented accurately with typed AST summaries. Dynamic route tables, unresolved calls, ill-typed packages, and unsupported control flow must produce coverage diagnostics rather than silent omissions.

Registrar-function following deliberately uses a different bounding philosophy than [ADR 0008](docs/adr/0008-bounded-enforcement-shape-analysis.md)'s same-function-only rule for enforcement-shape analysis. The two analyses carry opposite risk profiles: a false `confirmed-shape` is ADR 0008's worst failure, so it stays narrow and same-package only; a hidden route is this project's single most damaging failure per the [threat model](docs/threat-model.md), so registrar-following instead favors recall — it crosses package boundaries and follows named functions, methods, method values, and function literals (an inline immediately-invoked function expression, or a same-function local variable bound to one) wherever their source is available, bounded only by a fixed call-depth limit and cycle detection, not by a package boundary. It stops, with a diagnostic rather than a silent gap, only where static resolution genuinely runs out: a callee reached through a function-typed parameter or a variable not bound to a literal it can see in full, an external package with no available source, a depth or cycle limit, or a call whose passed argument cannot be matched to a callee parameter.

### Middleware Assurance Semantics

Authentication classification combines two independent facts: a reviewer-configured canonical-symbol match and optional enforcement-shape analysis. Control-flow heuristics never discover authentication on their own.

- `enforcementAnalysis: confirmed-shape` means a resolved middleware contains a recognizable deny path that terminates the Gin chain. It supports—but does not prove—the reviewer's assertion.
- `enforcementAnalysis: unresolved` means the body, factory result, or deny control flow cannot be established.
- `enforcementAnalysis: contradicted` means the analyzer can establish that the configured middleware always continues without terminating the chain. This always yields `unknown` and a `matched-but-unenforced` finding.
- Configuration defaults to `assurance: analyze`: `proven` requires a canonical match plus `confirmed-shape`. Reviewed third-party or delegated guards may use `assurance: attested`: a canonical match is `proven` when analysis is `confirmed-shape` or `unresolved`, but never when contradicted.
- `confirmed-shape` is recognized only for the bounded set of control-flow patterns fixed by [ADR 0008](docs/adr/0008-bounded-enforcement-shape-analysis.md); everything outside that boundary is `unresolved` by design, not by current limitation. Because `attested`+`unresolved` proves a route without confirmed control-flow evidence, the report summary counts `provenByConfirmedShape` and `provenByAttestedUnresolved` separately, and `--fail-on attested-unresolved` lets a stricter CI posture reject attestation-only proof.
- A configured `authMiddleware`/`authWrappers` symbol that never matches any resolved call site produces a `stale-auth-config` finding, so a target-side rename or removal is visible as its own signal rather than only appearing as routes quietly becoming `unknown`.

Provide two analysis profiles:

- `syntax-only`: hermetic parsing without invoking the Go toolchain. It inventories direct Gin-shaped registrations but cannot provide canonical symbol identity, `proven` classification, inter-package registrar resolution, or typed OpenAPI schemas; affected evidence is explicitly unresolved.
- `typed` (default): package-aware analysis with a sanitized environment, external package drivers disabled, CGO and toolchain auto-download disabled, offline dependency resolution by default, and one recorded build context per report.

## Security and Reporting

Reports use a Gin Recon schema starting at `1.0` while keeping common Express Recon concepts stable. Authentication states are `proven`, `public`, and `unknown`; `proven` is a reviewer-backed assertion under the configured assurance mode, not formal verification. Every route carries classification basis, enforcement analysis, confidence, source, middleware identity, build context, and applicable coverage diagnostics. Every report also carries a `classifierRulesetVersion` alongside `toolVersion`, so a classification change traceable to an analyzer upgrade (rather than a source change) is diagnosable from the report alone; the classifier version-diff tests in the [accuracy strategy](docs/accuracy-strategy.md) gate on this staying stable across releases unless a widening is explicitly reviewed under ADR 0008.

Canonical middleware configuration uses fully qualified package symbols. Arguments and values that may contain secrets must not be copied into reports. Exit codes are `0` for a successful non-gated result, `1` for operational/configuration failure, and `2` for an explicitly triggered security or policy gate.

## Delivery Phases

1. **Contracts and threat model:** implement the saved CLI/configuration schemas, report types, fixtures, trust profiles, limits, exit codes, and supported-pattern definitions without changing their public semantics.
2. **Foundation:** initialize the module, models, configuration, CLI shells, deterministic JSON, diagnostics, and schema validation.
3. **Static discovery:** implement typed loading, engine/group propagation, route registration, middleware order, registrar summaries, and completeness reporting.
4. **Security analysis:** add configured assurance, independent middleware enforcement-shape analysis, accepted-public baselines, findings, policies, exceptions, fingerprints, comparison, Gin engine rules, and the initial reviewed auth catalog for `suggest-auth`.
5. **Outputs and CI:** implement pretty, Markdown, OpenAPI 3.1, SARIF, PR annotations, and example workflows.
6. **Hardening:** execute the accuracy corpus, classifier version-diff tests, fuzzing, race tests, redaction tests, adversarial modules, and supply-chain review. The full Gin/Go/profile/mode compatibility matrix runs nightly and on release candidates; per-commit CI runs one representative combination plus a syntax-only smoke pass, per the [accuracy strategy](docs/accuracy-strategy.md).
7. **Agent integration:** add bounded, paginated, static-only MCP tools after report stability.
8. **Post-v1 investigation:** design an explicit runtime probe without weakening static guarantees.

## Versioning

Gin Recon follows semantic versioning (`MAJOR.MINOR.PATCH`) end to end: release tags, the report JSON Schema, the configuration JSON Schema, and the CLI/MCP contract all move together under the same discipline.

- **MAJOR**: a breaking change to the report schema (removal, renamed meaning, or changed required field per [report-contract.md](docs/report-contract.md)), a breaking CLI/MCP contract change, a breaking configuration schema change, or a classification-semantics change that alters existing routes' `proven`/`public`/`unknown` results on unchanged source — including a widening of the [ADR 0008](docs/adr/0008-bounded-enforcement-shape-analysis.md) enforcement-shape boundary.
- **MINOR**: additive, backward-compatible capability — new optional report fields, new finding types, new CLI flags with safe defaults, new supported Gin/Go API patterns that only add coverage without reclassifying existing routes.
- **PATCH**: bug fixes, performance work, and other changes with no observable effect on report shape or classification results.

The classifier version-diff tests in the [accuracy strategy](docs/accuracy-strategy.md) are the enforcement mechanism: an unreviewed classification change on the frozen corpus fails CI, which is what makes the MAJOR/MINOR/PATCH boundary verifiable rather than a matter of judgment at release time. `classifierRulesetVersion` in the report envelope lets a consumer confirm which classification behavior produced a given report independent of `toolVersion`.

## Release Criteria

Release criteria are staged so the project can ship and gather real-world feedback before every hardening bar is met.

**Alpha (phases 1-5 complete):** deterministic output, no silent route loss, at least 90% route recall and route precision across the maintained corpus, diagnostics for unsupported cases, and schema validation tests. Publish source tags only; do not distribute binaries before signing and provenance are operational. Alpha is not for CI gating in untrusted environments.

**Beta (phase 6 substantially complete):** at least 98% route recall, 95% route precision, zero false-`proven` classifications in the frozen release corpus, passing fuzzing/race/redaction/adversarial suites without known criticals, and stable output across repeated runs. Any distributed binaries are signed and accompanied by checksums and provenance. Suitable for CI gating in trusted repositories.

**First production release:** deterministic output; no silent route loss; 100% route recall for the frozen supported-pattern corpus; at least 98% route precision and middleware-chain exactness; zero false-`proven` classifications; separately measured OpenAPI field/type accuracy; diagnostics for unsupported cases; schema compatibility and redaction guarantees; and reproducible signed releases with checksums, SBOMs, and provenance.

Recall/precision must be tracked and reported per fixture category (not only in aggregate) at every stage so a regression in one supported pattern cannot hide behind gains elsewhere.
