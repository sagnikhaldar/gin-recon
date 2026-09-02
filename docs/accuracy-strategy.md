# Accuracy Strategy

## Quality Objective

Gin Recon optimizes first for avoiding silent false negatives, then for actionable precision. Code coverage is useful but cannot substitute for measured route-discovery and classification accuracy.

## Maintained Corpus

Create isolated fixture modules covering:

- `gin.New`, `gin.Default`, aliases, engine fields, interfaces, and wrapping factory functions whose return statements agree (resolved) or disagree (left explicitly untracked) on which engine/group value comes back.
- Global, group, nested-group, and route middleware with registration-order changes.
- All verb helpers, `Handle`, `Any`, `Match`, static helpers, `NoRoute`, and `NoMethod`.
- Constants, concatenated paths, aliases, loops over literal route tables, and unresolved dynamic paths.
- Same-package and cross-package registrar functions, recursive registrars, methods, closures, generic helpers, and functions that receive `gin.IRouter`/`*gin.RouterGroup` as a parameter rather than a literal.
- Auth middleware under both assurance modes with confirmed, unresolved, and contradicted enforcement shapes, exercising every boundary case in the bounded enforcement-shape analysis this project deliberately limits itself to: a direct same-function abort (confirmed), a one-level same-package delegated abort (confirmed), a two-level delegated abort (unresolved, proving the boundary does not silently widen), a cross-package delegated abort (unresolved), a `defer`/`recover`-based abort (unresolved), a goroutine/channel-signaled abort (unresolved), and the factory-closure family: a zero-hop factory returning a literal directly (confirmed), a one-hop same-package factory delegation matching the real-world exported-factory/unexported-implementation idiom (confirmed), a two-hop factory delegation (unresolved), and a cross-package factory delegation (unresolved). Include third-party bodies unavailable to analysis.
- Go modules, workspaces, replacements, build tags, GOOS/GOARCH variants, vendoring, generated files, and ill-typed packages.
- Named, anonymous, factory-produced, conditional, duplicated, and reordered middleware.
- Every binding/rendering API claimed by the OpenAPI strategy, media types, validation tags, embedded/recursive structs, aliases, enums, streams/files/SSE, custom renderers, and conflicting response branches.
- Malicious paths, symlinks, oversized files, deep syntax, malformed config/baselines, and report-injection strings.

Every fixture has a reviewed manifest describing expected routes, middleware order, confidence, diagnostics, I/O evidence, auth classification, and findings.

## Test Layers

- Unit tests for normalization, path joining, type identity, middleware propagation, fingerprints, policies, and formatters.
- Golden tests for complete JSON, Markdown, SARIF, and OpenAPI artifacts.
- Integration tests running the CLI against fixture modules and asserting exit codes and stdout/stderr separation.
- Differential tests comparing static route method/path results with `Engine.Routes()` for controlled fixtures. Runtime output is an oracle for route presence only, not middleware security.
- Native fuzz tests for paths, configuration, policy expressions, baselines, report parsing, and OpenAPI conversion.
- Metamorphic tests proving that renaming local variables or moving source lines does not change route identity or fingerprints.
- Classifier version-diff tests that run the current and immediately prior release binaries against the frozen corpus and assert identical `proven`/`public`/`unknown`/`enforcementAnalysis` results per route, unless the change is a documented, reviewed widening of the enforcement-shape boundary.
- Race, deterministic-repeat, bounded-resource, and secret-redaction tests.

## Metrics and Release Gates

Freeze each release corpus manifest before measuring a candidate. Adding, removing, or reclassifying a supported pattern requires review and cannot be used to make a failing candidate pass.

Measure separately:

- Route recall: expected route identities discovered; production requires 100% for frozen supported patterns.
- Route precision: emitted route identities that exist; production requires at least 98%.
- Middleware-chain exactness: routes whose ordered canonical chain matches the manifest; production requires at least 98%.
- Authentication safety: false-`proven` count; production and beta require exactly zero. Also report per-status precision/recall without using aggregate accuracy as a release substitute.
- OpenAPI accuracy: resolved parameter/body/response fields and types that match manifests, reported separately by evidence kind; no unresolved placeholder counts as correct inference.

- Every unsupported/dynamic construct produces a diagnostic or affected-route uncertainty.
- No regression in supported-pattern route recall or false-`proven` count.
- Stable output across repeated runs with identical build context.
- No credentials, environment values, middleware arguments, or absolute checkout paths in reports.
- Schema, SARIF, and OpenAPI validation must pass.

Track false positives and false negatives by fixture category and build context rather than only aggregate totals. A new supported construct requires at least one positive, one negative, and one ambiguity fixture.

## Compatibility Matrix

Test the maintained Gin versions 1.9 through 1.12 and Go 1.25/1.26. Static symbol recognition should tolerate compatible Gin releases without depending on private structure. New Gin APIs enter support only after fixtures and documentation are added.

The full matrix (every Gin/Go/profile/workspace/module-mode combination against the complete frozen corpus) is expensive to run on every change and is reserved for nightly runs and release-candidate tags. Per-commit CI runs one representative combination (latest maintained Gin, latest Go, `typed` profile, `readonly` module mode) against the full corpus plus a `syntax-only` smoke pass on a reduced fixture subset. A per-commit failure on the representative combination blocks merge; a nightly/release-candidate failure on a non-default combination blocks the release but not ordinary commits, and must be triaged before the next release candidate is cut.
