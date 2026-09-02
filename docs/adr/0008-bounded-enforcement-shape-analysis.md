# ADR 0008: Bounded Enforcement-Shape Analysis

## Status

Accepted.

## Context

`enforcementAnalysis` ([ADR 0005](0005-conservative-classification.md)) requires distinguishing `confirmed-shape` (the middleware provably terminates the Gin chain on a deny path) from `unresolved` (its control flow cannot be established) and `contradicted` (it provably never terminates the chain). Proving termination in general Go code is unbounded: the deny path may live behind a helper call, a `defer`/`recover`, a goroutine, a channel signal, or several packages of indirection. Without an explicit boundary, this analysis either degrades to "everything is unresolved" — making `assurance: analyze` useless on real codebases — or grows without limit chasing edge cases, which conflicts with the small-trusted-surface goal of [ADR 0002](0002-standard-library-cli.md) and [ADR 0003](0003-data-only-configuration.md).

## Decision

Version 1 recognizes `confirmed-shape` only for these resolvable forms, evaluated within the configured middleware's own function body or one level of same-package call delegation:

- A direct `if` branch that calls `c.Abort()`/`c.AbortWithStatus*`/`c.AbortWithError` and returns, with no further statements reachable after the call within that branch.
- The same shape reached through exactly one resolvable call to another function or method in the same package, itself taking `*gin.Context` and containing only the pattern above.

Every other shape — indirection beyond one same-package call, cross-package delegation, `defer`/`recover`-based termination, goroutines, channel or shared-state signaling, generic wrappers whose instantiation is not statically resolved, and any construct requiring points-to or escape analysis — always yields `unresolved`, never `confirmed-shape`, regardless of how confident a broader analysis might be. `contradicted` requires the same bounded resolution to prove the deny branch is absent or unreachable; anything not resolvable one way or the other is `unresolved`.

This boundary is fixed documentation, not an implementation detail: expanding it requires a new ADR, a fixture category proving both the new positive case and its negative/ambiguous counterparts, and a measured false-`confirmed-shape` review, matching the change-control bar already required for [Gin security rules](../gin-security-rules.md).

### Factory-closure resolution

Validating against a real production Gin codebase during development surfaced that the dominant real-world pattern for parameterized middleware is a factory function — `func RequireRole(role string) gin.HandlerFunc { return func(c *gin.Context) { ... } }` — which does not itself take `*gin.Context` at all. Without resolving through it, essentially no realistically parameterized middleware (role checks, JWT verification with a token-type argument, and equivalents) could ever reach `confirmed-shape` under `assurance: analyze`, regardless of how directly it enforces, which would have made that assurance mode close to useless on real codebases — precisely the failure this ADR's Context section already warns against.

Version 1 therefore extends `confirmed-shape` resolution to look through a factory function: when the configured symbol's own signature does not take `*gin.Context` but its result type is `gin.HandlerFunc`-compatible, and its body has exactly one resolvable `return` statement (not one belonging to a nested closure), that return is followed:

- If it returns a function literal directly, the literal's body is analyzed as the middleware's body under the existing rules above.
- If it returns a call to another function or method in the exact same package — the common two-layer idiom of an exported factory delegating to an unexported implementation — that one hop is followed and the same resolution repeats from there, bounded to exactly one such function-to-function hop (`maxFactoryHops = 1` in `internal/analyzer/gin/enforcement.go`) before giving up.

A factory with more than one return statement, a cross-package delegation, a delegation through anything other than a directly-named function/method, or a chain deeper than one hop all yield `unresolved`, matching this ADR's existing "anything not resolvable is unresolved" default. This is the same bounded, auditable philosophy as the plain middleware-delegation case, applied to one additional, extremely common layer of indirection — not a general interprocedural closure analysis.

## Consequences

Many real-world guards — especially those routed through a shared "require auth" helper package, or wrapping a third-party library — will report `unresolved` in v1 and require `assurance: attested` to reach `proven`. This is intentional: it keeps `confirmed-shape` auditable and keeps the analyzer's trusted logic small enough to review, at the cost of more manual attestation in brownfield projects. The boundary can be widened deliberately and incrementally in later versions without breaking existing classifications, since widening only ever moves routes from `unresolved` toward `confirmed-shape`, never the reverse.

## Rejected Alternatives

General interprocedural must-analysis (unbounded call depth, points-to-aware) was rejected for v1 as disproportionate implementation and audit cost for a single classification bit. Treating any allowlist-matched middleware as `confirmed-shape` by default was rejected because it collapses the distinction ADR 0005 introduced and reopens the false-`proven` risk that the assurance model exists to close.
