# ADR 0010: Opt-In Cross-Module Registrar Following

## Status

Accepted.

## Context

Registrar-following (`internal/analyzer/gin`'s `tryFollowRegistrarCall`) was, until this ADR, bounded strictly to the target module's own source: `buildFuncIndex` only indexes functions from `loaded.Packages` — the packages `packages.Load(cfg, "./...")` resolves for the scanned module itself, never its dependencies. That boundary is deliberate and stated directly in `buildFuncIndex`'s own doc comment: an earlier implementation walked the full `packages.Visit` dependency closure and was measured pulling in tens of thousands of unrelated stdlib/dependency functions on a real codebase, for no effect on results, since registrar-following could never legitimately reach any of them anyway.

Scanning real production services surfaced a shape that boundary does not handle well: a module (e.g. `las-be-flow`) constructs a real `*gin.Engine` and calls `someOtherModule.Init(routerGroup, ...)`, where `someOtherModule` is a **separate Go module** — same organization, imported the ordinary way via `go.mod`, but not the target's own source. `Init` genuinely registers real routes on the group it receives. Before this ADR, this produced `gin-unresolved-registrar` with a generic "external package or missing syntax" message and, from the *other* module's own perspective when scanned standalone, `gin-library-entry-point` (its `Init` is never called anywhere in its own source either) — two honest, correctly-diagnosed gaps, but a real reviewer had no way to see the actual routes without manually cross-referencing two separate scans by hand.

Investigation confirmed the dependency's full AST and type information is *already* loaded in memory: `Load`'s `packages.Config.Mode` includes `NeedDeps` alongside `NeedSyntax`/`NeedTypesInfo`, and per `go/packages`' own documented behavior, `NeedDeps` causes those needs to apply transitively to dependencies too. The data was there; only the deliberate scope boundary — not a technical limitation — was in the way.

Crossing a module boundary is a materially different decision from crossing a package boundary within one module, for reasons the original `buildFuncIndex` boundary already implicitly recognized:

- **Performance**: the full transitive dependency graph of a real service can be enormous; walking all of it (as the removed earlier implementation did) is wasted, unbounded work.
- **Scope of trust**: a dependency module's code was never reviewed as part of *this* module's own auditable surface. Even a same-organization internal module is a separate release, a separate repository, a separate set of reviewers.
- **Report path semantics**: `docs/cli-contract.md` requires "root-relative, slash-separated paths, never absolute checkout paths" for `source.file`. A file resolved inside a dependency lives in the Go module cache, not beneath `--src` — `filepath.Rel(root, ...)` against it produces a path that climbs *above* root with `../../..` segments, which would leak local module-cache directory structure (and, depending on the cache location, potentially the operating user's home directory) into the report. This needed an explicit design decision, not an accidental side effect of extending the existing relativization code untouched.

## Decision

Registrar-following (and `resolveEngineFactoryCall`'s wrapping-factory resolution) may cross a module boundary, but **only** into a dependency module whose own module path matches a glob pattern the reviewer explicitly lists in `analysis.followModules` (`internal/config`; see `docs/configuration-contract.md`). Empty by default — no module boundary is ever crossed unless named. This is config-only, with no CLI flag, matching the same pattern `authMiddleware`/`authWrappers`/`policies` already use for settings that widen what gin-recon trusts: a one-off command-line argument is not the right place to make a decision this consequential, a reviewed and versioned config file is.

Mechanically:

- `buildCrossModuleFuncIndex` (`internal/analyzer/crossmodule.go`) walks `packages.Visit`'s full transitive closure, but the glob filter is checked *before* a package's declarations are ever walked — a non-matching module's functions are never indexed, keeping the "tens of thousands of unrelated functions" cost bounded to however many modules a reviewer actually names, not the whole dependency graph.
- A resolved cross-module function is merged into the *same* function index `gin.Discover`'s registrar-following already uses — from `Discover`'s own perspective, a cross-module registrar function is indistinguishable from an in-module one; no changes to `internal/analyzer/gin` were needed to make this work.
- A route/middleware/diagnostic `Source` whose file falls outside `--src` is given a `"<module path>@<version>/<path within the module>"` label instead of a relativized (or worse, leaking) filesystem path — stable across machines, containing no local cache directory or username, and self-evidently external via the module-path prefix. The target module's own sources are completely unaffected: this label only ever applies to a file `buildCrossModuleFuncIndex` itself recorded as belonging to a matched external module.
- `analysis.followModules` is rejected together with `analysis.profile: syntax-only`, which never resolves canonical symbols or loads `go/packages` at all — the setting is meaningless there.

## Consequences

A reviewer who explicitly opts specific internal dependency modules in gets the same registrar-following recall across a module boundary that already existed within one module — no more manually cross-referencing two separate scans to reconstruct a route's real middleware chain. Classification behavior is unaffected: a canonical symbol resolved from a followed module is matched against `authMiddleware` exactly like any other, since the existing configuration format already allows a reviewer to name a symbol from any package, in or out of the target module — this ADR only changes *where discovery can look*, never what classification is willing to trust.

The cost is a config-only feature surface a reviewer must deliberately opt into, per module, per scan — a target with real cross-module routing that has not been configured this way will continue to see `gin-unresolved-registrar` (now naming the specific external symbol, a smaller, independent improvement made alongside this feature) rather than silently discovering less than expected.

## Rejected Alternatives

- **Follow every dependency automatically, no configuration.** Rejected: reintroduces the exact unbounded-cost and unreviewed-trust problems the original `buildFuncIndex` boundary existed to avoid, now for two axes (performance and trust) instead of one.
- **A CLI flag (`--follow-modules`) instead of config-only.** Rejected: this is a genuine trust-boundary widening, and every other setting of that character in gin-recon (`authMiddleware`, `authWrappers`, `policies`) is config-only for the same reason — a flag makes it one keystroke away from becoming muscle memory rather than a deliberate, reviewed decision.
- **Represent a cross-module source with its raw absolute path.** Rejected outright as a `docs/threat-model.md` violation: it would leak local module-cache layout (and potentially the operating user's home directory) into a report that may be shared outside the machine that produced it.
- **Omit the source location for cross-module routes entirely.** Rejected as a worse outcome than a label: dropping `source` for these routes would make them meaningfully less actionable than every other route in the same report, undermining the entire feature's purpose (letting a reviewer actually go look at the code).
