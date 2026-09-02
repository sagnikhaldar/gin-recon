# ADR 0011: Multi-App Detection, Stable Service IDs, and Existing-OpenAPI-Document Reconciliation

## Status

Proposed. Not yet implemented — this ADR scopes three related feature requests as a deliberate roadmap decision, not a bug backlog.

## Context

A review comparing gin-recon's discovery model against a checklist written for a different tool's domain (Express-application discovery) surfaced three capabilities gin-recon does not have:

1. **Multi-app-per-repo detection** — grouping routes by which distinct `*gin.Engine`/binary they belong to, when a single scanned module constructs more than one.
2. **Stable service/application IDs** — a durable identifier for "this service," independent of route-level fingerprints (`internal/model/model.go`'s `Route` has no such field; `docs/report-contract.md` defines none).
3. **Existing-OpenAPI-document reconciliation** — detecting and consulting a pre-existing `openapi.yaml`/`swagger.json` already checked into the target repo, rather than only ever producing gin-recon's own from-scratch document.

None of these are gaps in an existing capability. gin-recon's whole analysis pipeline — `packages.Load(cfg, "./...")` in `internal/analyzer/loader.go`, `buildFuncIndex`/`buildCrossModuleFuncIndex`, `ScanCoverage` (`model.go:315`) — is built around one governing assumption: **one `--src` module scan produces one inventory.** That assumption has held across the real repos this tool has been run against in this session (`/home/sagnik/Tools/Gin based repo/*`): every one of the 39 repos is a single Gin service in its own module, with a single `main.go` wiring a single router. Building for multi-app-per-repo, service identity, and spec reconciliation now, speculatively, would be scope creep against zero observed need.

That said, the underlying capability gap is real if the assumption ever stops holding (a monorepo with two Gin binaries, or a repo that already ships a hand-maintained OpenAPI doc gin-recon should defer to instead of silently duplicating). This ADR scopes what each feature would actually require, so a future implementer starts from a considered design instead of guessing at one under time pressure the day a real repo breaks the single-app assumption.

## Decision

Treat these as three **independent, separately triggerable** features, not one bundled effort — they have different triggers, different risk profiles, and no shared implementation core beyond "runs during `Load`/`Inventory`."

### 1. Multi-app-per-repo detection

**Trigger for building this:** a real repo in the fleet is found to construct more than one independent `*gin.Engine` that each starts its own HTTP server (as opposed to, e.g., a health-check engine and a main engine, or a test-only engine in `_test.go` files, both of which should NOT count as "another app").

**Design sketch:** `internal/analyzer/gin/discover.go` already tracks every `gin.New()`/`gin.Default()` construction site to resolve which values are real engines (lines 570-601 per the earlier review). The missing step is: cluster those construction sites by which one is reachable from a distinct `func main()` (via `(*Engine).Run`/`http.ListenAndServe(engine, ...)` in that same `main`'s call graph), and tag each `Route` in the report with which cluster it came from — a new `model.Route.AppRoot` (or similar) field, `Source`-shaped (file/line of the `main.go` that owns it), following the same "stable, root-relative, no leaked absolute paths" discipline ADR 0010 established for cross-module sources.

**Why this is genuinely new work, not a bug fix:** it requires a call-graph question ("is this engine reachable from this main?") gin-recon's registrar-following never had to answer before — today it only asks "is this a real engine," never "which entry point owns it."

### 2. Stable service IDs

**Trigger for building this:** a consumer needs to correlate gin-recon reports for the *same service* across runs/repos/renames — e.g. a fleet-wide dashboard keying rows by service rather than by `--src` path (which changes if the repo is renamed, moved, or cloned to a different local directory, as several repos in this fleet were mid-session).

**Design sketch:** the natural, already-available stable identifier is the Go module path read by `syntaxload.go:198`'s `readModulePath` (e.g. `github.com/smallcase/las-be-flow`) — it survives directory renames and is already used as the trust boundary for `analysis.followModules` (ADR 0010). The decision here is narrow: promote that existing internal value to a top-level, schema-documented report field (alongside `BuildContext`), rather than leaving it as an implementation detail only used for module-boundary matching. No new discovery logic is needed — this is a schema/report-contract change, not an analyzer change.

**Explicitly rejected as the identifier:** a synthetic hash or UUID minted per-scan. That would be *unstable* by construction (a new ID every run defeats the entire purpose) and would duplicate information the module path already provides for free.

### 3. Existing-OpenAPI-document reconciliation

**Trigger for building this:** a repo in the fleet is found to already maintain a hand-written or swaggo-generated OpenAPI document that gin-recon's own output should either defer to, diff against, or explicitly flag as shadowing.

**Design sketch — and why this is the highest-risk of the three:** this is not a discovery feature so much as a new *trust and precedence* decision, in the same family as ADR 0007 ("OpenAPI Evidence Precedence"). ADR 0007 already establishes the principle that when multiple evidence sources disagree, gin-recon's precedence rules must be explicit, documented, and conservative rather than silently picking a winner. A pre-existing hand-written spec is exactly this kind of second evidence source, at the *document* level rather than the per-route level ADR 0007 addresses. Before writing any file-glob-scanning code, this needs its own ADR answering: does gin-recon merge, diff-and-report, or simply refuse to overwrite silently? Any of those is defensible; picking one without deliberation is not, per `docs/threat-model.md`'s standing bar against silent, undocumented precedence.

**Interim, lower-risk step available today, without new discovery code:** the `openapi-doc` skill's enrichment workflow (used earlier in this session across ~20 repos) already treats gin-recon's generated skeleton as a *starting point* a human or AI enriches — a repo with a pre-existing hand-written spec could have that spec's content manually folded in as enrichment input the same way real Go source was. This covers the common case (a handful of repos, reconciled deliberately, once) without committing to automatic detection logic that would need its own precedence ADR to be trustworthy.

## Consequences

No code changes ship from this ADR alone. What changes is that the next time one of these three needs becomes real (a genuine multi-engine repo, a cross-run correlation requirement, or a repo with a pre-existing spec), the implementer has: a stated trigger condition to check before building anything, a design sketch grounded in the actual existing code paths it would extend, and — for reconciliation specifically — an explicit flag that it needs its own precedence ADR before implementation, not just a feature branch.

The cost of not building these now is that the fleet-wide reports produced this session (all 39 repos under `Gin based repo/`) do not carry a stable service ID field, do not distinguish multi-app repos (none currently exist in the fleet, so this is not an active gap), and do not reconcile against any pre-existing specs (none of the 39 repos were found to have one during this session's work).

## Rejected Alternatives

- **Build all three now, speculatively.** Rejected: none has a real trigger in the current 39-repo fleet (confirmed single-engine, single-`main`, no pre-existing OpenAPI docs found during this session's audit). Building ahead of need risks the same "tens of thousands of unrelated functions for no effect on results" outcome ADR 0010 explicitly measured and rejected for an analogous speculative-generality mistake.
- **Mint a synthetic per-scan service ID instead of reusing the module path.** Rejected under item 2 above — defeats the stability requirement that is the entire point of the feature.
- **Fold OpenAPI-document reconciliation into this ADR's Decision as a concrete design instead of deferring it.** Rejected: it is a precedence decision (ADR-0007-shaped), not a discovery decision, and deserves its own dedicated ADR with its own considered rejected-alternatives section once a real repo forces the question — bundling it here would produce exactly the "picked a winner without deliberation" outcome the interim section warns against.
