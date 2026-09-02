# ADR 0012: Swag Annotation Prose as Supplementary OpenAPI Evidence

## Status

Accepted.

## Context

ADR 0011 surveyed capability gaps against an Express-tooling checklist and deliberately deferred three features as independently triggerable. Its third item — existing-OpenAPI-document reconciliation — was flagged explicitly as "an evidence-precedence question in the same family as ADR 0007... not a discovery decision," needing its own ADR before implementation.

A narrower, lower-risk version of that same question has a real, immediate trigger: swaggo/swag (`https://github.com/swaggo/swag`) doc-comment annotations directly above a Gin handler function (`@Summary`, `@Description`, `@Tags`, `@Router`, `@Deprecated`, and more) are the de facto standard a large fraction of real Gin codebases already use to hand-author OpenAPI prose, the same role swagger-jsdoc annotations play for Express. Unlike ADR 0011 item 3's "a whole pre-existing `openapi.yaml` file to reconcile against," this is:

- **Scoped to one function at a time** — no document-level merge/diff/reconcile decision, since there is no second whole document, only per-handler prose fragments.
- **Already anchored to the exact evidence gin-recon's own formatter has genuinely never had**: `internal/format/openapi.go`'s own doc comment states plainly that every operation's `summary` was previously "set from data this formatter already carries" (method/path/handler), a generic derived string, never real human-authored prose — there is no existing gin-recon-derived value this could silently clobber for these four fields specifically.
- **Structurally bounded** — swaggo's `@Param`/`@Success`/`@Failure` directives require a type-schema-and-model-registry subsystem (resolving `{object} dtos.User`-style references against Go types) this ADR explicitly does not build; only the five prose/cross-check directives named below are in scope.

This is still, per ADR 0011's own framing, an evidence-precedence question: a swag comment is a second evidence source (developer-authored prose) that can agree or disagree with gin-recon's own statically-discovered route identity, and ADR 0007 already establishes the house rule for exactly this situation — analyzer evidence is authoritative, documentation may enrich prose, and a conflict must produce a diagnostic rather than being silently resolved either way.

## Decision

Parse only five swag directives from a handler function's Go doc comment (`*ast.CommentGroup`), via `internal/analyzer/gin.ParseSwagAnnotations`:

- `@Summary <text>` — single line.
- `@Description <text>` — may repeat across consecutive lines, concatenated with a space, matching swaggo's own convention.
- `@Tags <comma,separated,tags>`.
- `@Router <path> [<HTTP_METHOD>]` — parsed for cross-checking only, never for setting a route's actual path/method.
- `@Deprecated` — a bare marker line.

A doc comment with no recognized directive (the overwhelming majority of ordinary Go doc comments) yields `nil`, not an empty, meaningless annotation object — `model.Route.Swag` stays absent exactly when there is genuinely nothing to report, keeping this purely additive to `docs/report-contract.md`'s existing route shape.

**Precedence, following ADR 0007 exactly:**

- **Route identity is never touched.** `GinPath`, `Method`, `FinalHandler`, `Middleware`, `Source`, and auth classification remain entirely the product of gin-recon's own static discovery, unconditionally. `@Router`'s parsed path/method is carried on `SwagInfo.RouterPath`/`RouterMethod` purely as evidence of what the annotation claims — it is compared against the discovered route, never assigned to it.
- **Summary/Description/Tags/Deprecated are the one place swag prose wins outright when present**, in `internal/format/openapi.go`'s `applySwagEvidence`. This is a narrower rule than ADR 0007's general "documentation may enrich prose... schema may refine... conflict retains code-derived value" ladder specifically because these four fields have no analyzer-derived alternative worth preserving in the first place: the previous "summary" was a mechanically generated string with zero authorial intent (`"GET /users/{id} -> GetUser"`), not evidence a human reviewed and might be overridden. There is nothing to conflict with, so there is nothing to arbitrate — the annotation simply replaces the generic placeholder.
- **A disagreeing `@Router` is a diagnostic, never a silent override and never a hard error.** `internal/analyzer/gin.ApplySwagFromDoc` compares the annotation's path (converted from Gin's `:name`/`*name` syntax to swaggo's own `{name}` form before comparing, so a parameterized route is not a guaranteed false mismatch) and method against the route's own discovered `GinPath`/`Method`. A disagreement on either produces a `swag-router-mismatch` diagnostic at `warning` severity — deliberately below the `error` diagnostics analyzer-load failures use, since a stale doc comment is a documentation-hygiene issue, not a defect in the scanned application's actual behavior. It is not added to `coverageAffectingCodes`/`syntaxCoverageAffectingCodes`, so it never marks `ScanCoverage.Complete` false — the analyzer discovered the route completely; the annotation is merely out of date.
- **A mismatch never suppresses the rest of the same comment's evidence.** `ApplySwagFromDoc` always attaches `Swag` first and only then evaluates the mismatch — a handler whose `@Router` line rotted after a path was renamed still has a perfectly good `@Summary`/`@Description`/`@Tags` worth keeping.

**Population point:** during discovery, once a route's handler resolves. The typed profile (`internal/analyzer/inventory.go`'s `applySwagAnnotations`) resolves a route's `FinalHandler.CanonicalSymbol` back to the `*ast.FuncDecl` via the same whole-module `funcIndex` `gin.Discover`'s own registrar-following already relies on, and reads its `Doc`. The syntax-only profile (`internal/analyzer/gin/discover_syntax.go`) has no such cross-function symbol index by design (ADR/doc comment: "cannot provide canonical cross-package symbol identity"), so it applies a narrower, same-file-only match: a handler referenced by a bare identifier that happens to be declared in the very same file. A handler in another file, another package, or referenced through a selector/method value is not resolved in this profile — an accepted gap consistent with syntax-only's existing "reduced recall, hermetic parsing only" trade, not a new one this feature introduces.

**Schema change:** `model.Route` gains an optional `Swag *SwagInfo` field (`schema/report-1.0.json`'s `route` definition gains an optional `swag` property referencing a new `swag` `$def`). Per `docs/report-contract.md`'s "Additive optional fields may be introduced in a minor schema revision" and `internal/report.SchemaVersion`'s own doc comment ("Bumping it is a MAJOR change... unless the change is purely additive, in which case only ToolVersion/ClassifierRulesetVersion move"), this does not require a `schemaVersion` bump: `SchemaVersion` stays `"1.0"`. Every existing consumer of `routes.json` continues to work unchanged against a route with no `swag` key at all.

## Consequences

A handler already carrying swaggo-style doc comments — extremely common in real Gin codebases already targeting swag-generated documentation — gets a materially more useful `summary`/`description`/`tags`/`deprecated` in gin-recon's own OpenAPI output than the previous mechanically-generated placeholder, with zero authoring effort beyond what the codebase already has. A codebase with no such comments (the common case for teams that have never adopted swag) sees zero behavior change: `Route.Swag` is nil, `applySwagEvidence` is a no-op, and every existing test/consumer is unaffected — confirmed by the full existing test suite passing unmodified.

The cost is a second, independent evidence source a reviewer must reconcile when it goes stale: a renamed route whose `@Router` comment was not updated now surfaces as an explicit `swag-router-mismatch` diagnostic rather than either silently misleading a consumer of the generated document or silently vanishing. This is the intended cost, not an oversight — it is exactly ADR 0007's "conflicts... produce structured diagnostics" principle applied to a new evidence source.

This ADR does not touch `internal/classify` or any auth-related pipeline in any way, and does not implement `@Param`/`@Success`/`@Failure` or any existing-whole-OpenAPI-document reconciliation — ADR 0011 item 3 remains open, deliberately, for exactly the reasons stated there.

## Rejected Alternatives

- **Trust `@Router` to set the route's actual path/method.** Rejected outright: ADR 0007's central rule is that analyzer evidence is authoritative for path/method/handler, precisely because a hand-written annotation can silently rot as code changes — the exact failure mode ADR 0007's "Rejected Alternatives" names ("trusting annotations over code... conceal uncertainty").
- **Silently drop a mismatched `@Router` line with no diagnostic.** Rejected: indistinguishable from "gin-recon didn't notice," which is worse than a visible, low-severity note a reviewer can act on or ignore.
- **Treat a `@Router` mismatch as an error-severity finding or a hard failure.** Rejected: a stale doc comment says nothing about the scanned application's actual security or runtime behavior — conflating documentation hygiene with a security-relevant finding would misrepresent its severity to anyone triaging a report, and risks `--fail-on` gates treating a cosmetic issue as build-breaking.
- **Implement the full swaggo `@Param`/`@Success`/`@Failure` type-schema system.** Rejected as its own, much larger subsystem: it requires a Go-type-to-OpenAPI-schema model registry that duplicates work `docs/openapi-strategy.md`'s own request/response inference roadmap already owns, and mixing the two would blur which evidence (analyzer-inferred vs. annotation-declared) produced a given schema — exactly the kind of untraceable precedence ADR 0007 exists to prevent.
- **Fold this into ADR 0011 item 3 as part of a general "existing documentation" reconciliation feature.** Rejected: ADR 0011 explicitly scoped item 3 to a whole pre-existing OpenAPI *document*, a document-level merge/diff/shadow decision with real design risk of its own; per-handler swag comments are a fundamentally smaller, function-scoped evidence source with no document to reconcile against, and conflating the two would have delayed this lower-risk, already-common-in-the-fleet case behind a decision it does not actually depend on.
