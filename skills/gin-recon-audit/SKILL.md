---
name: gin-recon-audit
description: >-
  Audit or inventory a Gin (gin-gonic) codebase's HTTP routes and middleware,
  for one repository or many at once. Use when asked to find
  unauthenticated/open endpoints, list all routes and their auth/middleware,
  check which routes lack an auth guard, produce a route inventory for a Gin
  service, or audit multiple repositories/a whole GitHub organization in one
  pass. Triggers: "audit gin routes", "find open endpoints", "which routes
  have no auth", "list routes and middleware", "gin attack surface",
  "unauthenticated API endpoints", "audit all our services", "audit this
  org's repos".
---

# Gin route audit (gin-recon)

Drives the `gin-recon` binary to enumerate routes and flag unauthenticated
ones. gin-recon is a **deterministic static analyzer** — it type-checks the
target with `go/packages`, never runs the target application, and never
invokes an LLM anywhere in its own analysis. It classifies each route as
`proven` (behind a configured guard whose control flow is confirmed or
reviewer-attested to enforce), `public` (no recognized auth), or `unknown`
(guarded only by an opaque/unresolved middleware, or a guard whose control
flow provably never denies). This determinism is the entire point of the
tool — see the end of this file for exactly where AI does and does not fit
into the picture.

## 0. Locate the tool

Use whichever resolves first:

- `gin-recon` on PATH, else
- a pre-built binary at `${CLAUDE_PLUGIN_ROOT}/bin/gin-recon` (if the plugin
  ships one for the current platform), else
- build it from a local checkout: `go build -o /tmp/gin-recon ./cmd/gin-recon`
  (run from the gin-recon repo root), then use `/tmp/gin-recon`.

If none is available and no Go toolchain is present to build one, tell the
user how to install Go and build gin-recon, then stop.

All commands below take `--src <repoDir>` (the target repo, default cwd) and
`--profile typed|syntax-only` (default `typed`).

- `typed` (default) type-checks the target with `go/packages` but never runs
  it, never accesses the network by default, and uses a sanitized,
  offline-by-default environment (`GOPROXY=off`, `GOFLAGS` cleared, etc.).
  Pass `--allow-downloads` only if the module graph needs fetching and the
  checkout is trusted. It resolves canonical symbol identity, so `proven`
  and `stale-auth-config` are both available, and it follows registrar
  functions across files/packages.
- `syntax-only` never invokes `go/packages` or the Go toolchain at all — no
  module resolution, no network access, no `--allow-downloads` (rejected as
  invalid alongside this profile). It only recognizes routes registered
  directly inside the same function that constructs the engine
  (`r := gin.New()`/`gin.Default()`); a registrar-function pattern
  (`func RegisterRoutes(r *gin.Engine) {...}` called from elsewhere) is
  outside its scope and produces a `gin-syntax-unresolved-registrar` or
  `gin-syntax-untracked-value` coverage diagnostic rather than a silently
  missing route. It never resolves a canonical symbol, so it can never
  classify a route `proven` and never fires `stale-auth-config` (a
  `gin-syntax-auth-config-unverifiable` diagnostic explains why when auth
  config is present) — use it for a quick, hermetic pass over a hostile or
  untrusted checkout, not as a substitute for a full typed audit.

## 1. Discover auth middleware (don't guess the allowlist)

The audit is only as good as the auth allowlist. Discover candidates first:

```bash
gin-recon suggest-auth --src <repoDir>
```

This returns JSON `candidates` ranked with likely guards first (`nameHint:
true`, partial route coverage over `appliesToAllRoutes: true`). Each
candidate's `canonicalSymbol` is already the exact string a config needs —
copy it directly, do not retype or abbreviate it. Pick the ones that are
genuinely authentication/authorization/signature-verification middleware —
names like `RequireAuth`, `JWTMiddleware`, `PartnerSecretAuthMiddleware`,
`*SignatureVerifier`. Ignore request binding/validation, CORS, gzip,
recovery, logging, and tracing middleware — `knownNonAuth: true` already
flags Gin's own `Recovery`/`Logger` and a few well-known
`gin-contrib/{cors,gzip,requestid}` symbols, but that denylist is
deliberately small (see the "AI's role" section below for why gin-recon does
not ship a broader reviewed catalog itself).

`opaqueMiddleware` in the output counts middleware that never resolved to a
canonical symbol at all (anonymous functions, or references the analyzer
could not trace) — these can never become a config key; read their source at
the route(s) that carry them to judge whether they hide a real guard.

If the user already has a known auth-middleware list, skip discovery and use
it directly.

## 2. Write a config

Create a temp config file (JSON or YAML; strict — no comments, no unknown
fields) mapping each chosen canonical symbol to an entry. Keys are canonical
Go identities independent of import aliases: `pkg/path.FuncName`,
`pkg/path.(*Type).MethodName`, or a function-typed value's canonical name —
copy them verbatim from `suggest-auth`'s `canonicalSymbol` field.

```json
{
  "version": 1,
  "authMiddleware": {
    "github.com/example/service/internal/middlewares.JWTMiddleware": {
      "assurance": "analyze",
      "tags": ["authenticated"]
    },
    "github.com/example/service/internal/middlewares.PartnerSecretAuthMiddleware": {
      "assurance": "attested",
      "tags": ["signed:partner"]
    }
  },
  "acceptedPublic": ["GET /health", "POST /webhooks/stripe"]
}
```

`assurance` controls how much control-flow evidence a match needs:

- `analyze` (default) — the guard's body must have a **confirmed** abort
  shape (a direct or one-level-delegated if-abort-return on the request
  context). This is what "proven" should mean for most guards.
- `attested` — a human reviewer vouches the guard enforces even though its
  control flow could not be confirmed (e.g. it delegates two levels deep, or
  aborts via a framework hook the analyzer doesn't trace). Use sparingly and
  only for guards you have actually read. A guard whose control flow is
  **provably a no-op** (`enforcementAnalysis: contradicted`) is never
  `proven` regardless of assurance — that always produces a
  `matched-but-unenforced` finding instead.

On a brownfield service, seed `acceptedPublic` with `"METHOD /normalized/path"`
entries for endpoints that are intentionally open, after reviewing them —
otherwise every legitimately-public route trips `--fail-on public`. An entry
that no longer matches a live public route (deleted, or now guarded)
surfaces as a `stale-baseline` finding so the list can be pruned instead of
silently pre-approving a future, different route at the same path.

The config schema also accepts `authWrappers` (canonical factories that
always invoke a wrapped guard, e.g. `LoggedAuth(RequireAuth)`) — copy the
wrapper's own `canonicalSymbol` (not the wrapped guard's) into the list.
Once configured, a call like `LoggedAuth(RequireAuth)` exposes `RequireAuth`
as authentication evidence exactly as if it had been registered directly —
the same `analyze`/`attested` assurance and `confirmed-shape`/`unresolved`/
`contradicted` enforcement rules apply to the wrapped guard, so a wrapper
around a provably-no-op guard still yields `unknown` plus
`matched-but-unenforced`, never `proven`. An unconfigured wrapper never
exposes its argument, no matter how guard-like the wrapped call looks —
only add a symbol here after confirming by reading its source that it
always invokes its argument.

## 3. Audit

```bash
gin-recon audit --src <repoDir> --config <cfg.json> --format json
```

Parse the JSON report (`schemaVersion`, `summary`, `routes`, `findings`,
`scanCoverage`). Key fields per route: `method`, `normalizedPath`, `auth`
(`authStatus`, `enforcementAnalysis`, `confidence`), `middleware[].displayName`,
`source.{file,line}`, `pathConfidence`.

Findings to surface, in priority order:

- `matched-but-unenforced` (**high**) — a configured guard matched by
  canonical symbol, but bounded control-flow analysis proves its body never
  actually terminates the request chain on failure. The most dangerous
  finding: a route that *looks* guarded but isn't.
- `per-verb-gap` (**high**) — the same normalized path has inconsistent
  authentication across HTTP methods (e.g. `GET` proven, `DELETE` public on
  the same resource) — a classic write-path bypass. An accepted-public
  sibling does not itself trigger this (an intentionally-open health check
  next to a proven business endpoint is not a gap).
- `public-route` (**medium**) — no configured guard matched this route's
  resolved middleware chain.
- `opaque-middleware` (**medium**) — an anonymous or otherwise unresolved
  middleware could be hiding a real guard; read the source to judge.
- `stale-auth-config` (**medium**) — a configured `authMiddleware` symbol was
  never matched anywhere in the scanned code (rename, move, or removal in
  the target repo).
- `stale-baseline` (**low**) — an `acceptedPublic` entry no longer matches a
  live public route; prune it.
- `gin-explicit-trust-all-proxies` (**medium**) — engine trusts all proxies;
  client IP from forwarded headers may be attacker-controlled.
- `gin-explicit-debug-mode` (**low**) — `gin.SetMode(gin.DebugMode)` resolved
  in the selected build context.
- `policy-violation` (configured severity) — a route failed a named
  middleware/auth/role/scope/ordering/composed policy from `policies`.

Every finding carries a stable `fingerprint`, `severity`, `confidence`, and
source location when one was resolved. Also inspect `scanCoverage.complete`:
if false, do not present the audit as complete — surface `diagnostics` (each
has a `code`, `severity`, `message`, and often a `source`) and either fix the
underlying load/resolution failure or explicitly scope around it.

## 4. Report to the user

Lead with `matched-but-unenforced` and `public-route` findings, each with a
clickable `file:line` reference. Note the totals from `summary`
(`provenByConfirmedShape` vs `provenByAttestedUnresolved` are reported
separately — never merge them into one "proven" count when explaining
results, since one is analyzer-confirmed and the other is reviewer-trusted).
Then:

- If a `public` route's chain contains a middleware that IS auth but wasn't
  in the config, add it and re-audit — iterate until the public list is only
  genuinely-open routes.
- If `unresolvedRegistrations` in `scanCoverage` is nonzero, some routes
  could not be inventoried at all (an unresolvable registrar-function call,
  a wrapping-factory engine value, a recursive registrar chain) — read the
  corresponding diagnostics; a route this analyzer cannot see is a route it
  cannot audit, which is a worse outcome than a route it audits and gets
  wrong.

## CI gate

```bash
gin-recon audit --src <repoDir> --config <cfg> --format sarif,md \
  --out <outDir> --fail-on public,incomplete
# exit code 2 if any public route remains or scan coverage is incomplete;
# add unknown to also gate review items.
```

`results.sarif` is ready for GitHub Code Scanning (`upload-sarif` action) —
`ruleIndex`/`partialFingerprints` are wired for alert tracking across
commits. `routes.md` is a human-readable PR-comment-ready summary. Both are
escaped against a hostile scanned repository injecting content into the
rendered output (docs/threat-model.md).

## Auditing many repos at once (fleet)

Reach for `fleet` instead of a loop of manual `audit` invocations whenever
the ask spans more than one repository: "audit all our services," "check
this whole org for open endpoints," or any request naming several repos by
name. It runs the exact same `audit` you'd run by hand, once per target, in
its own subprocess, and aggregates the results — nothing about
classification, findings, or evidence differs from a single-repo `audit`.

For a known, fixed set of local checkouts, write a targets manifest:

```json
{
  "version": 1,
  "targets": [
    { "name": "svc-a", "src": "/path/to/svc-a" },
    { "name": "svc-b", "src": "/path/to/svc-b" }
  ]
}
```

```bash
gin-recon fleet --targets targets.json --config <cfg.json> --out <outDir> \
  --concurrency 4 --fail-on incomplete
```

For a whole GitHub organization, skip hand-writing the manifest:

```bash
gin-recon fleet --org <name> --config <cfg.json> --out <outDir> \
  --allow-remote-targets --fail-on incomplete
```

`--org` needs `--allow-remote-targets` plus `api.github.com` **and** the
repositories' own host (usually `github.com`) both listed in
`--config`'s `fleet.allowedRemoteHosts` — this is a real, deliberate trust
boundary (fetching the target's source itself, not just resolving Go module
dependencies), not a flag to add reflexively. If the user hasn't set this up
yet, show them the two-entry config shape rather than guessing at scope:

```json
{ "version": 1, "fleet": { "allowedRemoteHosts": [
  { "host": "api.github.com", "tokenEnv": "GH_TOKEN" },
  { "host": "github.com" }
] } }
```

Read the results from `<outDir>/fleet.json` (or open `<outDir>-html/fleet.html`
— a self-contained summary table linking to every target's own report)
rather than opening each target individually. `<outDir>` holds only raw
JSON; every HTML file, including a target's own `api.html` when `--format`
included `openapi`, lands in the sibling `<outDir>-html` directory
instead — generated automatically in the same run, no separate command.
Each target lands in exactly one of
`ok`, `not-go-module` (no `go.mod` — never counted as a failure), or
`failed` (retried automatically on the next `--resume`, so a long fleet run
interrupted partway through is safe to re-invoke with `--resume` added
rather than restarted from scratch).

**One caveat worth surfacing to the user, not just noting silently:** every
target in a fleet run shares the same `--config`, so the same
`authMiddleware` entries apply to every repo. A config written for one
service's real middleware symbols will classify every route in a
differently-structured service as `public` with zero warning beyond
`stale-auth-config` findings for the unmatched entries — this is exactly
gin-recon's conservative-by-design behavior, not a bug, but it means a fleet
result showing one target at 100% public deserves a second look at whether
that target actually has its own auth middleware missing from the shared
config, before reporting it as a real finding.

If a target scans an un-vendored module that needs network access to
resolve, pass `--allow-downloads` on the `fleet` invocation itself — it's
forwarded to every target's own `audit` subprocess exactly like `--config`.

Point `render --report <outDir>/fleet.json --out <outDir> --force` at a
fleet's own output to add a format (e.g. `--format json,openapi`) or
regenerate `fleet.html` afterward, without re-running any target's `audit` —
each target's own `routes.json` is re-rendered from what's already on disk.

## Comparing against a prior run

```bash
gin-recon audit --src <repoDir> --config <cfg> --format json \
  --baseline previous-report.json --fail-on regression,new
```

Requires a previous `audit` JSON report at the same schema major, analysis
profile, and build context (GOOS/GOARCH/tags/module/workspace mode) — an
incompatible baseline is rejected with an explanation rather than producing
a misleading diff. The resulting report's `delta` field lists
`addedRoutes`/`removedRoutes`, `authRegressions`/`authImprovements` (each
with a structural `explanation` — removed tags/roles/scopes, removed
middleware, newly-`unknown` enforcement, or a generic fallback when the
config change isn't visible in route-level evidence), and
`newFindings`/`resolvedFindings` by fingerprint. `--fail-on regression`
gates on any auth status becoming riskier (`proven`→`unknown`→`public` in
increasing risk order); `--fail-on new` gates on any added route or new
finding.

## Modes and honesty about what's built

- `typed` (default) — type-checks with `go/packages`, never executes the
  target. The richer profile: resolves canonical symbols, follows registrar
  functions across files/packages, can classify `proven`.
- `syntax-only` — hermetic, AST-only, no `go/packages` and no Go toolchain
  invocation at all. Scoped to direct, same-function Gin registrations only
  (see step 0 above); recommend it when the checkout itself is untrusted or
  the module graph cannot be resolved, not as a general substitute for
  `typed` — a registrar-heavy codebase will legitimately show much lower
  route recall under this profile, with `scanCoverage.complete: false` and
  diagnostics explaining why, not a silent gap.
- Inventory only (no security judgment): `gin-recon inventory --src <repoDir>`.
- To also **document the API** (OpenAPI 3.1 + a self-contained HTML viewer),
  use the `openapi-doc` skill, or add `--format openapi` to the same `audit`
  command — `api.html` is written alongside `openapi.json` automatically,
  with no extra flag.

## AI's role: ranking and enrichment, never classification

Everything above — route discovery, canonical symbol resolution, control-flow
enforcement-shape analysis, `proven`/`public`/`unknown` classification,
finding generation — runs with **zero AI involvement**, by design
(docs/threat-model.md). The reasons this matters for a security tool:
reproducibility (the same source always produces the same report, which is
what makes CI gating and baseline diffing meaningful at all), auditability
(a security reviewer can read the exact bounded control-flow rule that fired,
not guess at a model's reasoning), and resistance to prompt injection from a
hostile scanned repository (there is no prompt for injected source text to
reach).

AI (you, running this skill) only ever touches two things, both explicitly
advisory:

1. **`suggest-auth`'s ranking is a hint, never evidence.** The tool's own
   name-pattern heuristic and small non-auth denylist only reorder a list; a
   human/AI reviewer still decides what actually goes in `authMiddleware`.
   `docs/threat-model.md` is explicit that this list can never auto-promote a
   route's classification.
2. **Reading source to judge an `opaque-middleware` or `unresolved`
   diagnostic.** When the analyzer cannot resolve something (an anonymous
   function, a wrapping factory, a two-level registrar chain), that gap is
   surfaced as a diagnostic, not silently guessed at — reading the flagged
   source and deciding what it means is exactly the kind of judgment call
   static analysis correctly declines to make on its own.

Both roles are about **filling analyzer-declared gaps**, not about
second-guessing what the deterministic core already resolved. If gin-recon's
own analysis says `confirmed-shape`, that's load-bearing evidence — verify it
by reading the code if you want, but don't treat an AI's contrary read as
overriding it in a report.
