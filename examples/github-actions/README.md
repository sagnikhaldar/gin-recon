# GitHub Actions examples

Two ready-to-copy workflows: [`pr-gate.yml`](pr-gate.yml) gates a single
repository's pull requests, and
[`scheduled-org-scan.yml`](scheduled-org-scan.yml) sweeps a whole GitHub
organization on a schedule. Pick whichever matches what you're protecting -
they don't depend on each other.

## PR gate

[`pr-gate.yml`](pr-gate.yml) turns `gin-recon audit --baseline` into a GitHub
Actions check: it audits your PR's base commit, audits the PR's head commit
against that as a baseline, and fails the job only when the delta itself is
worth blocking on - a route that's newly `public`, or one that regressed
from `proven` to something weaker. An unrelated `unknown` route that already
existed on the base branch doesn't fail a PR that never touched it.

### Setup

1. Copy `pr-gate.yml` to `.github/workflows/` in your repository.
2. Make sure a reviewed `gin-recon.json` lives at your repository root - see
   [docs/reference.md](../../docs/reference.md#top-level-shape) if you don't
   have one yet, and `suggest-auth` to help find the middleware to put in it.
3. That's it. No secrets, no external service - `security-events: write` is
   only there so the workflow can upload its own SARIF output to your
   repository's Code Scanning tab.

### Why two checkouts

The base commit and the PR head commit are checked out into separate
directories (`base/`, `head/`) in the same job, rather than checking out the
head branch and diffing against a remote ref. gin-recon's `--baseline` flag
takes a previously-generated `routes.json`, not a git ref, so the base
commit needs its own real audit run to produce one.

The `head/gin-recon.json` config is deliberately reused for both audits.
That's what makes a renamed or removed auth guard show up as a
`stale-auth-config` finding on the PR side, instead of quietly changing
what "proven" even means between the two runs being compared.

### Reading a failure

Exit code `2` means the gate matched - a real, intentional stop, not a
crash. Open the job's `results/routes.md` (also written to the job summary)
or `results/results.sarif` (visible in the Code Scanning tab) to see exactly
which routes triggered it. Exit code `1` means gin-recon itself couldn't
run - a malformed config or an unreadable baseline - which is a workflow
problem to fix, not a route to review.

### Tightening the gate further

`--fail-on` takes a comma-separated list. Add `unknown` to also block on any
route gin-recon can't classify at all (not just ones that changed), or
`attested-unresolved` to require confirmed-shape enforcement in CI while
still allowing `attested` entries in the reviewed config for local runs. See
[docs/reference.md](../../docs/reference.md#common-options) for the full
selector list.

## Scheduled org scan

[`scheduled-org-scan.yml`](scheduled-org-scan.yml) runs `gin-recon fleet
--org` on a weekly schedule (also runnable by hand from the Actions tab) and
uses `--update` so each run only re-scans repositories that actually changed
since the previous one - a much shorter run than a full sweep once the
organization has been scanned once.

### Setup

1. Copy `scheduled-org-scan.yml` to `.github/workflows/` in whichever
   repository should own the schedule - it doesn't need to be one of the
   repositories being scanned.
2. Add a reviewed `fleet-config.json` at that repository's root, at minimum
   naming `github.com` in `fleet.allowedRemoteHosts` (see
   [docs/reference.md](../../docs/reference.md#fleet-options) for the full
   shape). The workflow's own `GIN_RECON_GITHUB_TOKEN` env var matches the
   `tokenEnv` name used in that doc's example config - keep them matching if
   you rename either one.
3. Set an Actions variable named `GIN_RECON_ORG` to the GitHub organization
   login to scan (repository or organization Settings -> Secrets and
   variables -> Actions -> Variables).
4. Add a secret named `GIN_RECON_GITHUB_TOKEN` - a token with read access to
   the organization's repositories, scoped only for that. This is separate
   from the workflow's own `GITHUB_TOKEN`, which can't see other
   repositories in the org.

### Why the cache

`--update` only works when the previous run's `fleet.json` and
`discovered-targets.json` are still around to compare against - inside one
job that's automatic, but a scheduled workflow gets a clean runner every
time. The cache steps carry `.gin-recon/scan` from one week's run into the
next so `--update` has something to compare. `actions/cache` keys can't be
overwritten, so this run always saves under a fresh key
(`...-${{ github.run_id }}`) and restores the most recent previous one via
`restore-keys`; GitHub evicts old entries on its own after about a week of
disuse, or you can prune them explicitly with `gh cache list` / `gh cache
delete`.

### Reading the summary

Each run adds a small table to the job summary - targets scanned, how many
were skipped as unchanged, and the fleet-wide proven/public/unknown totals.
The full `fleet.json` and rendered `fleet.html` are also uploaded as a
workflow artifact for a closer look, or for diffing against a previous
week's run by hand.
