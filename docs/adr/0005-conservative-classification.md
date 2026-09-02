# ADR 0005: Conservative Authentication Classification

## Status

Accepted.

## Context

Middleware names and configured symbols provide evidence but do not formally verify runtime enforcement. Incomplete propagation can otherwise create dangerous false assurance.

## Decision

Use `proven`, `public`, and `unknown`, and keep reviewer configuration separate from control-flow evidence.

Every configured auth entry selects an assurance mode:

- `analyze` (default): `proven` requires a canonical symbol match and `enforcementAnalysis: confirmed-shape`.
- `attested`: a reviewer explicitly asserts that the canonical symbol always enforces authentication; `confirmed-shape` or `unresolved` may be `proven`.

`enforcementAnalysis: contradicted` always yields `unknown` and a `matched-but-unenforced` finding, even for an attested entry. Abort/control-flow heuristics cannot identify auth without a configured symbol match. Anonymous, dynamic, or incompletely propagated route middleware remains `unknown`.

## Consequences

Brownfield projects may initially report more unknown routes and require reviewed configuration. Third-party or delegated guards require explicit attestation when their enforcement shape cannot be resolved. Findings remain explainable and avoid optimistic classification.

## Rejected Alternatives

Name heuristics, comments, or apparent JWT/session usage cannot independently prove authentication.
