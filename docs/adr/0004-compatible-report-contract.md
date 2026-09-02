# ADR 0004: Compatible-Core Report Contract

## Status

Accepted.

## Context

Existing Express Recon consumers benefit from familiar inventory, finding, policy, and delta concepts, but Gin has different evidence and stronger type information.

## Decision

Create an independent Gin Recon schema beginning at `1.0`. Preserve framework-neutral field meanings and status semantics while adding Gin-specific evidence explicitly.

## Consequences

Cross-tool consumers can share common processing without pretending that the schemas are identical. Gin-specific additions evolve without coupling releases to Express Recon.

## Rejected Alternatives

Exact schema identity was rejected because it would misrepresent Gin evidence. A wholly unrelated schema was rejected because it would needlessly fragment integrations.
