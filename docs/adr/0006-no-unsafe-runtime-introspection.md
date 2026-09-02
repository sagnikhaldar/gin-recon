# ADR 0006: No Unsafe Gin Introspection

## Status

Accepted.

## Context

Gin stores complete handler chains in private routing structures. Reading them through unsafe memory assumptions could appear to enable runtime parity but would couple the tool to undocumented layouts.

## Decision

Do not use `unsafe`, reflection over private memory, `go:linkname`, patched Gin forks, or version-specific structure offsets. Any future runtime evidence must come from a documented target-provided probe and remain opt-in.

## Consequences

Runtime middleware parity is deferred, but compatibility and safety do not depend on Gin internals. Runtime-only evidence will remain unknown unless the probe supplies a complete chain contract.

## Rejected Alternatives

Private tree traversal and source rewriting were rejected as fragile, difficult to audit, and unsafe for a security product.
