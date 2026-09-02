# ADR 0007: OpenAPI Evidence Precedence

## Status

Accepted.

## Context

Go types, Gin binding/render calls, annotations, and existing OpenAPI documents may disagree. Silent precedence could produce incorrect security or request/response documentation.

## Decision

Analyzer evidence is authoritative for route existence, method, path, handler, middleware, source, and configured authentication. Existing documentation may enrich prose and provide schemas when code evidence is unresolved. A reviewed schema may refine code-derived evidence only when it is structurally compatible with all resolved fields and types. Conflicts retain the code-derived value, produce structured diagnostics, and mark the affected detail unrefined.

Gin Recon never invents an OpenAPI security scheme. Operation-level `security` is emitted only when configured auth evidence names a validated scheme. Generated documents never set global `security`; unknown auth is represented through `x-gin-recon`, not an OpenAPI security assertion.

## Consequences

Generated OpenAPI remains traceable and conservative. Users may need to resolve conflicts instead of receiving a superficially complete but misleading document.

## Rejected Alternatives

Last-write-wins merging, trusting annotations over code, and inventing missing types were rejected because they conceal uncertainty.
