# ADR 0001: Static-First Version 1

## Status

Accepted.

## Context

Express Recon can instrument a dynamic JavaScript framework at runtime. Gin's public `Engine.Routes()` data contains method, path, and final handler but not a trustworthy complete middleware chain. Booting arbitrary Go applications also expands the execution boundary substantially.

## Decision

Version 1 will use syntax-only and typed static analysis. Runtime and hybrid evidence are deferred until an explicit probe contract exists.

## Consequences

V1 remains suitable for source-first review and can provide middleware source evidence. Dynamic registrations may be incomplete and must be diagnosed. Runtime-only route discovery is unavailable in v1.

## Rejected Alternatives

Booting target applications by default and treating `Engine.Routes()` as complete were rejected because they would execute code and omit security-critical middleware evidence.
