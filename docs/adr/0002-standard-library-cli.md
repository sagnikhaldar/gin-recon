# ADR 0002: Standard-Library CLI

## Status

Accepted.

## Context

The CLI needs subcommands, repeatable options, deterministic validation, and stable exit codes. Third-party frameworks improve ergonomics but enlarge the dependency and trusted supply-chain surface.

## Decision

Implement command dispatch and option parsing with the Go standard library. Centralize parsing and validation so each option has one definition and command applicability is tested.

## Consequences

Help generation and repeatable-value types require small internal utilities. The production CLI avoids a broad command-framework dependency.

## Rejected Alternatives

Cobra and Kong were rejected for v1. They may be reconsidered only if measured maintenance costs outweigh the security and dependency benefits.
