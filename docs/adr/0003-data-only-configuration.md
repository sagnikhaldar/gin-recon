# ADR 0003: Data-Only Configuration

## Status

Accepted.

## Context

Authentication mappings and policies require configuration. Executable configuration would allow target-controlled code execution and undermine static analysis trust guarantees.

## Decision

Accept strict JSON and YAML only. Reject unknown fields, ambiguous duplicates, malformed dates, invalid policy composition, and unsupported schema versions. Never compile, import, or execute configuration.

## Consequences

Configuration remains portable, schema-validatable, reviewable, and safe to parse. Dynamic boot hooks are unavailable and belong only to a future explicit runtime probe.

## Rejected Alternatives

Go plugins, interpreted scripts, and compiled configuration packages were rejected because they cross the execution boundary.
