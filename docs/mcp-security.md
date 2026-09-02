# MCP Security Contract

**Status: not yet implemented.** `cmd/gin-recon-mcp` is a reserved path with
no code behind it yet — per [PLAN.md](../PLAN.md#delivery-phases), MCP work
begins after the core report contract stabilizes. This document specifies
the security contract the server must satisfy once built; nothing below
describes current, callable behavior. Do not tell a user an MCP server is
available today.

## Scope

The v1 MCP server will expose static inventory, audit, suggestion, OpenAPI, schema, policy validation, paginated query, and finding lookup over stdio. It will not be able to invoke runtime/hybrid analysis, enable module downloads, change repository files, or start a network listener.

## Root Containment

The server will start with one or more explicit `--root <dir>` values; default is the server process's current directory. Roots will be canonicalized once. Every tool path, config, baseline, ignore file, workspace, and existing OpenAPI input must resolve beneath one permitted root after symlink resolution. Paths crossing roots, device files, FIFOs, sockets, and symlinks escaping a root must be rejected before reading.

Tool inputs will use root-relative paths. Responses must contain root-relative paths and a stable root label, never absolute host paths.

## Limits and Cancellation

- Default call timeout: 30 seconds; server maximum: five minutes.
- Default page size: 50; maximum: 200.
- Cursors must be opaque, versioned, query-bound, and rejected when tampered with or reused for different filters.
- Analyzer file/package/diagnostic/output caps must be inherited from the configuration contract and may only be lowered per call.
- Client cancellation must propagate to package loading and formatting; partial output must never be returned as a successful canonical report.
- Concurrent scans must be bounded by a server startup limit, default 2 and maximum 8; excess calls receive a retryable error.

## Output and Errors

Large reports must be queried through summary and cursor-paginated tools. A direct tool result may not exceed 1 MiB by default or 5 MiB at the server maximum. Errors must use stable codes and sanitized messages without environment values, absolute paths, source snippets, or Go command output beyond a bounded redacted tail.

The stdio channel must carry protocol messages only. Human logs go to stderr and must redact tool arguments that may contain sensitive path names. No telemetry may be emitted by default.

## Typed Analysis

MCP typed analysis must be offline-only, use the same sanitized environment as the CLI, and must not expose `--allow-downloads`. Syntax-only (already implemented in the CLI — see [PLAN.md](../PLAN.md)) must remain available for hostile checkouts once the MCP server itself exists. Configuration must never be able to widen server roots, environment access, concurrency, time, or output caps.
