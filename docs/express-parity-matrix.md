# Express Recon Parity Matrix

This matrix maps the inspected Express Recon behavior to Gin Recon. “Parity” preserves behavior, “redesigned” preserves intent using Go/Gin semantics, “deferred” is post-v1, and “rejected” is intentionally excluded.

| Capability | Disposition | Gin Recon decision |
| --- | --- | --- |
| Route inventory | Parity | Emit method, normalized path, middleware chain, handler, source, and confidence. |
| Static scanner | Redesigned | Use typed Go AST and package identity rather than JavaScript syntax and module resolution. |
| Runtime router walk | Deferred | Gin's public route metadata omits the full middleware chain; v1 remains static-only. |
| Hybrid reconciliation | Deferred | Define only after an explicit runtime probe has a trustworthy evidence contract. |
| Runtime compatibility stubs | Rejected | Do not fake databases, brokers, or infrastructure clients inside target Go applications. |
| Unsafe Gin tree inspection | Rejected | Never depend on private Gin layout through `unsafe` or `go:linkname`. |
| `inventory` command | Parity | Return raw route evidence without security judgment. |
| `audit` command | Parity | Classify routes, evaluate policies, and emit findings. |
| `suggest-auth` | Redesigned | Rank canonical Go middleware symbols and calls, excluding known non-auth middleware. |
| `schema` command | Parity | Emit the versioned Gin Recon JSON Schema. |
| Auth allowlist | Redesigned | Match fully qualified function/method identities with explicit `analyze` or `attested` assurance, not ambiguous display names. |
| Transparent wrappers | Redesigned | Support only explicitly configured factories/wrappers with conservative call evidence. |
| `proven/public/unknown` | Redesigned | Preserve statuses while separating configured evidence from confirmed/unresolved/contradicted enforcement analysis. |
| Accepted-public baseline | Parity | Suppress reviewed public-route findings and report stale entries. |
| Per-verb gaps | Parity | Detect inconsistent auth state across methods sharing a normalized path. |
| Route policies | Parity | Support auth, tags, roles, scopes, middleware presence/order, boolean composition, and expiring exceptions. |
| Stable finding fingerprints | Parity | Hash rule identity plus normalized route identity; exclude source line numbers. |
| Baseline comparison | Parity | Report added/removed routes, auth changes, new/resolved findings, and regressions. |
| Scan coverage | Redesigned | Include package/build context, typed/syntax profile, analyzed files/packages, and unresolved constructs. |
| Source scope and ignore file | Parity | Support root-relative include/exclude patterns and `.gin-reconignore`. |
| JSON/YAML config | Parity | Parse strictly and reject unknown fields. |
| Executable config | Rejected | Do not execute target-provided Go configuration. |
| Pretty/JSON/Markdown | Parity | Preserve human and machine outputs with deterministic ordering. |
| OpenAPI 3.1 | Redesigned | Use typed bindings and response values; expose uncertainty through `x-gin-recon`. |
| SARIF | Improvement | Emit GitHub Code Scanning-compatible findings and locations. |
| Handler I/O hints | Redesigned | Infer from Gin binding/render calls and Go types rather than JavaScript property access. |
| MCP server | Redesigned | Static/offline-only tools over stdio with permitted-root enforcement, cancellation, concurrency/output caps, filtering, and bound cursors. |
| CLI failure gates | Parity | Gate public, unknown, policy, new, regression, and incomplete results with exit code 2. |
| Worker time/output limits | Deferred | Apply to a future explicit runtime probe, not the v1 static analyzer. |
| Engine security findings | Improvement | V1 reports only explicit trust-all-proxies and explicit debug-mode evidence under fixed rule IDs; ambiguity remains diagnostic. |
| `NoRoute`/`NoMethod` | Improvement | Inventory fallback surfaces separately from ordinary routes. |
| CI PR annotations | Improvement | Support SARIF plus Markdown summaries and complete report artifacts. |
| Release controls | Parity | Pin actions/tools, verify versions, publish checksums/SBOM/provenance, and sign artifacts. |

## Compatibility Rule

Common report concepts keep the same meaning where that meaning is framework-neutral. Gin-specific evidence uses new fields or `x-gin-recon` extensions; it must not be forced into misleading Express-shaped data. Gin Recon owns its schema version independently.
