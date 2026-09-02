# Threat Model

## Security Objective

Gin Recon helps security engineers discover externally reachable Gin handlers and reason about authentication and policy evidence. Its most damaging failure is a false negative that hides a route or labels it authenticated without sufficient evidence.

## Assets

- Completeness and integrity of the route inventory.
- Correct classification, findings, fingerprints, and baseline deltas.
- Confidentiality of source, environment variables, credentials, and middleware arguments.
- Integrity of the invoking repository and workstation.
- Availability of CI runners and developer machines.

## Adversaries and Inputs

Assume a scanned repository may contain malicious source, module/workspace files, symlinks, generated code, extreme syntax, dependency graphs, and values designed to enter reports. Configuration, baseline reports, ignore files, and existing OpenAPI documents are also untrusted inputs.

The analyzer must defend against path escape, excessive memory/CPU use, malicious diagnostics, report injection, secret disclosure, ambiguous middleware names, hash instability, and incomplete analysis presented as success.

## Trust Profiles

### Syntax-only

The syntax-only profile reads files beneath an explicitly resolved root using the standard parser. It does not run the target, invoke the Go toolchain, resolve remote modules, or load plugins. Symlinks that resolve outside the root are rejected. This is the preferred profile for hostile checkouts, with clearly lower analysis confidence. It cannot emit `proven`, canonical cross-package symbol identity, typed schemas, or complete inter-package propagation; these limitations are recorded in coverage.

### Typed

The typed profile uses `go/packages` and therefore invokes Go package-loading machinery. It still never runs the application, but it has a larger trust boundary than syntax-only mode. Registrar-following stays within the target module's own source unless `analysis.followModules` explicitly opts specific dependency modules in (see [docs/reference.md](reference.md#top-level-shape)); a resolved cross-module route's source is a stable `<module path>@<version>/<path>` label, never an absolute filesystem path.

Before invocation it must:

- Construct an allowlisted environment rather than inherit arbitrary variables.
- Set `GOPACKAGESDRIVER=off`.
- Set `GOTOOLCHAIN=local` to prevent toolchain auto-download.
- Disable CGO by default.
- Clear inherited `GOFLAGS`, `GOWORK`, `GOPROXY`, `GOPRIVATE`, `GONOPROXY`, `GONOSUMDB`, and tool-specific environment values, then set only documented values.
- Default `GOWORK=off`; accept only an explicitly selected root-contained workspace.
- Default to offline module loading with `GOPROXY=off` and `GOSUMDB=off`; module/toolchain downloads require the CLI's explicit opt-in and remain unavailable through MCP.
- Use `-mod=readonly`, or `-mod=vendor` for an explicitly selected valid root-contained vendor tree, so analysis never edits module files.
- Reject module replacements that resolve outside the scan root unless a future explicitly allowlisted path policy is introduced.
- Use tool-owned bounded caches outside the target tree and never write into the checkout.
- Apply the concrete wall-time, package/file, file-size, recursion, diagnostic, and output limits in the [configuration contract](configuration-contract.md).
- Record build tags, GOOS, GOARCH, workspace/module mode, and dependency-resolution failures.
- Avoid `go generate`, tests, application initialization, compiler plugins, and executable configuration.

For genuinely hostile code, users should additionally run typed analysis inside an OS/container sandbox with network disabled and a read-only checkout.

## Classification Safety

- Match middleware by canonical package symbol and callable identity.
- Treat anonymous, unresolved, dynamic, or conditionally propagated middleware as `unknown`.
- Treat configured auth middleware as reviewer-supplied evidence and control-flow analysis as an independent enforcement-shape signal, never as semantic proof.
- Under default `assurance: analyze`, a canonical match needs `enforcementAnalysis: confirmed-shape` for `proven`. Under explicit `assurance: attested`, `confirmed-shape` or `unresolved` may be `proven`.
- `enforcementAnalysis: contradicted` always yields `unknown` and a `matched-but-unenforced` finding. An abort path cannot identify auth without a configured canonical match.
- Never promote `unknown` to `proven` because of a suggest-auth heuristic, and never use the curated auth-middleware reference list to auto-promote a route — it only ranks `suggest-auth` output.
- Runtime-only routes in any future hybrid mode remain `unknown` unless the probe supplies independently trustworthy middleware evidence.
- Incomplete coverage is visible at report and affected-route level and can fail CI.

## Data Handling

Reports may include package paths, symbol names, route paths, struct field names, and bounded source locations. They must not include environment values, request examples discovered in code, middleware arguments, tokens, connection strings, or arbitrary source snippets. Diagnostics and SARIF/Markdown content must be safely escaped for their output context.

Fingerprints use normalized rule and route identity, not secret values, absolute machine paths, or line numbers.

## Runtime Boundary

Runtime/hybrid analysis is excluded from v1. A future implementation must be an explicit target-provided probe, executed only for trusted code in a bounded child process or container. It must not claim OS isolation, silently inherit the parent environment, bind public listeners, or depend on Gin private fields.

The static MCP boundary is separately constrained by the [MCP security contract](mcp-security.md); tool requests cannot widen permitted roots, enable downloads, or raise server resource caps.

## Security Review Gates

Changes to classification, route propagation, package loading, path handling, schemas, runtime behavior, or output redaction require explicit security review and adversarial tests. A decrease in supported-pattern recall blocks release even when aggregate code coverage remains high.
