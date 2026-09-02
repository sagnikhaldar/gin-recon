# Security

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub Security Advisories for this repository. Do not open a public issue containing exploit details.

Include the affected gin-recon version, reproduction steps, impact, and any suggested mitigation. Reports concerning incorrect route or authentication classification are especially welcome: a false `proven` or a silently dropped route is this project's most damaging failure mode — see [docs/threat-model.md](docs/threat-model.md).

## Execution trust model

Gin Recon is static-only in v1: it never runs the target application. Two analysis profiles apply different trust boundaries — see [docs/threat-model.md](docs/threat-model.md#trust-profiles) for the complete rules enforced before invoking either.

- **`syntax-only`** reads files beneath an explicitly resolved root with the standard parser. It does not invoke the Go toolchain, resolve remote modules, or load plugins, and rejects symlinks that escape the root. This is the appropriate profile for untrusted checkouts.
- **`typed`** invokes `go/packages` under a sanitized, allowlisted environment with module/toolchain downloads disabled by default (`--allow-downloads` opts in explicitly). It still never runs the target application, but has a larger trust boundary than `syntax-only`. For genuinely hostile code, run typed analysis inside an OS/container sandbox with network disabled and a read-only checkout.

Configuration is strict, non-executable JSON/YAML — see [docs/adr/0003-data-only-configuration.md](docs/adr/0003-data-only-configuration.md). Gin Recon never executes target-provided configuration.

## Accepted dependency risk

Reviewed 2026-08-19: `govulncheck` against Go 1.26.5 reports eight advisories (GO-2026-6218, 6091, 6090, 6089, 6088, 5972, 5942, 5026), all in the Go standard library / `golang.org/x/net` as vendored into that toolchain release, not in any module this project imports. `govulncheck`'s own call-graph analysis confirms 0 vulnerabilities reachable from gin-recon's actual code. Most are already fixed in Go 1.26.6; CI should track the latest Go 1.25/1.26 patch release rather than pin an exact patch version, so this list should shrink automatically as the toolchain updates.

No findings yet in gin-recon's own direct dependencies (`go.yaml.in/yaml/v3`).
