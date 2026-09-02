# Gin Security Rules

Gin-specific engine findings are evidence-based and separate from route authentication. Version 1 defines only the following rules; additional rules require an ADR, fixture corpus, and measured false-positive review.

## `gin-explicit-trust-all-proxies`

- Severity: medium.
- Confidence: high when a resolved `SetTrustedProxies` call contains `0.0.0.0/0`, `::/0`, or an equivalent all-address CIDR; otherwise no finding.
- Detail: client IP derived from forwarded headers may be attacker-controlled when all proxies are trusted.
- Recommendation: configure only known proxy CIDRs or pass `nil` when forwarded client IP is unnecessary.

The analyzer does not claim that an engine retained Gin's default proxy setting unless construction and every configuration path are completely resolved. When default state cannot be established, it emits a diagnostic rather than a vulnerability finding. A future correlated rule may raise severity when trusted client IP is used for authorization or rate limiting.

## `gin-explicit-debug-mode`

- Severity: low.
- Confidence: high only for a resolved `gin.SetMode(gin.DebugMode)` or equivalent constant assignment in the selected build context.
- Detail: production execution may expose verbose diagnostics or route information.
- Recommendation: select release mode in production and keep mode configuration outside attacker control.

The rule does not infer environment values and does not flag absence of an explicit release-mode call.

## Reporting

Engine findings include canonical rule ID, source, build context, structured call/value evidence, confidence, and stable fingerprint. They never change route authentication status. Ambiguous values, calls through unresolved helpers, or configuration in excluded build contexts produce diagnostics rather than findings.
