# Authentication Catalog Governance

## Purpose

The auth-adjacent middleware catalog seeds `suggest-auth` ranking for commonly used Gin integrations. It is discovery assistance only: catalog membership can never create authentication evidence, select an assurance mode, or change `public`/`unknown`/`proven` classification.

## Artifact

Implementation will store a schema-versioned, deterministic `data/auth-catalog.json` containing canonical module/symbol identities, module version range when known, category, documentation URL, evidence summary, review date, and catalog entry version. It must not contain executable matching code, regular expressions over arbitrary source, package downloads, or default auth configuration.

Initial categories may cover authentication, authorization, sessions, signatures/webhooks, and deliberately non-auth adjacent middleware. Product names such as gin-jwt, Casbin integrations, and gin-contrib/sessions are added only after verifying their actual canonical symbols and semantics against pinned upstream source.

## Change Control

- Every entry requires primary-source evidence and two-person review, including one security reviewer.
- Updates include fixtures proving suggestion ranking and proving no classification change.
- Removed or renamed upstream symbols remain version-scoped rather than silently retargeted.
- The catalog version is included in `suggest-auth` output, not ordinary audit fingerprints.
- Network lookup or automatic catalog refresh during a scan is prohibited.
- Release notes identify catalog additions, removals, and evidence changes.

The repository's security/code owners approve catalog changes once those governance files are introduced during scaffolding.
