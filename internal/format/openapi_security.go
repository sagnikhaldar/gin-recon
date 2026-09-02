package format

import (
	"github.com/sagnikhaldar/gin-recon/internal/config"
	"github.com/sagnikhaldar/gin-recon/internal/model"
)

// applySecurity implements docs/openapi-strategy.md's Security Mapping
// section exactly: only audit evidence (route.Auth != nil) may set
// security at all — an inventory report never asserts it, regardless of
// whether a config happened to be supplied. Public routes get an explicit
// empty requirement (security: []); proven routes get a positive
// requirement only when their matched guard names a scheme that is both
// configured and declared in openapi.securitySchemes; everything else
// (unknown, or proven without a resolvable scheme) omits the field
// entirely and is marked unrefined instead of guessed at.
func applySecurity(op *operation, route model.Route, cfg *config.Config) {
	if route.Auth == nil {
		return
	}
	ext := op.Extensions["x-gin-recon"]
	ext.Roles = route.Auth.Roles
	ext.Scopes = route.Auth.Scopes

	switch route.Auth.AuthStatus {
	case model.AuthPublic:
		empty := []map[string][]string{}
		op.Security = &empty
	case model.AuthProven:
		if scheme, ok := resolveScheme(route.Auth, cfg); ok {
			sec := []map[string][]string{{scheme: {}}}
			op.Security = &sec
		} else {
			ext.Unrefined = append(ext.Unrefined, "security")
		}
	case model.AuthUnknown:
		ext.Unrefined = append(ext.Unrefined, "security")
	}
	op.Extensions["x-gin-recon"] = ext
}

// resolveScheme finds the OpenAPI security scheme name for a proven
// route's matched guard, requiring the scheme to be both named in the
// guard's authMiddleware entry and actually declared (and already
// validated by internal/config) in openapi.securitySchemes — Gin Recon
// never invents a scheme.
func resolveScheme(auth *model.AuthClassification, cfg *config.Config) (string, bool) {
	if cfg == nil || auth.MatchedEvidence == nil {
		return "", false
	}
	entry, ok := cfg.AuthMiddleware[*auth.MatchedEvidence]
	if !ok || entry.OpenAPIScheme == "" || cfg.OpenAPI == nil {
		return "", false
	}
	if _, declared := cfg.OpenAPI.SecuritySchemes[entry.OpenAPIScheme]; !declared {
		return "", false
	}
	return entry.OpenAPIScheme, true
}

// securitySchemesFrom returns the configured, already-validated security
// schemes to publish under components.securitySchemes, or nil if none were
// configured (config.SecurityScheme's JSON shape already matches OpenAPI's
// own SecurityScheme object exactly — see docs/configuration-contract.md's
// example — so no separate type is needed here).
func securitySchemesFrom(cfg *config.Config) map[string]config.SecurityScheme {
	if cfg == nil || cfg.OpenAPI == nil {
		return nil
	}
	return cfg.OpenAPI.SecuritySchemes
}
