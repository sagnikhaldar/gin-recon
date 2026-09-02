package config

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// acceptedPublicPattern is "METHOD /path": an uppercase HTTP method, a space,
// then an absolute path (docs/configuration-contract.md#policies-and-baselines).
var acceptedPublicPattern = regexp.MustCompile(`^[A-Z]+ /`)

// exceptionDatePattern is strict YYYY-MM-DD; time.Parse alone would also
// accept some non-canonical forms depending on layout reuse, so the regex
// runs first and time.Parse only confirms the date itself is calendrically
// valid (rejects 2026-02-30, for example).
var exceptionDatePattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

// Validate checks a decoded Config against every rule in
// docs/configuration-contract.md that Decode's strict parsing does not
// already enforce structurally (unknown fields, custom YAML tags, duplicate
// YAML mapping keys), applies documented defaults in place, and reports every
// violation found rather than stopping at the first one — a reviewer fixing
// configuration wants the whole list, not one error per run.
//
// Validate does not require going through Decode first, but Decode always
// calls it; call it directly only from tests that construct a Config by hand.
func Validate(cfg *Config) error {
	var errs []error

	if cfg.Version != 1 {
		errs = append(errs, fmt.Errorf("version: must be 1, got %d", cfg.Version))
	}

	errs = append(errs, validateAuthMiddleware(cfg)...)
	errs = append(errs, validateAuthWrappers(cfg)...)
	errs = append(errs, validateAcceptedPublic(cfg)...)

	resolvedDepth := DefaultMaxCallDepth
	if cfg.Limits != nil && cfg.Limits.MaxCallDepth != nil {
		resolvedDepth = *cfg.Limits.MaxCallDepth
	}
	errs = append(errs, validatePolicies(cfg, resolvedDepth)...)
	errs = append(errs, validateLimits(cfg.Limits)...)
	errs = append(errs, validateOpenAPI(cfg.OpenAPI)...)
	errs = append(errs, validateAnalysis(cfg.Analysis)...)

	applyDefaults(cfg)

	return errors.Join(errs...)
}

func applyDefaults(cfg *Config) {
	for key, entry := range cfg.AuthMiddleware {
		if entry.Assurance == "" {
			entry.Assurance = AssuranceAnalyze
			cfg.AuthMiddleware[key] = entry
		}
	}
}

func validateAuthMiddleware(cfg *Config) []error {
	var errs []error
	for symbol, entry := range cfg.AuthMiddleware {
		if strings.TrimSpace(symbol) == "" {
			errs = append(errs, errors.New("authMiddleware: keys must not be empty"))
			continue
		}
		switch entry.Assurance {
		case "", AssuranceAnalyze, AssuranceAttested:
		default:
			errs = append(errs, fmt.Errorf("authMiddleware[%s].assurance: must be %q or %q, got %q", symbol, AssuranceAnalyze, AssuranceAttested, entry.Assurance))
		}
		errs = append(errs, validateUniqueNonEmptyMinOne(fmt.Sprintf("authMiddleware[%s].tags", symbol), entry.Tags)...)
		errs = append(errs, validateUniqueNonEmptyMinOne(fmt.Sprintf("authMiddleware[%s].roles", symbol), entry.Roles)...)
		errs = append(errs, validateUniqueNonEmptyMinOne(fmt.Sprintf("authMiddleware[%s].scopes", symbol), entry.Scopes)...)
	}
	return errs
}

// validateUniqueNonEmptyMinOne enforces schema/config-1.json's "minItems: 1,
// uniqueItems: true, non-empty string items" rule, used for authMiddleware's
// tags/roles/scopes: nil (field absent) is fine, but an explicitly provided
// array must not be empty and must not repeat an item — an explicit empty
// array signals a misconfiguration (e.g. a template that forgot to fill in a
// value) rather than "no tags", which is instead expressed by omitting the
// field entirely.
func validateUniqueNonEmptyMinOne(field string, values []string) []error {
	if values == nil {
		return nil
	}
	var errs []error
	if len(values) == 0 {
		errs = append(errs, fmt.Errorf("%s: if present must be non-empty", field))
	}
	errs = append(errs, validateUniqueItems(field, values)...)
	return errs
}

// validateUniqueItems enforces "uniqueItems: true, non-empty string items"
// without a minItems constraint, used for authWrappers, where
// schema/config-1.json allows an explicit empty array to mean "no wrapper
// factories configured."
func validateUniqueItems(field string, values []string) []error {
	var errs []error
	seen := make(map[string]bool, len(values))
	for _, v := range values {
		if strings.TrimSpace(v) == "" {
			errs = append(errs, fmt.Errorf("%s: entries must not be empty", field))
			continue
		}
		if seen[v] {
			errs = append(errs, fmt.Errorf("%s: duplicate entry %q", field, v))
		}
		seen[v] = true
	}
	return errs
}

func validateAuthWrappers(cfg *Config) []error {
	return validateUniqueItems("authWrappers", cfg.AuthWrappers)
}

func validateAcceptedPublic(cfg *Config) []error {
	var errs []error
	seen := make(map[string]bool, len(cfg.AcceptedPublic))
	for _, entry := range cfg.AcceptedPublic {
		if !acceptedPublicPattern.MatchString(entry) {
			errs = append(errs, fmt.Errorf("acceptedPublic: %q must be \"METHOD /path\" (uppercase method, absolute path)", entry))
			continue
		}
		if seen[entry] {
			errs = append(errs, fmt.Errorf("acceptedPublic: duplicate entry %q", entry))
		}
		seen[entry] = true
	}
	return errs
}

func validatePolicies(cfg *Config, maxDepth int) []error {
	var errs []error
	seenPolicyIDs := make(map[string]bool, len(cfg.Policies))
	for i, p := range cfg.Policies {
		field := fmt.Sprintf("policies[%d]", i)
		if strings.TrimSpace(p.ID) == "" {
			errs = append(errs, fmt.Errorf("%s.id: must not be empty", field))
		} else if seenPolicyIDs[p.ID] {
			errs = append(errs, fmt.Errorf("policies: duplicate policy id %q", p.ID))
		} else {
			seenPolicyIDs[p.ID] = true
		}

		if depth := requirementDepth(&p.Require); depth > maxDepth {
			errs = append(errs, fmt.Errorf("%s.require: nesting depth %d exceeds maxCallDepth %d", field, depth, maxDepth))
		}
		if err := validateAuthValue(p.Require.Auth); err != nil {
			errs = append(errs, fmt.Errorf("%s.require.auth: %w", field, err))
		}

		seenExceptionIDs := make(map[string]bool, len(p.Exceptions))
		for j, exc := range p.Exceptions {
			excField := fmt.Sprintf("%s.exceptions[%d]", field, j)
			if strings.TrimSpace(exc.ID) == "" {
				errs = append(errs, fmt.Errorf("%s.id: must not be empty", excField))
			} else if seenExceptionIDs[exc.ID] {
				errs = append(errs, fmt.Errorf("%s: duplicate exception id %q within policy %q", excField, exc.ID, p.ID))
			} else {
				seenExceptionIDs[exc.ID] = true
			}
			if strings.TrimSpace(exc.Reason) == "" {
				errs = append(errs, fmt.Errorf("%s.reason: must not be empty", excField))
			}
			if err := validateExpiry(exc.Expires); err != nil {
				errs = append(errs, fmt.Errorf("%s.expires: %w", excField, err))
			}
		}
	}
	return errs
}

func validateAuthValue(v string) error {
	switch v {
	case "", "proven", "public", "unknown":
		return nil
	default:
		return fmt.Errorf("must be \"proven\", \"public\", or \"unknown\", got %q", v)
	}
}

// requirementDepth returns the maximum nesting depth of all/any/not, where a
// requirement with no nested composition is depth 1. This bounds the same
// recursive structure docs/configuration-contract.md caps at maxCallDepth.
func requirementDepth(r *PolicyRequirement) int {
	if r == nil {
		return 0
	}
	max := 0
	for _, child := range r.All {
		if d := requirementDepth(&child); d > max {
			max = d
		}
	}
	for _, child := range r.Any {
		if d := requirementDepth(&child); d > max {
			max = d
		}
	}
	if d := requirementDepth(r.Not); d > max {
		max = d
	}
	return max + 1
}

func validateExpiry(expires string) error {
	if !exceptionDatePattern.MatchString(expires) {
		return fmt.Errorf("must be a strict YYYY-MM-DD date, got %q", expires)
	}
	if _, err := time.Parse("2006-01-02", expires); err != nil {
		return fmt.Errorf("not a valid calendar date: %q", expires)
	}
	return nil
}

func validateLimits(l *LimitsConfig) []error {
	if l == nil {
		return nil
	}
	var errs []error

	if l.Timeout != nil {
		d, err := time.ParseDuration(*l.Timeout)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("limits.timeout: invalid duration %q: %w", *l.Timeout, err))
		case d <= 0:
			errs = append(errs, fmt.Errorf("limits.timeout: must be positive, got %q", *l.Timeout))
		case d > HardCapTimeout:
			errs = append(errs, fmt.Errorf("limits.timeout: %q exceeds the hard cap of %s", *l.Timeout, HardCapTimeout))
		}
	}

	errs = append(errs, boundedInt("limits.maxFiles", l.MaxFiles, HardCapMaxFiles)...)
	errs = append(errs, boundedInt("limits.maxPackages", l.MaxPackages, HardCapMaxPackages)...)
	errs = append(errs, boundedInt("limits.maxFileBytes", l.MaxFileBytes, HardCapMaxFileBytes)...)
	errs = append(errs, boundedInt("limits.maxDiagnostics", l.MaxDiagnostics, HardCapMaxDiagnostics)...)
	errs = append(errs, boundedInt("limits.maxOutputBytes", l.MaxOutputBytes, HardCapMaxOutputBytes)...)
	errs = append(errs, boundedInt("limits.maxCallDepth", l.MaxCallDepth, HardCapMaxCallDepth)...)

	return errs
}

// boundedInt enforces "zero and negative values are invalid" and the
// documented hard cap for one optional *int limits field.
func boundedInt(field string, v *int, hardCap int) []error {
	if v == nil {
		return nil
	}
	var errs []error
	if *v <= 0 {
		errs = append(errs, fmt.Errorf("%s: must be positive, got %d", field, *v))
	}
	if *v > hardCap {
		errs = append(errs, fmt.Errorf("%s: %d exceeds the hard cap of %d", field, *v, hardCap))
	}
	return errs
}

func validateAnalysis(a *AnalysisConfig) []error {
	if a == nil {
		return nil
	}
	var errs []error
	switch a.Profile {
	case "", "syntax-only", "typed":
	default:
		errs = append(errs, fmt.Errorf("analysis.profile: must be \"syntax-only\" or \"typed\", got %q", a.Profile))
	}
	switch a.ModuleMode {
	case "", "readonly", "vendor":
	default:
		errs = append(errs, fmt.Errorf("analysis.moduleMode: must be \"readonly\" or \"vendor\", got %q", a.ModuleMode))
	}
	if len(a.FollowModules) > 0 && a.Profile == "syntax-only" {
		errs = append(errs, fmt.Errorf("analysis.followModules is not meaningful with analysis.profile \"syntax-only\", which never loads go/packages or resolves canonical symbols at all"))
	}
	for _, pattern := range a.FollowModules {
		if strings.TrimSpace(pattern) == "" {
			errs = append(errs, fmt.Errorf("analysis.followModules: pattern must not be empty"))
		}
	}
	// A non-empty-but-all-whitespace value is rejected the same way other
	// optional string fields reject a blank-but-present value elsewhere in
	// this file (see validateUniqueNonEmptyMinOne's reasoning): "" is the
	// documented off switch, and anything else must be a real path, not a
	// misconfiguration artifact (e.g. a template that left the value blank).
	// Filesystem existence/parseability are deliberately NOT checked here —
	// per ADR 0013, a missing or unparsable document degrades the scan with a
	// diagnostic, it never fails configuration validation.
	if a.ExistingOpenAPIDocument != "" && strings.TrimSpace(a.ExistingOpenAPIDocument) == "" {
		errs = append(errs, fmt.Errorf("analysis.existingOpenAPIDocument: if present must be non-blank"))
	}
	return errs
}

func validateOpenAPI(o *OpenAPIConfig) []error {
	if o == nil {
		return nil
	}
	var errs []error
	for name, scheme := range o.SecuritySchemes {
		field := fmt.Sprintf("openapi.securitySchemes[%s]", name)
		switch scheme.Type {
		case "http":
			if strings.TrimSpace(scheme.Scheme) == "" {
				errs = append(errs, fmt.Errorf("%s: type \"http\" requires \"scheme\"", field))
			}
		case "apiKey":
			if strings.TrimSpace(scheme.Name) == "" {
				errs = append(errs, fmt.Errorf("%s: type \"apiKey\" requires \"name\"", field))
			}
			switch scheme.In {
			case "header", "query", "cookie":
			default:
				errs = append(errs, fmt.Errorf("%s: type \"apiKey\" requires \"in\" to be \"header\", \"query\", or \"cookie\", got %q", field, scheme.In))
			}
		case "oauth2":
			if scheme.Flows == nil {
				errs = append(errs, fmt.Errorf("%s: type \"oauth2\" requires \"flows\"", field))
			}
		case "openIdConnect":
			if !strings.HasPrefix(scheme.OpenIDConnectURL, "https://") {
				errs = append(errs, fmt.Errorf("%s: type \"openIdConnect\" requires an absolute https:// \"openIdConnectUrl\", got %q", field, scheme.OpenIDConnectURL))
			}
		default:
			errs = append(errs, fmt.Errorf("%s: type must be \"http\", \"apiKey\", \"oauth2\", or \"openIdConnect\", got %q", field, scheme.Type))
		}
	}
	return errs
}
