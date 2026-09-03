package config

import (
	"fmt"
	"strings"
	"testing"
)

func TestValidateDefaultsAssuranceToAnalyze(t *testing.T) {
	cfg := mustDecode(t, FormatJSON, `{
		"version": 1,
		"authMiddleware": {"example.com/auth.Require": {}}
	}`)
	entry := cfg.AuthMiddleware["example.com/auth.Require"]
	if entry.Assurance != AssuranceAnalyze {
		t.Errorf("Assurance = %q, want default %q", entry.Assurance, AssuranceAnalyze)
	}
}

func TestValidateRejectsUnknownAssurance(t *testing.T) {
	expectDecodeError(t, FormatJSON, `{
		"version": 1,
		"authMiddleware": {"example.com/auth.Require": {"assurance": "trust-me-bro"}}
	}`, "assurance")
}

func TestValidateRejectsFollowModulesWithSyntaxOnlyProfile(t *testing.T) {
	expectDecodeError(t, FormatJSON, `{
		"version": 1,
		"analysis": {"profile": "syntax-only", "followModules": ["github.com/example/**"]}
	}`, "followModules is not meaningful")
}

func TestValidateAcceptsFollowModulesWithTypedProfile(t *testing.T) {
	cfg := mustDecode(t, FormatJSON, `{
		"version": 1,
		"analysis": {"profile": "typed", "followModules": ["github.com/example/**"]}
	}`)
	if len(cfg.Analysis.FollowModules) != 1 || cfg.Analysis.FollowModules[0] != "github.com/example/**" {
		t.Errorf("Analysis.FollowModules = %v, want [\"github.com/example/**\"]", cfg.Analysis.FollowModules)
	}
}

func TestValidateRejectsEmptyFollowModulesPattern(t *testing.T) {
	expectDecodeError(t, FormatJSON, `{
		"version": 1,
		"analysis": {"followModules": [""]}
	}`, "must not be empty")
}

func TestValidateRejectsEmptyAuthMiddlewareKey(t *testing.T) {
	expectDecodeError(t, FormatJSON, `{"version": 1, "authMiddleware": {"": {}}}`, "must not be empty")
}

func TestValidateRejectsEmptyExplicitTagsArray(t *testing.T) {
	// An absent "tags" is fine (no tags); an explicit empty array is treated
	// as a likely mistake, per docs/configuration-contract.md's minItems: 1.
	expectDecodeError(t, FormatJSON, `{
		"version": 1,
		"authMiddleware": {"example.com/auth.Require": {"tags": []}}
	}`, "must be non-empty")
}

// TestValidateAcceptsExplicitlyEmptyAuthWrappers is the regression test for
// a bug caught while cross-checking the Go decoder against
// testdata/examples/config-minimal.json: unlike authMiddleware's tags/roles/
// scopes, authWrappers has no minItems:1 in schema/config-1.json — an
// explicit empty array legitimately means "no wrapper factories configured."
func TestValidateAcceptsExplicitlyEmptyAuthWrappers(t *testing.T) {
	mustDecode(t, FormatJSON, `{"version": 1, "authWrappers": []}`)
}

func TestValidateRejectsDuplicateTags(t *testing.T) {
	expectDecodeError(t, FormatJSON, `{
		"version": 1,
		"authMiddleware": {"example.com/auth.Require": {"tags": ["a", "a"]}}
	}`, "duplicate entry")
}

func TestValidateRejectsMalformedAcceptedPublic(t *testing.T) {
	expectDecodeError(t, FormatJSON, `{"version": 1, "acceptedPublic": ["get /health"]}`, "METHOD /path")
	expectDecodeError(t, FormatJSON, `{"version": 1, "acceptedPublic": ["GET health"]}`, "METHOD /path")
}

func TestValidateAcceptsWellFormedAcceptedPublic(t *testing.T) {
	mustDecode(t, FormatJSON, `{"version": 1, "acceptedPublic": ["GET /health", "POST /webhooks/stripe"]}`)
}

func TestValidateRejectsDuplicateAcceptedPublic(t *testing.T) {
	expectDecodeError(t, FormatJSON, `{"version": 1, "acceptedPublic": ["GET /health", "GET /health"]}`, "duplicate entry")
}

func TestValidateRejectsDuplicatePolicyIDs(t *testing.T) {
	expectDecodeError(t, FormatJSON, `{
		"version": 1,
		"policies": [
			{"id": "p1", "selector": {}, "require": {"auth": "proven"}},
			{"id": "p1", "selector": {}, "require": {"auth": "proven"}}
		]
	}`, "duplicate policy id")
}

func TestValidateRejectsUnknownAuthValue(t *testing.T) {
	expectDecodeError(t, FormatJSON, `{
		"version": 1,
		"policies": [{"id": "p1", "selector": {}, "require": {"auth": "sort-of"}}]
	}`, "require.auth")
}

func TestValidateRejectsPolicyRequirementDeeperThanMaxCallDepth(t *testing.T) {
	// Build a requirement nested 3 levels deep (any -> any -> auth) but cap
	// maxCallDepth at 2, so it must be rejected.
	expectDecodeError(t, FormatJSON, `{
		"version": 1,
		"limits": {"maxCallDepth": 2},
		"policies": [{
			"id": "p1",
			"selector": {},
			"require": {"any": [{"any": [{"auth": "proven"}]}]}
		}]
	}`, "exceeds maxCallDepth")
}

func TestValidateAcceptsPolicyRequirementWithinMaxCallDepth(t *testing.T) {
	mustDecode(t, FormatJSON, `{
		"version": 1,
		"limits": {"maxCallDepth": 3},
		"policies": [{
			"id": "p1",
			"selector": {},
			"require": {"any": [{"any": [{"auth": "proven"}]}]}
		}]
	}`)
}

func TestValidateRejectsMalformedExceptionExpiry(t *testing.T) {
	base := `{
		"version": 1,
		"policies": [{
			"id": "p1", "selector": {}, "require": {"auth": "proven"},
			"exceptions": [{"id": "e1", "reason": "reviewed", "selector": {}, "expires": %q}]
		}]
	}`
	for _, bad := range []string{"2026-13-40", "not-a-date", "2026/12/31", "2026-1-1"} {
		expectDecodeError(t, FormatJSON, fmt.Sprintf(base, bad), "expires")
	}
}

func TestValidateAcceptsWellFormedExceptionExpiry(t *testing.T) {
	template := `{
		"version": 1,
		"policies": [{
			"id": "p1", "selector": {}, "require": {"auth": "proven"},
			"exceptions": [{"id": "e1", "reason": "reviewed", "selector": {}, "expires": %q}]
		}]
	}`
	cfg := mustDecode(t, FormatJSON, fmt.Sprintf(template, "2026-12-31"))
	if len(cfg.Policies[0].Exceptions) != 1 {
		t.Fatalf("expected one exception, got %d", len(cfg.Policies[0].Exceptions))
	}
}

func TestValidateRejectsDuplicateExceptionIDsWithinPolicy(t *testing.T) {
	expectDecodeError(t, FormatJSON, `{
		"version": 1,
		"policies": [{
			"id": "p1", "selector": {}, "require": {"auth": "proven"},
			"exceptions": [
				{"id": "e1", "reason": "a", "selector": {}, "expires": "2026-12-31"},
				{"id": "e1", "reason": "b", "selector": {}, "expires": "2026-12-31"}
			]
		}]
	}`, "duplicate exception id")
}

func TestValidateLimitsHardCaps(t *testing.T) {
	for _, tc := range []struct {
		name string
		json string
		want string
	}{
		{"maxFiles over cap", `{"version":1,"limits":{"maxFiles":200001}}`, "exceeds the hard cap"},
		{"maxFiles zero", `{"version":1,"limits":{"maxFiles":0}}`, "must be positive"},
		{"maxFiles negative", `{"version":1,"limits":{"maxFiles":-1}}`, "must be positive"},
		{"maxCallDepth over cap", `{"version":1,"limits":{"maxCallDepth":129}}`, "exceeds the hard cap"},
		{"timeout over cap", `{"version":1,"limits":{"timeout":"6m"}}`, "exceeds the hard cap"},
		{"timeout invalid", `{"version":1,"limits":{"timeout":"not-a-duration"}}`, "invalid duration"},
		{"timeout zero", `{"version":1,"limits":{"timeout":"0s"}}`, "must be positive"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			expectDecodeError(t, FormatJSON, tc.json, tc.want)
		})
	}
}

func TestValidateLimitsWithinCapsAccepted(t *testing.T) {
	mustDecode(t, FormatJSON, `{"version":1,"limits":{"maxFiles":200000,"maxCallDepth":128,"timeout":"5m"}}`)
}

func TestValidateOpenAPISecuritySchemes(t *testing.T) {
	for _, tc := range []struct {
		name string
		json string
		want string
	}{
		{
			"http missing scheme",
			`{"version":1,"openapi":{"securitySchemes":{"bearerAuth":{"type":"http"}}}}`,
			"requires \"scheme\"",
		},
		{
			"apiKey missing name",
			`{"version":1,"openapi":{"securitySchemes":{"key":{"type":"apiKey","in":"header"}}}}`,
			"requires \"name\"",
		},
		{
			"apiKey invalid in",
			`{"version":1,"openapi":{"securitySchemes":{"key":{"type":"apiKey","name":"X-Api-Key","in":"body"}}}}`,
			"header",
		},
		{
			"oauth2 missing flows",
			`{"version":1,"openapi":{"securitySchemes":{"oauth":{"type":"oauth2"}}}}`,
			"requires \"flows\"",
		},
		{
			"openIdConnect insecure url",
			`{"version":1,"openapi":{"securitySchemes":{"oidc":{"type":"openIdConnect","openIdConnectUrl":"http://example.com"}}}}`,
			"https://",
		},
		{
			"unknown type",
			`{"version":1,"openapi":{"securitySchemes":{"x":{"type":"carrier-pigeon"}}}}`,
			"type must be",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			expectDecodeError(t, FormatJSON, tc.json, tc.want)
		})
	}
}

func TestValidateOpenAPISecuritySchemesAccepted(t *testing.T) {
	mustDecode(t, FormatJSON, `{"version":1,"openapi":{"securitySchemes":{
		"bearerAuth": {"type":"http","scheme":"bearer","bearerFormat":"JWT"},
		"apiKey": {"type":"apiKey","name":"X-Api-Key","in":"header"},
		"oauth": {"type":"oauth2","flows":{}},
		"oidc": {"type":"openIdConnect","openIdConnectUrl":"https://example.com/.well-known/openid-configuration"}
	}}}`)
}

func TestValidateFleetAllowedRemoteHosts(t *testing.T) {
	for _, tc := range []struct {
		name string
		json string
		want string
	}{
		{
			"scheme in host",
			`{"version":1,"fleet":{"allowedRemoteHosts":[{"host":"https://github.com"}]}}`,
			"bare hostname",
		},
		{
			"port in host",
			`{"version":1,"fleet":{"allowedRemoteHosts":[{"host":"github.com:443"}]}}`,
			"bare hostname",
		},
		{
			"path in host",
			`{"version":1,"fleet":{"allowedRemoteHosts":[{"host":"github.com/example"}]}}`,
			"bare hostname",
		},
		{
			"duplicate host",
			`{"version":1,"fleet":{"allowedRemoteHosts":[{"host":"github.com"},{"host":"github.com"}]}}`,
			"duplicate host",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			expectDecodeError(t, FormatJSON, tc.json, tc.want)
		})
	}
}

func TestValidateFleetAllowedRemoteHostsAccepted(t *testing.T) {
	cfg := mustDecode(t, FormatJSON, `{"version":1,"fleet":{"allowedRemoteHosts":[
		{"host":"github.com","tokenEnv":"GIN_RECON_GITHUB_TOKEN"},
		{"host":"gitlab.example.com"}
	]}}`)
	if len(cfg.Fleet.AllowedRemoteHosts) != 2 {
		t.Fatalf("AllowedRemoteHosts = %+v", cfg.Fleet.AllowedRemoteHosts)
	}
	if cfg.Fleet.AllowedRemoteHosts[0].TokenEnv != "GIN_RECON_GITHUB_TOKEN" {
		t.Errorf("TokenEnv = %q", cfg.Fleet.AllowedRemoteHosts[0].TokenEnv)
	}
}

func TestValidateReportsAllErrorsNotJustFirst(t *testing.T) {
	_, err := Decode(FormatJSON, []byte(`{
		"version": 2,
		"acceptedPublic": ["bad-entry"],
		"authMiddleware": {"": {}}
	}`))
	if err == nil {
		t.Fatal("expected error")
	}
	for _, want := range []string{"version", "METHOD /path", "must not be empty"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("joined error %q missing expected substring %q", err.Error(), want)
		}
	}
}
