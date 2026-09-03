// Package config defines the strict, data-only configuration format
// (schema/config-1.json, docs/configuration-contract.md). Struct field names
// and JSON/YAML tags mirror the schema exactly; Decode (decode.go) and
// Validate (validate.go) are what actually enforce the contract — this file
// only defines the shape.
//
// Per ADR 0003, configuration is never executed: Decode only ever parses
// data into these types, and nothing in this package invokes Go code found
// in a configuration file.
package config

// Assurance is the reviewer-selected trust mode for a configured
// authMiddleware entry (docs/configuration-contract.md#canonical-symbols-and-assurance).
type Assurance string

const (
	AssuranceAnalyze  Assurance = "analyze"
	AssuranceAttested Assurance = "attested"
)

// AuthMiddlewareEntry is the value side of one authMiddleware canonical-symbol
// key. Assurance defaults to AssuranceAnalyze when absent — see
// Config.applyDefaults in validate.go.
type AuthMiddlewareEntry struct {
	Assurance     Assurance `json:"assurance,omitempty" yaml:"assurance,omitempty"`
	Tags          []string  `json:"tags,omitempty" yaml:"tags,omitempty"`
	Roles         []string  `json:"roles,omitempty" yaml:"roles,omitempty"`
	Scopes        []string  `json:"scopes,omitempty" yaml:"scopes,omitempty"`
	OpenAPIScheme string    `json:"openapiScheme,omitempty" yaml:"openapiScheme,omitempty"`
}

// PolicySelector narrows which routes a policy or exception applies to.
type PolicySelector struct {
	Method      []string `json:"method,omitempty" yaml:"method,omitempty"`
	Path        []string `json:"path,omitempty" yaml:"path,omitempty"`
	Status      []string `json:"status,omitempty" yaml:"status,omitempty"`
	Tag         []string `json:"tag,omitempty" yaml:"tag,omitempty"`
	Role        []string `json:"role,omitempty" yaml:"role,omitempty"`
	Scope       []string `json:"scope,omitempty" yaml:"scope,omitempty"`
	Package     []string `json:"package,omitempty" yaml:"package,omitempty"`
	SurfaceKind []string `json:"surfaceKind,omitempty" yaml:"surfaceKind,omitempty"`
}

// PolicyRequirement is a boolean composition of route requirements. All/Any/Not
// recurse; Validate bounds recursion depth by Limits.MaxCallDepth
// (docs/configuration-contract.md#policies-and-baselines).
//
// docs/configuration-contract.md's "any/all/no middleware" describes three
// distinct presence checks: MiddlewareAny requires at least one of the
// listed canonical symbols to be present, MiddlewarePresent (the "all" case)
// requires every listed symbol to be present, and MiddlewareAbsent (the "no"
// case) requires none of them to be present.
type PolicyRequirement struct {
	Auth              string              `json:"auth,omitempty" yaml:"auth,omitempty"`
	MiddlewareAny     []string            `json:"middlewareAny,omitempty" yaml:"middlewareAny,omitempty"`
	MiddlewarePresent []string            `json:"middlewarePresent,omitempty" yaml:"middlewarePresent,omitempty"`
	MiddlewareAbsent  []string            `json:"middlewareAbsent,omitempty" yaml:"middlewareAbsent,omitempty"`
	MiddlewareOrder   []string            `json:"middlewareOrder,omitempty" yaml:"middlewareOrder,omitempty"`
	AnyTag            []string            `json:"anyTag,omitempty" yaml:"anyTag,omitempty"`
	AllTags           []string            `json:"allTags,omitempty" yaml:"allTags,omitempty"`
	AnyRole           []string            `json:"anyRole,omitempty" yaml:"anyRole,omitempty"`
	AnyScope          []string            `json:"anyScope,omitempty" yaml:"anyScope,omitempty"`
	All               []PolicyRequirement `json:"all,omitempty" yaml:"all,omitempty"`
	Any               []PolicyRequirement `json:"any,omitempty" yaml:"any,omitempty"`
	Not               *PolicyRequirement  `json:"not,omitempty" yaml:"not,omitempty"`
}

// Exception is a time-bounded, reviewed carve-out from a policy. Expires must
// be a strict YYYY-MM-DD date, evaluated in UTC
// (docs/configuration-contract.md#policies-and-baselines).
type Exception struct {
	ID       string         `json:"id" yaml:"id"`
	Reason   string         `json:"reason" yaml:"reason"`
	Selector PolicySelector `json:"selector" yaml:"selector"`
	Expires  string         `json:"expires" yaml:"expires"`
}

// Policy is one deterministic audit-time rule.
type Policy struct {
	ID         string            `json:"id" yaml:"id"`
	Selector   PolicySelector    `json:"selector" yaml:"selector"`
	Require    PolicyRequirement `json:"require" yaml:"require"`
	Exceptions []Exception       `json:"exceptions,omitempty" yaml:"exceptions,omitempty"`
}

// ScanConfig controls source scope, mirroring the CLI's --include/--exclude/
// --ignore-file (docs/cli-contract.md).
type ScanConfig struct {
	Include    []string `json:"include,omitempty" yaml:"include,omitempty"`
	Exclude    []string `json:"exclude,omitempty" yaml:"exclude,omitempty"`
	IgnoreFile *string  `json:"ignoreFile,omitempty" yaml:"ignoreFile,omitempty"`
}

// AnalysisConfig controls the analysis profile and build context, mirroring
// the CLI's --profile/--goos/--goarch/--tags/--workspace/--module-mode/
// --allow-downloads (docs/cli-contract.md).
type AnalysisConfig struct {
	Profile        string   `json:"profile,omitempty" yaml:"profile,omitempty"`
	AllowDownloads bool     `json:"allowDownloads,omitempty" yaml:"allowDownloads,omitempty"`
	Workspace      string   `json:"workspace,omitempty" yaml:"workspace,omitempty"`
	ModuleMode     string   `json:"moduleMode,omitempty" yaml:"moduleMode,omitempty"`
	GOOS           string   `json:"goos,omitempty" yaml:"goos,omitempty"`
	GOARCH         string   `json:"goarch,omitempty" yaml:"goarch,omitempty"`
	Tags           []string `json:"tags,omitempty" yaml:"tags,omitempty"`

	// FollowModules is a list of Go module import-path glob patterns
	// (matched against each dependency's own module path, e.g.
	// "github.com/myorg/**") that registrar-following is explicitly
	// permitted to cross into, in addition to the target module's own
	// source. Empty by default: registrar-following never crosses a module
	// boundary unless a reviewer opts a specific set of modules in — see
	// docs/adr/0010-opt-in-cross-module-registrar-following.md for why this
	// is a deliberate trust-boundary widening, never a default behavior,
	// and docs/threat-model.md for what it does and does not change about
	// which code's evidence gin-recon trusts.
	FollowModules []string `json:"followModules,omitempty" yaml:"followModules,omitempty"`
}

// LimitsConfig overrides resource defaults, bounded by hard caps that
// configuration can never exceed (docs/configuration-contract.md#resource-defaults-and-caps).
// Every field is a pointer so "absent" (use the documented default) is
// distinguishable from "explicitly zero" (always invalid per that doc) —
// a plain int field would conflate the two and silently apply the default to
// a user's explicit, invalid zero instead of rejecting it.
type LimitsConfig struct {
	Timeout        *string `json:"timeout,omitempty" yaml:"timeout,omitempty"`
	MaxFiles       *int    `json:"maxFiles,omitempty" yaml:"maxFiles,omitempty"`
	MaxPackages    *int    `json:"maxPackages,omitempty" yaml:"maxPackages,omitempty"`
	MaxFileBytes   *int    `json:"maxFileBytes,omitempty" yaml:"maxFileBytes,omitempty"`
	MaxDiagnostics *int    `json:"maxDiagnostics,omitempty" yaml:"maxDiagnostics,omitempty"`
	MaxOutputBytes *int    `json:"maxOutputBytes,omitempty" yaml:"maxOutputBytes,omitempty"`
	MaxCallDepth   *int    `json:"maxCallDepth,omitempty" yaml:"maxCallDepth,omitempty"`
}

// SecurityScheme mirrors one OpenAPI 3.1 security scheme. Which fields are
// required depends on Type — see Validate.
type SecurityScheme struct {
	Type             string         `json:"type" yaml:"type"`
	Scheme           string         `json:"scheme,omitempty" yaml:"scheme,omitempty"`
	BearerFormat     string         `json:"bearerFormat,omitempty" yaml:"bearerFormat,omitempty"`
	Name             string         `json:"name,omitempty" yaml:"name,omitempty"`
	In               string         `json:"in,omitempty" yaml:"in,omitempty"`
	OpenIDConnectURL string         `json:"openIdConnectUrl,omitempty" yaml:"openIdConnectUrl,omitempty"`
	Flows            map[string]any `json:"flows,omitempty" yaml:"flows,omitempty"`
}

// OpenAPIConfig seeds document metadata and security schemes for `--format
// openapi` (docs/openapi-strategy.md).
type OpenAPIConfig struct {
	Title           string                    `json:"title,omitempty" yaml:"title,omitempty"`
	Version         string                    `json:"version,omitempty" yaml:"version,omitempty"`
	SecuritySchemes map[string]SecurityScheme `json:"securitySchemes,omitempty" yaml:"securitySchemes,omitempty"`
}

// RemoteHost is one entry in fleet.allowedRemoteHosts: an exact hostname a
// `fleet --allow-remote-targets` run is permitted to clone from, and
// optionally which environment variable holds a token for it
// (docs/adr/0019-fleet-remote-targets.md). TokenEnv names a variable, never
// a credential value — the value itself is resolved from the environment at
// clone time, not stored in this reviewed, shared config file.
type RemoteHost struct {
	Host     string `json:"host" yaml:"host"`
	TokenEnv string `json:"tokenEnv,omitempty" yaml:"tokenEnv,omitempty"`
}

// FleetConfig scopes what a `fleet` run's remote targets may reach.
// AllowedRemoteHosts is empty by default: matching every other
// trust-widening setting in this package (authMiddleware, followModules,
// securitySchemes), no host is ever reachable unless a reviewer names it
// here — the `--allow-remote-targets` CLI flag only ever unlocks the
// capability, never the scope (docs/adr/0019-fleet-remote-targets.md).
type FleetConfig struct {
	AllowedRemoteHosts []RemoteHost `json:"allowedRemoteHosts,omitempty" yaml:"allowedRemoteHosts,omitempty"`
}

// Config is the strict, data-only root object (schema/config-1.json).
// Construct it only via Decode, never by hand-populating a zero value and
// skipping validation — see decode.go.
type Config struct {
	Version        int                            `json:"version" yaml:"version"`
	AuthMiddleware map[string]AuthMiddlewareEntry `json:"authMiddleware,omitempty" yaml:"authMiddleware,omitempty"`
	AuthWrappers   []string                       `json:"authWrappers,omitempty" yaml:"authWrappers,omitempty"`
	AcceptedPublic []string                       `json:"acceptedPublic,omitempty" yaml:"acceptedPublic,omitempty"`
	Policies       []Policy                       `json:"policies,omitempty" yaml:"policies,omitempty"`
	Scan           *ScanConfig                    `json:"scan,omitempty" yaml:"scan,omitempty"`
	Analysis       *AnalysisConfig                `json:"analysis,omitempty" yaml:"analysis,omitempty"`
	Limits         *LimitsConfig                  `json:"limits,omitempty" yaml:"limits,omitempty"`
	OpenAPI        *OpenAPIConfig                 `json:"openapi,omitempty" yaml:"openapi,omitempty"`
	Fleet          *FleetConfig                   `json:"fleet,omitempty" yaml:"fleet,omitempty"`
}
