package config

import "time"

// Default and hard-cap values from
// docs/reference.md#resource-defaults-and-caps. Defaults are
// what an absent field resolves to; hard caps are the maximum a configured
// value may ever request, regardless of what the target repository's own
// configuration asks for.
const (
	DefaultTimeout        = 30 * time.Second
	DefaultMaxFiles       = 20000
	DefaultMaxPackages    = 5000
	DefaultMaxFileBytes   = 2097152
	DefaultMaxDiagnostics = 1000
	DefaultMaxOutputBytes = 26214400
	DefaultMaxCallDepth   = 32

	HardCapTimeout        = 5 * time.Minute
	HardCapMaxFiles       = 200000
	HardCapMaxPackages    = 20000
	HardCapMaxFileBytes   = 20971520
	HardCapMaxDiagnostics = 10000
	HardCapMaxOutputBytes = 104857600
	HardCapMaxCallDepth   = 128
)

// ResolvedLimits is LimitsConfig with every default applied and every hard
// cap already enforced. Analyzer/CLI code should consume this, not
// LimitsConfig directly, so a nil-vs-zero mistake can't reintroduce the bug
// LimitsConfig's pointer fields exist to prevent.
type ResolvedLimits struct {
	Timeout        time.Duration
	MaxFiles       int
	MaxPackages    int
	MaxFileBytes   int
	MaxDiagnostics int
	MaxOutputBytes int
	MaxCallDepth   int
}

// DefaultResolvedLimits is ResolvedLimits with every field at its documented
// default, for use when no LimitsConfig was supplied at all.
func DefaultResolvedLimits() ResolvedLimits {
	return ResolvedLimits{
		Timeout:        DefaultTimeout,
		MaxFiles:       DefaultMaxFiles,
		MaxPackages:    DefaultMaxPackages,
		MaxFileBytes:   DefaultMaxFileBytes,
		MaxDiagnostics: DefaultMaxDiagnostics,
		MaxOutputBytes: DefaultMaxOutputBytes,
		MaxCallDepth:   DefaultMaxCallDepth,
	}
}

// Resolve merges l (a possibly-nil *LimitsConfig, itself possibly holding
// only some fields — see LimitsConfig's own doc comment) onto
// DefaultResolvedLimits, filling every unset field with its documented
// default. Assumes l already passed validateLimits (Config.Validate calls
// it), so every set field is already within its hard cap and every duration
// string already parses — Resolve itself does not re-validate, only merges.
func (l *LimitsConfig) Resolve() ResolvedLimits {
	r := DefaultResolvedLimits()
	if l == nil {
		return r
	}
	if l.Timeout != nil {
		if d, err := time.ParseDuration(*l.Timeout); err == nil {
			r.Timeout = d
		}
	}
	if l.MaxFiles != nil {
		r.MaxFiles = *l.MaxFiles
	}
	if l.MaxPackages != nil {
		r.MaxPackages = *l.MaxPackages
	}
	if l.MaxFileBytes != nil {
		r.MaxFileBytes = *l.MaxFileBytes
	}
	if l.MaxDiagnostics != nil {
		r.MaxDiagnostics = *l.MaxDiagnostics
	}
	if l.MaxOutputBytes != nil {
		r.MaxOutputBytes = *l.MaxOutputBytes
	}
	if l.MaxCallDepth != nil {
		r.MaxCallDepth = *l.MaxCallDepth
	}
	return r
}
