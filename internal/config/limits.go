package config

import "time"

// Default and hard-cap values from
// docs/configuration-contract.md#resource-defaults-and-caps. Defaults are
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
