// Package cli implements gin-recon's command-line contract
// (docs/cli-contract.md): argument parsing, cross-field validation, and exit
// codes. Parsing logic is centralized here and unit-tested directly, per
// ADR 0002's "each option has one definition and command applicability is
// tested"; cmd/gin-recon is a thin wrapper that calls Parse and dispatches.
package cli

import (
	"time"

	"github.com/sagnikhaldar/gin-recon/internal/model"
)

// Command is the first positional argument.
type Command string

const (
	CommandInventory   Command = "inventory"
	CommandAudit       Command = "audit"
	CommandSuggestAuth Command = "suggest-auth"
	CommandSchema      Command = "schema"
	CommandRender      Command = "render"
	CommandFleet       Command = "fleet"
)

// OutputFormat is one --format value. This is deliberately a separate type
// from config.Format (which selects the *configuration* file's JSON/YAML
// syntax) — the two are unrelated axes that happen to share the word
// "format".
type OutputFormat string

const (
	FormatPretty  OutputFormat = "pretty"
	FormatJSON    OutputFormat = "json"
	FormatMD      OutputFormat = "md"
	FormatOpenAPI OutputFormat = "openapi"
	FormatSARIF   OutputFormat = "sarif"
)

// SchemaKind selects which document `schema` emits.
type SchemaKind string

const (
	SchemaKindReport SchemaKind = "report"
	SchemaKindConfig SchemaKind = "config"
)

// Exit codes, per docs/cli-contract.md and docs/report-contract.md.
const (
	ExitSuccess          = 0
	ExitOperationalError = 1
	ExitGate             = 2
)

// Options is the fully parsed, but not yet filesystem-validated, command
// line. Parse populates it; Validate (validate.go) checks cross-field rules,
// applicability, and path containment.
type Options struct {
	Command Command

	// Common to inventory, audit, and suggest-auth.
	Src            string
	Profile        model.AnalysisProfile
	ConfigPath     string
	Include        []string
	Exclude        []string
	IgnoreFile     string // resolved value; "none" sentinel means disabled
	IncludeTests   bool
	GOOS           string
	GOARCH         string
	Tags           []string
	Workspace      string // "off" or an explicit path
	ModuleMode     model.ModuleMode
	AllowDownloads bool
	Timeout        time.Duration

	// inventory and audit only.
	Formats  []OutputFormat
	OutDir   string
	Force    bool
	Baseline string
	FailOn   []string

	// schema only.
	SchemaKind SchemaKind

	// render only. render reuses Formats/OutDir/Force/ConfigPath above (same
	// semantics as inventory/audit per docs/adr/0016-render-command-decouples-formatting-from-analysis.md)
	// but has no --src/--profile/--include/etc. of its own, since it never
	// runs analysis — it only ever reads the one file named by --report (and,
	// if given, --config).
	ReportPath string

	// fleet only (docs/adr/0018-fleet-scanning.md): orchestrates one `audit`
	// subprocess per target named in TargetsPath's manifest. Reuses
	// ConfigPath, Formats, OutDir, Force, and FailOn above — a fleet run's
	// shared config and format selection apply identically to every target,
	// and FailOn's "incomplete" selector extends naturally to "the fleet
	// aggregate isn't complete" rather than needing a fleet-specific gate
	// vocabulary.
	TargetsPath        string
	Concurrency        int
	Resume             bool
	AllowRemoteTargets bool

	// fleet --org only (docs/adr/0021-fleet-org-enumeration.md): an
	// alternative to TargetsPath that populates the same manifest shape by
	// enumerating a GitHub organization instead of reading a hand-written
	// file. Exactly one of TargetsPath/Org is required.
	Org             string
	MaxRepos        int
	IncludeArchived bool
	IncludeForks    bool

	// ExplicitFlags records which flag names the user actually passed on the
	// command line, as opposed to a field merely holding its default value
	// (e.g. GOOS defaults to runtime.GOOS, indistinguishable from an
	// explicit "--goos <the-running-tool's-own-GOOS>" without this). Needed
	// so a caller layering config file values on top of parsed Options (per
	// docs/configuration-contract.md: "Scalar CLI values override
	// configuration") can tell "the user asked for this on the command
	// line" apart from "this field just has its zero-value default," which
	// the Options struct alone cannot express once Parse has already
	// applied every default.
	ExplicitFlags map[string]bool
}

// DefaultIgnoreFile is the CLI's default --ignore-file value.
const DefaultIgnoreFile = ".gin-reconignore"

// DefaultTimeout is the CLI's default --timeout value.
const DefaultTimeout = 30 * time.Second
