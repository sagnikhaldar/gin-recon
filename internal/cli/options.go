// Package cli implements gin-recon's command-line contract
// (docs/reference.md): argument parsing, cross-field validation, and exit
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
	SchemaKindReport     SchemaKind = "report"
	SchemaKindConfig     SchemaKind = "config"
	SchemaKindFleet      SchemaKind = "fleet"
	SchemaKindFleetDelta SchemaKind = "fleet-delta"
)

// Exit codes, per docs/reference.md and docs/reference.md.
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
	RepoAttempts       int
	RepoTimeout        time.Duration
	FleetTimeout       time.Duration
	ProgressMode       string

	// RenderHTML is fleet-only (docs/adr/0037-fleet-html-opt-in.md): off by
	// default. fleet.html was previously an unconditional companion to
	// every fleet.json (ADR-0020); a fleet run's own job is now just the
	// raw scan — rendering it into fleet.html is a separate, explicit
	// decision the caller opts into, the same way `render` already treats
	// a saved fleet.json rather than something fleet decides for them.
	RenderHTML bool

	// SuggestAuth is fleet-only: off by default. When set, every
	// successfully-scanned target also runs `suggest-auth`
	// (docs/reference.md), and fleet writes fleet-auth-candidates.json — a
	// single, org-wide ranked authMiddleware candidate list aggregated
	// across every target, so building a reviewed authMiddleware config for
	// a whole organization doesn't mean running suggest-auth by hand against
	// hundreds of repositories one at a time. Never affects classification,
	// same as suggest-auth itself: still purely candidates for a human/AI
	// reviewer, never auto-applied.
	SuggestAuth bool

	// UseTargetConfig is fleet-only (docs/adr/0031-fleet-per-target-config.md):
	// off by default, the same "capability switch, off unless asked"
	// posture AllowRemoteTargets/AllowDownloads already use for a trust
	// boundary this wide. When set, a target whose own source tree commits
	// a conventional per-target config file uses it instead of ConfigPath
	// for that target only — real evidence a human already reviewed and
	// committed for that one repository specifically, not something gin-recon
	// invents. Without it, fleet behaves exactly as before: ConfigPath only.
	UseTargetConfig bool

	// TargetConfigDir is fleet-only (docs/adr/0033-fleet-target-config-dir.md):
	// a local, operator-owned directory holding one config file per target
	// (<dir>/<target-name>.json), entirely outside every scanned
	// repository. Takes precedence over both UseTargetConfig's
	// repository-embedded file and ConfigPath for a target it has an entry
	// for. Solves the same "give this one target its own real auth
	// evidence" need UseTargetConfig does, without requiring that evidence
	// ever be committed into the target's own repository — no PR, no
	// merge, no risk to a production branch, and a strictly stronger trust
	// story (the scanned repository can never supply its own "proof").
	TargetConfigDir string

	// fleet --org only (docs/adr/0021-fleet-org-enumeration.md): an
	// alternative to TargetsPath that populates the same manifest shape by
	// enumerating a GitHub organization instead of reading a hand-written
	// file. Exactly one of TargetsPath/Org/Repo is required.
	Org             string
	MaxRepos        int
	IncludeArchived bool
	IncludeForks    bool
	RepoInclude     []string
	RepoExclude     []string

	// Repo/Ref are fleet-only (docs/adr/0038-fleet-repo-shorthand.md): a
	// third alternative to TargetsPath/Org for the common case of auditing
	// exactly one remote repository, without hand-writing a one-target
	// manifest file first. Repo is either "owner/name" (expanded against
	// github.com) or a full "https://" git URL; Ref is optional and
	// defaults to the remote's own default branch, same as a --targets
	// manifest's own "git" target. Reuses --targets' entire remote-clone
	// path (ADR-0019) — --allow-remote-targets and
	// fleet.allowedRemoteHosts still gate it identically; nothing new is
	// trusted just because the manifest was built in memory instead of
	// read from a file.
	Repo string
	Ref  string

	// Update is fleet --org only (docs/adr/0039-fleet-org-update.md):
	// off by default. When set, a target whose GitHub pushedAt hasn't
	// changed since the previous complete run in the same --out reuses
	// that run's own result instead of rescanning — the same reuse
	// mechanism --resume's checkpoint already uses, just keyed off "no new
	// commits" (this run's own fresh discovery vs the last complete run's)
	// rather than "already done earlier in this same run."
	Update bool

	// ExplicitFlags records which flag names the user actually passed on the
	// command line, as opposed to a field merely holding its default value
	// (e.g. GOOS defaults to runtime.GOOS, indistinguishable from an
	// explicit "--goos <the-running-tool's-own-GOOS>" without this). Needed
	// so a caller layering config file values on top of parsed Options (per
	// docs/reference.md: "Scalar CLI values override
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
