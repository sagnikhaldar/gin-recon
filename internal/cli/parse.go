package cli

import (
	"flag"
	"fmt"
	"runtime"
	"strconv"
	"time"

	"github.com/sagnikhaldar/gin-recon/internal/model"
)

// Parse parses a full argument list (not including the program name, e.g.
// os.Args[1:]) into Options. It returns an error for anything
// docs/cli-contract.md says must fail before analysis: an unknown command,
// an unknown or inapplicable option for the given command, a duplicate
// scalar option, a missing value, or a malformed duration. Parse does not
// touch the filesystem — see Validate for path resolution and containment
// checks, which are a separate concern from syntax.
func Parse(args []string) (*Options, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("missing command: expected one of inventory, audit, suggest-auth, schema, render, fleet")
	}

	cmd := Command(args[0])
	rest := args[1:]

	switch cmd {
	case CommandInventory, CommandAudit, CommandSuggestAuth:
		return parseScanCommand(cmd, rest)
	case CommandRender:
		return parseRender(rest)
	case CommandSchema:
		return parseSchema(rest)
	case CommandFleet:
		return parseFleet(rest)
	case "-h", "--help", "-help":
		return nil, flag.ErrHelp
	default:
		return nil, fmt.Errorf("unknown command %q: expected one of inventory, audit, suggest-auth, schema, render, fleet", cmd)
	}
}

// parseScanCommand handles inventory, audit, and suggest-auth, which share
// every common option. --out/--force additionally apply to suggest-auth
// (docs/cli-contract.md: "suggest-auth writes JSON to stdout unless --out is
// supplied"), but --format does not — suggest-auth's output has no format
// choice to make. --baseline/--fail-on remain audit-only. suggest-auth
// explicitly does not register --format/--baseline/--fail-on, per
// docs/cli-contract.md ("does not accept baseline, fail-on, SARIF, or
// OpenAPI options") — they are simply never defined on its FlagSet, so the
// flag package's own "flag provided but not defined" error enforces
// inapplicability for us.
func parseScanCommand(cmd Command, args []string) (*Options, error) {
	fs := flag.NewFlagSet(string(cmd), flag.ContinueOnError)
	fs.SetOutput(discardWriter{})

	opts := &Options{
		Command:    cmd,
		Src:        ".",
		Profile:    model.ProfileTyped,
		IgnoreFile: DefaultIgnoreFile,
		Timeout:    DefaultTimeout,
		GOOS:       runtime.GOOS,
		GOARCH:     runtime.GOARCH,
		Workspace:  "off",
	}

	var profile, ignoreFile, workspace, moduleMode, timeout string
	registerOnceString(fs, "src", &opts.Src)
	registerOnceString(fs, "profile", &profile)
	registerOnceString(fs, "config", &opts.ConfigPath)
	fs.Var(&repeatableList{&opts.Include}, "include", "repeatable root-relative include glob")
	fs.Var(&repeatableList{&opts.Exclude}, "exclude", "repeatable root-relative exclude glob")
	registerOnceString(fs, "ignore-file", &ignoreFile)
	registerOnceBool(fs, "include-tests", &opts.IncludeTests)
	registerOnceString(fs, "goos", &opts.GOOS)
	registerOnceString(fs, "goarch", &opts.GOARCH)
	fs.Var(&repeatableList{&opts.Tags}, "tags", "comma-separated build tags")
	registerOnceString(fs, "workspace", &workspace)
	registerOnceString(fs, "module-mode", &moduleMode)
	registerOnceBool(fs, "allow-downloads", &opts.AllowDownloads)
	registerOnceString(fs, "timeout", &timeout)

	var formats []string
	if cmd == CommandInventory || cmd == CommandAudit {
		fs.Var(&repeatableList{&formats}, "format", "repeatable or comma-separated output format")
	}
	// --out/--force apply to suggest-auth too (docs/cli-contract.md:
	// "suggest-auth writes JSON to stdout unless --out is supplied") — only
	// --format is inventory/audit-only, since suggest-auth's output has no
	// format choice to make (always JSON).
	if cmd == CommandInventory || cmd == CommandAudit || cmd == CommandSuggestAuth {
		registerOnceString(fs, "out", &opts.OutDir)
		registerOnceBool(fs, "force", &opts.Force)
	}
	if cmd == CommandAudit {
		registerOnceString(fs, "baseline", &opts.Baseline)
		fs.Var(&repeatableList{&opts.FailOn}, "fail-on", "repeatable or comma-separated gate selector")
	}

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("%s: unexpected positional argument %q", cmd, fs.Arg(0))
	}

	opts.ExplicitFlags = map[string]bool{}
	fs.Visit(func(f *flag.Flag) { opts.ExplicitFlags[f.Name] = true })

	if profile != "" {
		opts.Profile = model.AnalysisProfile(profile)
	}
	if ignoreFile != "" {
		opts.IgnoreFile = ignoreFile
	}
	if workspace != "" {
		opts.Workspace = workspace
	}
	if moduleMode != "" {
		opts.ModuleMode = model.ModuleMode(moduleMode)
	}
	if timeout != "" {
		d, err := time.ParseDuration(timeout)
		if err != nil {
			return nil, fmt.Errorf("--timeout: invalid duration %q: %w", timeout, err)
		}
		opts.Timeout = d
	}
	for _, f := range formats {
		opts.Formats = append(opts.Formats, OutputFormat(f))
	}
	if len(opts.Formats) == 0 {
		opts.Formats = []OutputFormat{FormatPretty}
	}

	return opts, nil
}

// parseRender handles render, per
// docs/adr/0016-render-command-decouples-formatting-from-analysis.md: its
// only inputs are --report (the document to reformat), --format/--out/--force
// (identical semantics to inventory/audit's own), and --config (applied only
// to what the formatting layer itself reads). render registers none of
// inventory/audit's scan/analysis flags (--src, --profile, --include, etc.)
// at all — it never runs analysis, so there is nothing for them to configure.
func parseRender(args []string) (*Options, error) {
	fs := flag.NewFlagSet(string(CommandRender), flag.ContinueOnError)
	fs.SetOutput(discardWriter{})

	opts := &Options{Command: CommandRender}

	registerOnceString(fs, "report", &opts.ReportPath)
	registerOnceString(fs, "config", &opts.ConfigPath)
	registerOnceString(fs, "out", &opts.OutDir)
	registerOnceBool(fs, "force", &opts.Force)
	var formats []string
	fs.Var(&repeatableList{&formats}, "format", "repeatable or comma-separated output format")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("%s: unexpected positional argument %q", CommandRender, fs.Arg(0))
	}

	opts.ExplicitFlags = map[string]bool{}
	fs.Visit(func(f *flag.Flag) { opts.ExplicitFlags[f.Name] = true })

	for _, f := range formats {
		opts.Formats = append(opts.Formats, OutputFormat(f))
	}
	if len(opts.Formats) == 0 {
		opts.Formats = []OutputFormat{FormatPretty}
	}

	return opts, nil
}

// parseFleet handles fleet, per docs/adr/0018-fleet-scanning.md: its inputs
// are --targets (the manifest naming each local target), --config (shared
// across every target's own audit subprocess), --format/--out/--force
// (identical semantics to audit's own), --fail-on (fleet-level selectors
// only — Validate restricts this to "incomplete"), --concurrency, and
// --resume. It registers none of audit's --src/--profile/--include/etc.:
// each target supplies its own --src, resolved from the manifest, not from
// a single flag on this command.
func parseFleet(args []string) (*Options, error) {
	fs := flag.NewFlagSet(string(CommandFleet), flag.ContinueOnError)
	fs.SetOutput(discardWriter{})

	opts := &Options{Command: CommandFleet, Concurrency: 1}

	registerOnceString(fs, "targets", &opts.TargetsPath)
	registerOnceString(fs, "org", &opts.Org)
	registerOnceString(fs, "config", &opts.ConfigPath)
	registerOnceString(fs, "out", &opts.OutDir)
	registerOnceBool(fs, "force", &opts.Force)
	registerOnceBool(fs, "resume", &opts.Resume)
	registerOnceString(fs, "baseline", &opts.Baseline)
	registerOnceBool(fs, "allow-remote-targets", &opts.AllowRemoteTargets)
	registerOnceBool(fs, "allow-downloads", &opts.AllowDownloads)
	registerOnceBool(fs, "include-archived", &opts.IncludeArchived)
	registerOnceBool(fs, "include-forks", &opts.IncludeForks)
	fs.Var(&repeatableList{&opts.RepoInclude}, "repo-include", "repeatable or comma-separated repository name glob")
	fs.Var(&repeatableList{&opts.RepoExclude}, "repo-exclude", "repeatable or comma-separated repository name glob")
	var concurrency, maxRepos string
	registerOnceString(fs, "concurrency", &concurrency)
	registerOnceString(fs, "max-repos", &maxRepos)
	fs.Var(&repeatableList{&opts.FailOn}, "fail-on", "repeatable or comma-separated gate selector")
	var formats []string
	fs.Var(&repeatableList{&formats}, "format", "repeatable or comma-separated output format")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("%s: unexpected positional argument %q", CommandFleet, fs.Arg(0))
	}

	opts.ExplicitFlags = map[string]bool{}
	fs.Visit(func(f *flag.Flag) { opts.ExplicitFlags[f.Name] = true })

	if concurrency != "" {
		n, err := strconv.Atoi(concurrency)
		if err != nil {
			return nil, fmt.Errorf("--concurrency: invalid integer %q", concurrency)
		}
		opts.Concurrency = n
	}
	if maxRepos != "" {
		n, err := strconv.Atoi(maxRepos)
		if err != nil {
			return nil, fmt.Errorf("--max-repos: invalid integer %q", maxRepos)
		}
		opts.MaxRepos = n
	}
	for _, f := range formats {
		opts.Formats = append(opts.Formats, OutputFormat(f))
	}
	if len(opts.Formats) == 0 {
		opts.Formats = []OutputFormat{FormatJSON}
	}

	return opts, nil
}

func parseSchema(args []string) (*Options, error) {
	fs := flag.NewFlagSet(string(CommandSchema), flag.ContinueOnError)
	fs.SetOutput(discardWriter{})

	var kind string
	registerOnceString(fs, "kind", &kind)

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("schema: unexpected positional argument %q", fs.Arg(0))
	}

	opts := &Options{Command: CommandSchema, SchemaKind: SchemaKindReport}
	if kind != "" {
		opts.SchemaKind = SchemaKind(kind)
	}
	return opts, nil
}

func registerOnceString(fs *flag.FlagSet, name string, dest *string) {
	fs.Var(&onceString{name: name, val: dest}, name, "")
}

func registerOnceBool(fs *flag.FlagSet, name string, dest *bool) {
	fs.Var(&onceBool{name: name, val: dest}, name, "")
}

// discardWriter silences flag.FlagSet's default "usage" printing to stderr on
// parse errors; Parse's caller (cmd/gin-recon) is responsible for presenting
// errors, so the package stays silent and just returns them.
type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }
