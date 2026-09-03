// Command gin-recon is the CLI entry point (docs/reference.md). main
// itself only wires argument parsing, dispatch, and exit codes; all real
// logic lives in internal packages so it can be unit-tested without
// spawning a process.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sagnikhaldar/gin-recon/internal/analyzer"
	"github.com/sagnikhaldar/gin-recon/internal/cli"
	"github.com/sagnikhaldar/gin-recon/internal/compare"
	"github.com/sagnikhaldar/gin-recon/internal/config"
	"github.com/sagnikhaldar/gin-recon/internal/fleet"
	"github.com/sagnikhaldar/gin-recon/internal/format"
	"github.com/sagnikhaldar/gin-recon/internal/model"
	"github.com/sagnikhaldar/gin-recon/internal/report"
	"github.com/sagnikhaldar/gin-recon/schema"
)

// formatsImplemented are the --format values renderReport can actually
// produce — every format cli.Validate allows through is implemented.
// FormatSARIF's command restriction (audit-only) is enforced entirely by
// cli.Validate before this point is ever reached, not by this map.
var formatsImplemented = map[cli.OutputFormat]bool{
	cli.FormatPretty:  true,
	cli.FormatJSON:    true,
	cli.FormatOpenAPI: true,
	cli.FormatMD:      true,
	cli.FormatSARIF:   true,
}

// implementedFormatsMessage is the exact list quoted back in "not
// implemented yet" errors, kept in one place so it can't drift out of sync
// with formatsImplemented.
const implementedFormatsMessage = `"json", "pretty", "openapi", "md", and "sarif" are available so far`

// htmlCompanionFilename is api.html's fixed name. It is not a selectable
// --format value — html is not a distinct report representation, it is the
// same OpenAPI document format.OpenAPI produces, rendered as a browsable
// page. Requesting it separately would let it drift out of sync with
// openapi.json (mismatched routes, or the pair only partially regenerated);
// writeReport instead always emits it as openapi's fixed companion file
// whenever there is a directory to put it in.
const htmlCompanionFilename = "api.html"

// formatFilename returns the --out filename for one format, per
// docs/cli-contract.md: "Files are routes.json, routes.md, openapi.json,
// api.html, results.sarif, and routes.txt."
func formatFilename(f cli.OutputFormat) string {
	switch f {
	case cli.FormatJSON:
		return "routes.json"
	case cli.FormatMD:
		return "routes.md"
	case cli.FormatOpenAPI:
		return "openapi.json"
	case cli.FormatSARIF:
		return "results.sarif"
	default:
		return "routes.txt" // pretty
	}
}

// renderReport renders rep in format f. The returned diagnostics are
// discovered only during formatting (currently only possible for
// FormatOpenAPI — see format.OpenAPI's doc comment) and are always empty for
// every other format; callers must surface them separately since they cannot
// be folded into rep.Diagnostics after the fact.
func renderReport(rep *report.Report, f cli.OutputFormat, cfg *config.Config) ([]byte, []model.Diagnostic, error) {
	switch f {
	case cli.FormatJSON:
		data, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			return nil, nil, err
		}
		return append(data, '\n'), nil, nil
	case cli.FormatPretty:
		var buf bytes.Buffer
		if err := format.Pretty(&buf, rep); err != nil {
			return nil, nil, err
		}
		return buf.Bytes(), nil, nil
	case cli.FormatOpenAPI:
		data, diags, err := format.OpenAPI(rep, cfg)
		if err != nil {
			return nil, nil, err
		}
		return data, diags, nil
	case cli.FormatMD:
		var buf bytes.Buffer
		if err := format.Markdown(&buf, rep); err != nil {
			return nil, nil, err
		}
		return buf.Bytes(), nil, nil
	case cli.FormatSARIF:
		data, err := format.SARIF(rep)
		if err != nil {
			return nil, nil, err
		}
		return data, nil, nil
	default:
		return nil, nil, fmt.Errorf("--format %s is not implemented yet", f)
	}
}

// printFormatDiagnostics writes format-time diagnostics (docs/cli-contract.md:
// "warnings and diagnostics intended for humans go to stderr") as one line
// each, never mixed into the stdout report content.
func printFormatDiagnostics(stderr io.Writer, f cli.OutputFormat, diags []model.Diagnostic) {
	for _, d := range diags {
		if d.Source != nil {
			fmt.Fprintf(stderr, "gin-recon: %s: %s [%s] (%s)\n", f, d.Message, d.Code, sourceLabel(d.Source))
		} else {
			fmt.Fprintf(stderr, "gin-recon: %s: %s [%s]\n", f, d.Message, d.Code)
		}
	}
}

// sourceLabel formats a model.Source as file:line, or just file when no line
// is available.
func sourceLabel(s *model.Source) string {
	if s.Line != nil {
		return fmt.Sprintf("%s:%d", s.File, *s.Line)
	}
	return s.File
}

// renderedFile is one file writeReport will place under --out: a name and
// its rendered bytes. A plain slice (rather than the map[OutputFormat][]byte
// this replaced) is what lets api.html — openapi's fixed companion file,
// not itself a --format value — sit alongside the format-keyed entries.
type renderedFile struct {
	name string
	data []byte
}

// writeReport renders rep in every requested format and writes it either to
// stdout (exactly one format, no --out — cli.Validate guarantees this
// combination when --out is absent) or to per-format files under --out.
// successExitCode is returned when writing succeeds — runAudit passes
// cli.ExitGate here when a --fail-on selector matched, since the report
// still needs to be written before the process exits nonzero.
func writeReport(rep *report.Report, opts *cli.Options, cfg *config.Config, stdout, stderr io.Writer, successExitCode int) int {
	if opts.OutDir == "" {
		data, diags, err := renderReport(rep, opts.Formats[0], cfg)
		if err != nil {
			fmt.Fprintf(stderr, "gin-recon: %v\n", err)
			return cli.ExitOperationalError
		}
		printFormatDiagnostics(stderr, opts.Formats[0], diags)
		if _, err := stdout.Write(data); err != nil {
			fmt.Fprintf(stderr, "gin-recon: writing report: %v\n", err)
			return cli.ExitOperationalError
		}
		return successExitCode
	}

	var files []renderedFile
	for _, f := range opts.Formats {
		data, diags, err := renderReport(rep, f, cfg)
		if err != nil {
			fmt.Fprintf(stderr, "gin-recon: %v\n", err)
			return cli.ExitOperationalError
		}
		printFormatDiagnostics(stderr, f, diags)
		files = append(files, renderedFile{formatFilename(f), data})

		if f == cli.FormatOpenAPI {
			// api.html renders the exact same document just built above, so
			// its diagnostics are identical to what printFormatDiagnostics
			// already printed for "openapi" — printing them again under a
			// second label would just be noise about the same evidence.
			htmlData, _, err := format.HTML(rep, cfg)
			if err != nil {
				fmt.Fprintf(stderr, "gin-recon: %v\n", err)
				return cli.ExitOperationalError
			}
			files = append(files, renderedFile{htmlCompanionFilename, htmlData})
		}
	}
	if !opts.Force {
		for _, rf := range files {
			outPath := filepath.Join(opts.OutDir, rf.name)
			if _, err := os.Stat(outPath); err == nil {
				fmt.Fprintf(stderr, "gin-recon: %s already exists; pass --force to overwrite\n", outPath)
				return cli.ExitOperationalError
			}
		}
	}
	if err := os.MkdirAll(opts.OutDir, 0o755); err != nil {
		fmt.Fprintf(stderr, "gin-recon: %v\n", err)
		return cli.ExitOperationalError
	}
	for _, rf := range files {
		outPath := filepath.Join(opts.OutDir, rf.name)
		if err := os.WriteFile(outPath, rf.data, 0o644); err != nil {
			fmt.Fprintf(stderr, "gin-recon: %v\n", err)
			return cli.ExitOperationalError
		}
	}
	return successExitCode
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run contains everything main would otherwise do directly, so tests can
// exercise it without a subprocess and without main calling os.Exit itself.
func run(args []string, stdout, stderr io.Writer) int {
	opts, err := cli.Parse(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(stdout, usage)
			return cli.ExitSuccess
		}
		fmt.Fprintf(stderr, "gin-recon: %v\n", err)
		return cli.ExitOperationalError
	}

	// schema is the one command with no filesystem/build-context surface to
	// validate: it does not accept --src or any scan/config/output option
	// (enforced by Parse's per-command flag registration), so it skips
	// cli.Validate entirely rather than running checks that do not apply.
	if opts.Command != cli.CommandSchema {
		if err := cli.Validate(opts); err != nil {
			fmt.Fprintf(stderr, "gin-recon: %v\n", err)
			return cli.ExitOperationalError
		}
	}

	switch opts.Command {
	case cli.CommandSchema:
		return runSchema(opts, stdout, stderr)
	case cli.CommandInventory:
		return runInventory(opts, stdout, stderr)
	case cli.CommandAudit:
		return runAudit(opts, stdout, stderr)
	case cli.CommandSuggestAuth:
		return runSuggestAuth(opts, stdout, stderr)
	case cli.CommandRender:
		return runRender(opts, stdout, stderr)
	case cli.CommandFleet:
		return runFleet(opts, stdout, stderr)
	default:
		// Unreachable: cli.Parse rejects any other command before returning.
		fmt.Fprintf(stderr, "gin-recon: internal error: unhandled command %q\n", opts.Command)
		return cli.ExitOperationalError
	}
}

// runInventory wires cli.Options through internal/analyzer's loader and
// discovery orchestration into a report.Report. Both the typed and
// syntax-only profiles are implemented; syntax-only never invokes
// go/packages or the Go toolchain at all (internal/analyzer.LoadSyntax),
// per docs/threat-model.md's syntax-only trust profile.
func runInventory(opts *cli.Options, stdout, stderr io.Writer) int {
	// --config is applicable to inventory (docs/cli-contract.md) purely for
	// scan/analysis settings and OpenAPI title/version/securitySchemes
	// metadata; it can never make an inventory report assert security, since
	// applySecurity only ever runs against route.Auth, which inventory
	// routes never populate. It must be loaded and merged before the
	// profile/format checks below, since a config's analysis.profile can
	// itself request something unimplemented.
	cfg, err := loadConfig(opts.ConfigPath)
	if err != nil {
		fmt.Fprintf(stderr, "gin-recon: %v\n", err)
		return cli.ExitOperationalError
	}
	if err := applyConfigDefaults(opts, cfg); err != nil {
		fmt.Fprintf(stderr, "gin-recon: %v\n", err)
		return cli.ExitOperationalError
	}

	for _, f := range opts.Formats {
		if !formatsImplemented[f] {
			fmt.Fprintf(stderr, "gin-recon: --format %s is not implemented yet; %s\n", f, implementedFormatsMessage)
			return cli.ExitOperationalError
		}
	}

	exclude, err := scopeExclude(opts)
	if err != nil {
		fmt.Fprintf(stderr, "gin-recon: %v\n", err)
		return cli.ExitOperationalError
	}

	if opts.Profile == model.ProfileSyntaxOnly {
		loaded, err := analyzer.LoadSyntax(context.Background(), analyzer.LoadOptions{
			Src: opts.Src, GOOS: opts.GOOS, GOARCH: opts.GOARCH, Tags: opts.Tags,
			Workspace: opts.Workspace, ModuleMode: opts.ModuleMode,
			Include: opts.Include, Exclude: exclude,
		})
		if err != nil {
			fmt.Fprintf(stderr, "gin-recon: %v\n", err)
			return cli.ExitOperationalError
		}
		result := analyzer.InventorySyntax(loaded)
		rep := report.NewInventoryReport(model.ProfileSyntaxOnly, report.Target{
			Module:       result.Module,
			BuildContext: result.ScanCoverage.BuildContext,
		})
		rep.Routes = result.Routes
		rep.GlobalMiddleware = result.GlobalMiddleware
		rep.FallbackSurfaces = result.FallbackSurfaces
		rep.Diagnostics = result.Diagnostics
		rep.ScanCoverage = result.ScanCoverage
		return writeReport(rep, opts, cfg, stdout, stderr, cli.ExitSuccess)
	}

	moduleMode := analyzer.ResolveModuleMode(opts.Src, opts.ModuleMode)
	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	defer cancel()

	loaded, err := analyzer.Load(ctx, analyzer.LoadOptions{
		Src:            opts.Src,
		GOOS:           opts.GOOS,
		GOARCH:         opts.GOARCH,
		Tags:           opts.Tags,
		Workspace:      opts.Workspace,
		ModuleMode:     moduleMode,
		AllowDownloads: opts.AllowDownloads,
		Include:        opts.Include,
		Exclude:        exclude,
		FollowModules:  followModulesFrom(cfg),
	})
	if err != nil {
		fmt.Fprintf(stderr, "gin-recon: %v\n", err)
		return cli.ExitOperationalError
	}

	result := analyzer.Inventory(loaded)

	rep := report.NewInventoryReport(model.ProfileTyped, report.Target{
		Module:       result.Module,
		BuildContext: result.ScanCoverage.BuildContext,
	})
	rep.Routes = result.Routes
	rep.GlobalMiddleware = result.GlobalMiddleware
	rep.FallbackSurfaces = result.FallbackSurfaces
	rep.Diagnostics = result.Diagnostics
	rep.ScanCoverage = result.ScanCoverage

	return writeReport(rep, opts, cfg, stdout, stderr, cli.ExitSuccess)
}

// auditFailOnImplemented are the --fail-on selectors runAudit can actually
// evaluate. "new" and "regression" are only evaluable once a baseline has
// actually been compared — cli.Validate already requires --baseline
// alongside either selector, so by the time runAudit runs its own
// isFailOnImplemented check, both are always safe to claim as implemented.
// "policy" and "policy:<id>" are handled separately since "policy:<id>"
// carries a dynamic suffix this fixed set can't express.
var auditFailOnImplemented = map[string]bool{
	"public":              true,
	"unknown":             true,
	"attested-unresolved": true,
	"incomplete":          true,
	"policy":              true,
	"new":                 true,
	"regression":          true,
}

func isFailOnImplemented(selector string) bool {
	return auditFailOnImplemented[selector] || strings.HasPrefix(selector, "policy:")
}

// runAudit wires cli.Options through internal/analyzer's Audit orchestration
// (discovery plus internal/classify's ADR 0005 classification) into a
// report.Report. Like runInventory, both the typed and syntax-only profiles
// are implemented.
func runAudit(opts *cli.Options, stdout, stderr io.Writer) int {
	cfg, err := loadConfig(opts.ConfigPath)
	if err != nil {
		fmt.Fprintf(stderr, "gin-recon: %v\n", err)
		return cli.ExitOperationalError
	}
	if err := applyConfigDefaults(opts, cfg); err != nil {
		fmt.Fprintf(stderr, "gin-recon: %v\n", err)
		return cli.ExitOperationalError
	}

	for _, f := range opts.Formats {
		if !formatsImplemented[f] {
			fmt.Fprintf(stderr, "gin-recon: --format %s is not implemented yet; %s\n", f, implementedFormatsMessage)
			return cli.ExitOperationalError
		}
	}
	for _, selector := range opts.FailOn {
		if !isFailOnImplemented(selector) {
			fmt.Fprintf(stderr, "gin-recon: --fail-on %s is not implemented yet\n", selector)
			return cli.ExitOperationalError
		}
	}
	var baselineReport *report.Report
	if opts.Baseline != "" {
		baselineReport, err = loadBaseline(opts.Baseline)
		if err != nil {
			fmt.Fprintf(stderr, "gin-recon: --baseline: %v\n", err)
			return cli.ExitOperationalError
		}
	}

	exclude, err := scopeExclude(opts)
	if err != nil {
		fmt.Fprintf(stderr, "gin-recon: %v\n", err)
		return cli.ExitOperationalError
	}

	var result *analyzer.AuditResult
	var rep *report.Report

	if opts.Profile == model.ProfileSyntaxOnly {
		loaded, err := analyzer.LoadSyntax(context.Background(), analyzer.LoadOptions{
			Src: opts.Src, GOOS: opts.GOOS, GOARCH: opts.GOARCH, Tags: opts.Tags,
			Workspace: opts.Workspace, ModuleMode: opts.ModuleMode,
			Include: opts.Include, Exclude: exclude,
		})
		if err != nil {
			fmt.Fprintf(stderr, "gin-recon: %v\n", err)
			return cli.ExitOperationalError
		}
		result = analyzer.AuditSyntax(loaded, cfg, time.Now())
		rep = report.NewAuditReport(
			model.ProfileSyntaxOnly,
			report.Target{Module: result.Module, BuildContext: result.ScanCoverage.BuildContext},
			result.Summary,
			result.Findings,
			report.PolicyEvaluation{EvaluatedPolicies: result.EvaluatedPolicies},
			nil,
		)
	} else {
		moduleMode := analyzer.ResolveModuleMode(opts.Src, opts.ModuleMode)
		ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
		defer cancel()

		loaded, err := analyzer.Load(ctx, analyzer.LoadOptions{
			Src:            opts.Src,
			GOOS:           opts.GOOS,
			GOARCH:         opts.GOARCH,
			Tags:           opts.Tags,
			Workspace:      opts.Workspace,
			ModuleMode:     moduleMode,
			AllowDownloads: opts.AllowDownloads,
			Include:        opts.Include,
			Exclude:        exclude,
			FollowModules:  followModulesFrom(cfg),
		})
		if err != nil {
			fmt.Fprintf(stderr, "gin-recon: %v\n", err)
			return cli.ExitOperationalError
		}

		result = analyzer.Audit(loaded, cfg, time.Now())
		rep = report.NewAuditReport(
			model.ProfileTyped,
			report.Target{Module: result.Module, BuildContext: result.ScanCoverage.BuildContext},
			result.Summary,
			result.Findings,
			report.PolicyEvaluation{EvaluatedPolicies: result.EvaluatedPolicies},
			nil,
		)
	}

	rep.Routes = result.Routes
	rep.GlobalMiddleware = result.GlobalMiddleware
	rep.FallbackSurfaces = result.FallbackSurfaces
	rep.Diagnostics = result.Diagnostics
	rep.ScanCoverage = result.ScanCoverage

	var delta *report.Delta
	if baselineReport != nil {
		if err := compare.Compatible(baselineReport, rep); err != nil {
			fmt.Fprintf(stderr, "gin-recon: --baseline: %v\n", err)
			return cli.ExitOperationalError
		}
		delta = compare.Compare(baselineReport, rep)
		rep.Delta = delta
	}

	exitCode := cli.ExitSuccess
	if gateMatched(opts.FailOn, result, delta) {
		exitCode = cli.ExitGate
	}
	return writeReport(rep, opts, cfg, stdout, stderr, exitCode)
}

// loadReportFile reads and decodes a previously emitted report.Report from
// disk. It is the one shared load path for every place gin-recon reads an
// already-produced report back off disk instead of producing one via
// analysis: --baseline (runAudit) and --report (runRender). gin-recon only
// ever emits JSON reports (never YAML, unlike --config), so JSON is the only
// format accepted here.
func loadReportFile(path string) (*report.Report, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rep report.Report
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, fmt.Errorf("decoding report: %w", err)
	}
	return &rep, nil
}

// loadBaseline is loadReportFile with --baseline's own error-wrapping —
// compare.Compatible (called by runAudit right after) already performs
// --baseline's actual compatibility validation (schema major, audit-only,
// matching profile/build context), so this stays a thin wrapper.
func loadBaseline(path string) (*report.Report, error) {
	return loadReportFile(path)
}

// gateMatched evaluates the --fail-on selectors runAudit knows how to
// enforce against the audit result. delta is nil unless --baseline was
// supplied; cli.Validate already guarantees "new"/"regression" never appear
// in selectors without a baseline, so those two cases can assume delta is
// non-nil.
func gateMatched(selectors []string, result *analyzer.AuditResult, delta *report.Delta) bool {
	for _, selector := range selectors {
		switch {
		case selector == "public":
			if result.Summary.Public > 0 {
				return true
			}
		case selector == "unknown":
			if result.Summary.Unknown > 0 {
				return true
			}
		case selector == "attested-unresolved":
			if result.Summary.ProvenByAttestedUnresolved > 0 {
				return true
			}
		case selector == "incomplete":
			if !result.ScanCoverage.Complete {
				return true
			}
		case selector == "new":
			if len(delta.AddedRoutes) > 0 || len(delta.NewFindings) > 0 {
				return true
			}
		case selector == "regression":
			if len(delta.AuthRegressions) > 0 {
				return true
			}
		case selector == "policy":
			if hasFindingWithRuleID(result.Findings, "policy-violation") {
				return true
			}
		case strings.HasPrefix(selector, "policy:"):
			id := strings.TrimPrefix(selector, "policy:")
			if hasPolicyViolationForID(result.Findings, id) {
				return true
			}
		}
	}
	return false
}

func hasFindingWithRuleID(findings []report.Finding, ruleID string) bool {
	for _, f := range findings {
		if string(f.RuleID) == ruleID {
			return true
		}
	}
	return false
}

// hasPolicyViolationForID checks a policy-violation finding's evidence for
// the specific policy ID --fail-on policy:<id> names — see
// internal/policy's newPolicyFinding, which stamps evidence["policyId"].
func hasPolicyViolationForID(findings []report.Finding, id string) bool {
	for _, f := range findings {
		if string(f.RuleID) != "policy-violation" {
			continue
		}
		if policyID, ok := f.Evidence["policyId"].(string); ok && policyID == id {
			return true
		}
	}
	return false
}

// loadConfig reads and decodes --config, defaulting to an empty but valid
// configuration when none was supplied — an audit with no configured auth
// middleware is a legitimate request (every resolved, non-opaque route is
// then classified public), not an error; an inventory with no config simply
// gets OpenAPI's default title/version and no security schemes. Format is
// detected from the file extension: .yaml/.yml decode as YAML, everything
// else as JSON.
func loadConfig(path string) (*config.Config, error) {
	if path == "" {
		return &config.Config{Version: 1}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("--config: %w", err)
	}
	format := config.FormatJSON
	if ext := strings.ToLower(filepath.Ext(path)); ext == ".yaml" || ext == ".yml" {
		format = config.FormatYAML
	}
	cfg, err := config.Decode(format, data)
	if err != nil {
		return nil, fmt.Errorf("--config: %w", err)
	}
	return cfg, nil
}

// applyConfigDefaults fills any scan/analysis/limits option the user did
// not pass explicitly on the command line from cfg, per
// docs/configuration-contract.md: "Scalar CLI values override
// configuration. Repeatable CLI include/exclude values append as specified
// by the CLI contract." opts.ExplicitFlags — not the field's current value —
// is what decides "explicitly passed," since a flag's default can happen to
// equal what config would have set anyway (e.g. --goos defaulting to the
// running tool's own GOOS). Include/Exclude/Tags are additive: config
// supplies the base list, whatever the CLI passed is appended on top, never
// replacing it — the same "append" rule the CLI contract already documents
// for --include/--exclude.
func applyConfigDefaults(opts *cli.Options, cfg *config.Config) error {
	if cfg.Scan != nil {
		opts.Include = append(append([]string{}, cfg.Scan.Include...), opts.Include...)
		opts.Exclude = append(append([]string{}, cfg.Scan.Exclude...), opts.Exclude...)
		if cfg.Scan.IgnoreFile != nil && !opts.ExplicitFlags["ignore-file"] {
			opts.IgnoreFile = *cfg.Scan.IgnoreFile
		}
	}
	if a := cfg.Analysis; a != nil {
		if a.Profile != "" && !opts.ExplicitFlags["profile"] {
			opts.Profile = model.AnalysisProfile(a.Profile)
		}
		if !opts.ExplicitFlags["allow-downloads"] {
			opts.AllowDownloads = a.AllowDownloads
		}
		if a.Workspace != "" && !opts.ExplicitFlags["workspace"] {
			opts.Workspace = a.Workspace
		}
		if a.ModuleMode != "" && !opts.ExplicitFlags["module-mode"] {
			opts.ModuleMode = model.ModuleMode(a.ModuleMode)
		}
		if a.GOOS != "" && !opts.ExplicitFlags["goos"] {
			opts.GOOS = a.GOOS
		}
		if a.GOARCH != "" && !opts.ExplicitFlags["goarch"] {
			opts.GOARCH = a.GOARCH
		}
		opts.Tags = append(append([]string{}, a.Tags...), opts.Tags...)
	}
	if l := cfg.Limits; l != nil && l.Timeout != nil && !opts.ExplicitFlags["timeout"] {
		d, err := time.ParseDuration(*l.Timeout)
		if err != nil {
			return fmt.Errorf("config limits.timeout: invalid duration %q: %w", *l.Timeout, err)
		}
		opts.Timeout = d
	}
	return nil
}

// followModulesFrom returns cfg's configured analysis.followModules, or nil
// when cfg.Analysis is unset — the one config-only, no-CLI-flag setting
// analyzer.LoadOptions needs directly from config, matching the same
// config-only pattern authMiddleware/authWrappers/policies already use for
// settings deliberately not exposed as a flag (see
// docs/adr/0010-opt-in-cross-module-registrar-following.md for why this one
// in particular is never a flag: it widens the analysis trust boundary and
// must come from a reviewed, versioned config file, not a one-off command
// line argument).
func followModulesFrom(cfg *config.Config) []string {
	if cfg == nil || cfg.Analysis == nil {
		return nil
	}
	return cfg.Analysis.FollowModules
}

// scopeExclude returns opts.Exclude with --ignore-file's patterns folded
// in — the one piece of scan scoping that is a filesystem path rather than
// a value already resolved by Parse/applyConfigDefaults, so it is resolved
// here rather than carried on Options itself.
func scopeExclude(opts *cli.Options) ([]string, error) {
	ignorePatterns, err := readIgnoreFilePatterns(opts.Src, opts.IgnoreFile)
	if err != nil {
		return nil, err
	}
	return append(append([]string{}, ignorePatterns...), opts.Exclude...), nil
}

// readIgnoreFilePatterns reads opts.IgnoreFile (already validated by
// cli.Validate to resolve beneath --src) as a list of exclude globs — one
// per line, blank lines and lines starting with "#" ignored. A missing file
// is not an error: the default ".gin-reconignore" not existing is the
// ordinary case for a repo with nothing to ignore, and an explicitly-named
// but missing file is treated the same way rather than failing a scan over
// what is a scoping convenience, not a security control.
func readIgnoreFilePatterns(src, ignoreFile string) ([]string, error) {
	if ignoreFile == "" || ignoreFile == "none" {
		return nil, nil
	}
	path := ignoreFile
	if !filepath.IsAbs(path) {
		path = filepath.Join(src, path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("--ignore-file: %w", err)
	}
	var patterns []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		patterns = append(patterns, line)
	}
	return patterns, nil
}

func runSchema(opts *cli.Options, stdout, stderr io.Writer) int {
	var doc []byte
	switch opts.SchemaKind {
	case cli.SchemaKindReport:
		doc = schema.Report10
	case cli.SchemaKindConfig:
		doc = schema.Config1
	}
	if _, err := stdout.Write(doc); err != nil {
		fmt.Fprintf(stderr, "gin-recon: writing schema: %v\n", err)
		return cli.ExitOperationalError
	}
	fmt.Fprintln(stdout)
	return cli.ExitSuccess
}

// runSuggestAuth wires cli.Options through internal/analyzer's loader and
// SuggestAuth ranking into JSON output. Like runInventory, only the typed
// profile is implemented so far. --config is accepted per
// docs/cli-contract.md even though SuggestAuth's own ranking does not
// consume it (no formats, OpenAPI metadata, or auth classification apply to
// suggest-auth) — an invalid config file must still fail loudly here rather
// than being silently ignored, matching every other command.
func runSuggestAuth(opts *cli.Options, stdout, stderr io.Writer) int {
	cfg, err := loadConfig(opts.ConfigPath)
	if err != nil {
		fmt.Fprintf(stderr, "gin-recon: %v\n", err)
		return cli.ExitOperationalError
	}
	if err := applyConfigDefaults(opts, cfg); err != nil {
		fmt.Fprintf(stderr, "gin-recon: %v\n", err)
		return cli.ExitOperationalError
	}

	if opts.Profile != model.ProfileTyped {
		fmt.Fprintf(stderr, "gin-recon: --profile %s is not implemented yet; only \"typed\" is available so far\n", opts.Profile)
		return cli.ExitOperationalError
	}

	exclude, err := scopeExclude(opts)
	if err != nil {
		fmt.Fprintf(stderr, "gin-recon: %v\n", err)
		return cli.ExitOperationalError
	}

	moduleMode := analyzer.ResolveModuleMode(opts.Src, opts.ModuleMode)
	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	defer cancel()

	loaded, err := analyzer.Load(ctx, analyzer.LoadOptions{
		Src:            opts.Src,
		GOOS:           opts.GOOS,
		GOARCH:         opts.GOARCH,
		Tags:           opts.Tags,
		Workspace:      opts.Workspace,
		ModuleMode:     moduleMode,
		AllowDownloads: opts.AllowDownloads,
		Include:        opts.Include,
		Exclude:        exclude,
		FollowModules:  followModulesFrom(cfg),
	})
	if err != nil {
		fmt.Fprintf(stderr, "gin-recon: %v\n", err)
		return cli.ExitOperationalError
	}

	result := analyzer.SuggestAuth(loaded)
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "gin-recon: %v\n", err)
		return cli.ExitOperationalError
	}
	data = append(data, '\n')

	if opts.OutDir == "" {
		if _, err := stdout.Write(data); err != nil {
			fmt.Fprintf(stderr, "gin-recon: writing report: %v\n", err)
			return cli.ExitOperationalError
		}
		return cli.ExitSuccess
	}

	outPath := filepath.Join(opts.OutDir, "suggestions.json")
	if !opts.Force {
		if _, err := os.Stat(outPath); err == nil {
			fmt.Fprintf(stderr, "gin-recon: %s already exists; pass --force to overwrite\n", outPath)
			return cli.ExitOperationalError
		}
	}
	if err := os.MkdirAll(opts.OutDir, 0o755); err != nil {
		fmt.Fprintf(stderr, "gin-recon: %v\n", err)
		return cli.ExitOperationalError
	}
	if err := os.WriteFile(outPath, data, 0o644); err != nil {
		fmt.Fprintf(stderr, "gin-recon: %v\n", err)
		return cli.ExitOperationalError
	}
	return cli.ExitSuccess
}

// runRender implements docs/adr/0016-render-command-decouples-formatting-from-analysis.md:
// its only input is --report, an already-produced report.Report loaded with
// loadReportFile (the exact same load path --baseline uses); it re-runs
// gin-recon's own formatting layer over that document via renderReport/
// writeReport, the same functions runInventory/runAudit already use to turn
// a report.Report into routes.json/routes.md/openapi.json/api.html/
// results.sarif. Nothing in this function calls into
// internal/analyzer or golang.org/x/tools/go/packages, and none of
// cli.Options' scan/analysis fields (Src, Profile, Include, ...) are read —
// render has no source tree to point them at.
func runRender(opts *cli.Options, stdout, stderr io.Writer) int {
	// --config here only ever feeds the formatting layer itself (OpenAPI
	// title/version/securitySchemes) — see format.OpenAPI's infoFrom, the
	// only place cfg.OpenAPI is read. Unlike runInventory/runAudit, render
	// never calls applyConfigDefaults: that function exists to fill
	// scan/analysis Options fields (--goos, --workspace, --allow-downloads,
	// ...) render doesn't have and would never act on, since no analysis
	// runs here.
	cfg, err := loadConfig(opts.ConfigPath)
	if err != nil {
		fmt.Fprintf(stderr, "gin-recon: %v\n", err)
		return cli.ExitOperationalError
	}

	rep, err := loadReportFile(opts.ReportPath)
	if err != nil {
		fmt.Fprintf(stderr, "gin-recon: --report: %v\n", err)
		return cli.ExitOperationalError
	}
	if err := validateRenderedReport(rep); err != nil {
		fmt.Fprintf(stderr, "gin-recon: --report: %v\n", err)
		return cli.ExitOperationalError
	}

	for _, f := range opts.Formats {
		if !formatsImplemented[f] {
			fmt.Fprintf(stderr, "gin-recon: --format %s is not implemented yet; %s\n", f, implementedFormatsMessage)
			return cli.ExitOperationalError
		}
		// cli.Validate already rejects --format sarif as audit-only for
		// inventory/audit, decided purely from the CLI command name. render's
		// command is always "render", so that same decision has to wait until
		// the loaded document's own Command field is known — right here.
		if f == cli.FormatSARIF && rep.Command != report.CommandAudit {
			fmt.Fprintf(stderr, "gin-recon: --format sarif is audit-only; the loaded --report document's command is %q\n", rep.Command)
			return cli.ExitOperationalError
		}
	}

	return writeReport(rep, opts, cfg, stdout, stderr, cli.ExitSuccess)
}

// runFleet wires cli.Options through internal/fleet's orchestration, per
// docs/adr/0018-fleet-scanning.md. It owns the one filesystem decision that
// belongs at the CLI layer rather than inside internal/fleet — refusing to
// overwrite an existing fleet.json without --force, the same convention
// writeReport already applies to every other command's output — and
// resolves the binary fleet re-execs per target.
func runFleet(opts *cli.Options, stdout, stderr io.Writer) int {
	manifest, manifestData, err := fleet.LoadManifest(opts.TargetsPath)
	if err != nil {
		fmt.Fprintf(stderr, "gin-recon: %v\n", err)
		return cli.ExitOperationalError
	}

	aggregatePath := filepath.Join(opts.OutDir, fleetAggregateFilename)
	if !opts.Force && !opts.Resume {
		if _, err := os.Stat(aggregatePath); err == nil {
			fmt.Fprintf(stderr, "gin-recon: %s already exists; pass --force to overwrite or --resume to continue\n", aggregatePath)
			return cli.ExitOperationalError
		}
	}

	binaryPath, err := os.Executable()
	if err != nil {
		fmt.Fprintf(stderr, "gin-recon: fleet: resolving the gin-recon binary to re-exec per target: %v\n", err)
		return cli.ExitOperationalError
	}

	// The shared --config is loaded here too (in addition to being passed
	// through to each target's own audit subprocess) purely to read
	// fleet.allowedRemoteHosts — docs/adr/0019-fleet-remote-targets.md's
	// config-reviewed scope for --allow-remote-targets. No other config
	// field is read at this layer; everything else still only ever reaches
	// analysis through the per-target audit subprocess itself.
	cfg, err := loadConfig(opts.ConfigPath)
	if err != nil {
		fmt.Fprintf(stderr, "gin-recon: %v\n", err)
		return cli.ExitOperationalError
	}
	var allowedHosts []fleet.AllowedHost
	if cfg.Fleet != nil {
		for _, h := range cfg.Fleet.AllowedRemoteHosts {
			allowedHosts = append(allowedHosts, fleet.AllowedHost{Host: h.Host, TokenEnv: h.TokenEnv})
		}
	}

	var stderrBuf bytes.Buffer
	agg, err := fleet.Run(context.Background(), fleet.RunOptions{
		ManifestPath: opts.TargetsPath,
		Manifest:     manifest,
		ManifestData: manifestData,
		ConfigPath:   opts.ConfigPath,
		Formats:      []string{string(cli.FormatJSON)},
		OutDir:       opts.OutDir,
		Concurrency:  opts.Concurrency,
		Resume:       opts.Resume,
		BinaryPath:   binaryPath,
		ToolVersion:  report.ToolVersion,
		Stderr:       &stderrBuf,
		AllowRemote:  opts.AllowRemoteTargets,
		AllowedHosts: allowedHosts,
	})
	if stderrBuf.Len() > 0 {
		stderr.Write(stderrBuf.Bytes())
	}
	if err != nil {
		fmt.Fprintf(stderr, "gin-recon: %v\n", err)
		return cli.ExitOperationalError
	}

	data, err := json.MarshalIndent(agg, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "gin-recon: fleet: encoding fleet.json: %v\n", err)
		return cli.ExitOperationalError
	}
	if err := os.WriteFile(aggregatePath, data, 0o644); err != nil {
		fmt.Fprintf(stderr, "gin-recon: %v\n", err)
		return cli.ExitOperationalError
	}

	for _, sel := range opts.FailOn {
		if sel == "incomplete" && !agg.Coverage.Complete {
			return cli.ExitGate
		}
	}
	return cli.ExitSuccess
}

// fleetAggregateFilename is fleet's one output file at --out's top level;
// each target's own full report lives underneath targets/<name>/, untouched
// (docs/adr/0018-fleet-scanning.md).
const fleetAggregateFilename = "fleet.json"

// validateRenderedReport rejects a --report document render cannot safely
// reformat: an unrecognized/incompatible schema major — the same
// compare.SchemaMajor check --baseline applies via compare.Compatible,
// reused directly here rather than compare.Compatible itself since
// Compatible additionally requires both sides to be audit reports, which
// would wrongly reject a perfectly valid inventory-shaped --report — or a
// command value report.Report never actually carries.
func validateRenderedReport(rep *report.Report) error {
	major, ok := compare.SchemaMajor(rep.SchemaVersion)
	if !ok {
		return fmt.Errorf("unrecognized schemaVersion %q", rep.SchemaVersion)
	}
	currentMajor, _ := compare.SchemaMajor(report.SchemaVersion)
	if major != currentMajor {
		return fmt.Errorf("report schema major %q is not compatible with this gin-recon build's schema major %q", major, currentMajor)
	}
	switch rep.Command {
	case report.CommandInventory, report.CommandAudit:
	default:
		return fmt.Errorf("unrecognized report command %q", rep.Command)
	}
	return nil
}

const usage = `gin-recon - inventory and audit Gin route surfaces

Usage:
  gin-recon inventory [options]
  gin-recon audit [options]
  gin-recon suggest-auth [options]
  gin-recon schema [--kind report|config]
  gin-recon render --report <routes.json> [options]
  gin-recon fleet --targets <targets.json> --out <dir> [options]

See docs/reference.md for the full option reference.`
