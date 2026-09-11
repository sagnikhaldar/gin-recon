// fleet.go wires cli.Options through internal/fleet's orchestration for the
// `fleet` command — docs/adr/0018-fleet-scanning.md (local targets),
// docs/adr/0019-fleet-remote-targets.md (remote targets),
// docs/adr/0020-fleet-html-view.md (fleet.html), docs/adr/0021-fleet-org-enumeration.md
// (--org), and docs/adr/0022-fleet-baseline-delta.md (--baseline). Kept
// separate from main.go: fleet is the one command with its own multi-step
// output (an aggregate, an optional delta, an HTML companion, and for
// --org a discovered-manifest record) rather than the single
// report/format pair every other command produces, so it earns its own
// file the same way internal/fleet and internal/format's fleet_html.go
// already have their own home instead of living inside a shared file.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/sagnikhaldar/gin-recon/internal/cli"
	"github.com/sagnikhaldar/gin-recon/internal/config"
	"github.com/sagnikhaldar/gin-recon/internal/fleet"
	"github.com/sagnikhaldar/gin-recon/internal/format"
	"github.com/sagnikhaldar/gin-recon/internal/report"
)

// fleetAggregateFilename is fleet's one output file at --out's top level;
// each target's own full report lives underneath targets/<name>/, untouched
// (docs/adr/0018-fleet-scanning.md).
const fleetAggregateFilename = "fleet.json"

// fleetHTMLFilename is fleet.json's unconditional HTML companion
// (docs/adr/0020-fleet-html-view.md).
const fleetHTMLFilename = "fleet.html"

// fleetDeltaFilename is fleet's --baseline output, written only when
// --baseline is given (docs/adr/0022-fleet-baseline-delta.md).
const fleetDeltaFilename = "fleet-delta.json"

// discoveredTargetsFilename is where a --org run's discovered manifest is
// persisted, per docs/adr/0021-fleet-org-enumeration.md: an auditable,
// replayable record of exactly what was scanned, independent of the
// organization's membership possibly changing before the next run.
const discoveredTargetsFilename = "discovered-targets.json"

// configSnapshotBasename is the base filename an --org run's resolved
// --config is copied into --out under (its own extension, .json or
// .yaml/.yml, is preserved) — docs/adr/0025-fleet-org-config-snapshot.md.
// Unlike discoveredTargetsFilename this isn't schema data fleet.json ever
// references, just a plain audit copy for whoever revisits an --org run
// later, after the original --config path may have moved or changed.
const configSnapshotBasename = "config-snapshot"

// targetConfigsSnapshotDirName is where --target-config-dir's actually-used
// contents are copied into --out, for the same reason configSnapshotBasename
// exists for --config: a reviewed authMiddleware config, per target, is
// real evidence a human/AI checked against source before writing it down —
// not something this run's own output should ever depend on the operator's
// original directory still existing to reconstruct later.
const targetConfigsSnapshotDirName = "target-configs-snapshot"
const targetConfigsSnapshotMarker = ".gin-recon-complete"

// fleetHTMLSibling resolves --out's rendered-output directory and the
// relative link back to --out from inside it
// (docs/adr/0023-fleet-raw-rendered-split.md). Anchored to --out's own
// absolute path rather than a naive `outDir + "-html"` / filepath.Base(outDir)
// on the raw string: --out "." is a real, common invocation (scanning from
// inside the intended output directory), and filepath.Base(".") is itself
// "." — a naive approach turns it into a nonsense ".-html" sibling nested
// inside --out and a "../." raw-link that points at --out's own parent
// instead of --out itself.
//
// --out "." gets a second special case on top of that: a *sibling* of "."
// is --out's own parent directory — for a project directory like
// ~/repo, that is ~/, outside the directory the caller actually asked to
// scope output to (docs/adr/0027-fleet-out-dot-nests-rendered-output.md).
// So --out "." nests the rendered output inside itself (<out>/html) rather
// than beside it, trading the "no HTML file ever lives under --out"
// invariant ADR 0023 states for every other --out value for keeping
// everything under a `.`-scoped run inside the directory the caller named.
func fleetHTMLSibling(outDir string) (htmlDir, rawLink string, err error) {
	abs, err := filepath.Abs(outDir)
	if err != nil {
		return "", "", fmt.Errorf("resolving --out: %w", err)
	}
	if filepath.Clean(outDir) == "." {
		return filepath.Join(abs, "html"), "..", nil
	}
	base := filepath.Base(abs)
	return filepath.Join(filepath.Dir(abs), base+"-html"), "../" + base, nil
}

// fleetGitHubAPIBaseForTests overrides the GitHub API base URL --org uses.
// Empty in every real invocation; tests point it at a local httptest.Server
// so --org's own logic (pagination, incompleteness, gating) is exercisable
// without real network access or a real token.
var fleetGitHubAPIBaseForTests string

// fleetBinaryPathForTests overrides the binary fleet re-execs per target.
// Empty in every real invocation (os.Executable() resolves it); tests point
// it at a real gin-recon binary built from this checkout, since
// os.Executable() under `go test` resolves to the test binary itself, which
// doesn't understand "audit" as a subcommand.
var fleetBinaryPathForTests string

// fleetCloneForTests replaces git cloning in integration tests. Nil in every
// real invocation.
var fleetCloneForTests fleet.CloneFunc

// isInteractiveTerminalForTests overrides isInteractiveTerminal's result —
// nil in every real invocation, falling through to the real os.Stdin
// check. main_test.go's TestMain sets this to a false-returning func by
// default for the whole test binary, so no test can ever accidentally
// inherit a real terminal's stdin (e.g. `go test` run directly in an
// interactive shell) and hang waiting on a prompt that will never be
// answered; a test that specifically wants the prompt path overrides it
// back to true just for that test, alongside fleetStdinForTests.
var isInteractiveTerminalForTests func() bool

// isInteractiveTerminal reports whether fleet is connected to a real
// terminal it can safely prompt on — never true for CI, a script, or
// piped/redirected input, all of which have no one able to answer a
// prompt (docs/adr/0034-fleet-interactive-conflict-prompt.md).
func isInteractiveTerminal() bool {
	if isInteractiveTerminalForTests != nil {
		return isInteractiveTerminalForTests()
	}
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// fleetStdinForTests overrides the reader resolveFleetConflictInteractively
// reads from; nil in every real invocation (os.Stdin).
var fleetStdinForTests io.Reader

// fleetConflictChoice is the user's answer to resolveFleetConflictInteractively.
type fleetConflictChoice int

const (
	fleetConflictCancel fleetConflictChoice = iota
	fleetConflictResume
	fleetConflictOverwrite
)

// resolveFleetConflictInteractively asks, on a real terminal only (the
// caller has already checked isInteractiveTerminal), how to proceed when
// fleet's own prior output already exists at conflictPath. Any
// unrecognized answer, blank input, or a stdin read error/EOF resolves to
// cancel — the same safe, non-destructive outcome a non-interactive run
// already gets from the hard error this replaces; never resumes or
// overwrites on an ambiguous answer.
func resolveFleetConflictInteractively(conflictPath string, stdout io.Writer) fleetConflictChoice {
	fmt.Fprintf(stdout, "gin-recon: %s already exists.\n", conflictPath)
	fmt.Fprint(stdout, "[R]esume, [O]verwrite, or [C]ancel? ")
	stdin := io.Reader(os.Stdin)
	if fleetStdinForTests != nil {
		stdin = fleetStdinForTests
	}
	scanner := bufio.NewScanner(stdin)
	if !scanner.Scan() {
		fmt.Fprintln(stdout)
		return fleetConflictCancel
	}
	switch strings.ToLower(strings.TrimSpace(scanner.Text())) {
	case "r", "resume":
		return fleetConflictResume
	case "o", "overwrite":
		return fleetConflictOverwrite
	default:
		return fleetConflictCancel
	}
}

// runFleet is the command's entry point: resolve the target manifest (a
// hand-written file or a discovered --org), load any --baseline up front,
// run the fleet, then write its aggregate/delta/HTML outputs and evaluate
// --fail-on. Each step below is a named stage rather than one long
// sequence — resolveFleetManifest, buildFleetAllowedHosts, and
// buildFleetScope each own one concern so this function reads as the
// stages of a fleet run, not an undifferentiated block.
func runFleet(opts *cli.Options, stdout, stderr io.Writer) int {
	if opts.Org != "" && opts.ConfigPath == "" {
		if err := ensureFleetOrgConfig(opts); err != nil {
			fmt.Fprintf(stderr, "gin-recon: fleet: %v\n", err)
			return cli.ExitOperationalError
		}
		fmt.Fprintf(stderr, "gin-recon: fleet: using default org config %s\n", opts.ConfigPath)
	}
	// A prior run at this same --out already reviewed and published its own
	// target-configs-snapshot/ (writeFleetTargetConfigSnapshot below) — reuse
	// it automatically when --target-config-dir wasn't passed this time, so a
	// reviewed authMiddleware config, once established, survives indefinitely
	// across runs at this --out without the operator ever needing to keep an
	// external directory around, let alone re-supply it after losing it (a
	// real incident, not a hypothetical one). Passing --target-config-dir
	// explicitly still always wins and replaces this run's own persisted set
	// going forward — the same "explicit flag beats a prior default" rule
	// every other capability switch in this command already follows.
	if opts.TargetConfigDir == "" {
		candidate := filepath.Join(opts.OutDir, targetConfigsSnapshotDirName)
		reusable, err := reusableTargetConfigSnapshot(candidate, filepath.Join(opts.OutDir, fleetAggregateFilename))
		if err != nil {
			fmt.Fprintf(stderr, "gin-recon: fleet: %v\n", err)
			return cli.ExitOperationalError
		}
		if reusable {
			opts.TargetConfigDir = candidate
		}
	}
	fleetContext, cancelFleet := context.WithTimeout(context.Background(), opts.FleetTimeout)
	defer cancelFleet()
	effectiveConfigPath, configSnapshot, cleanupConfig, err := freezeFleetConfig(opts.ConfigPath)
	if err != nil {
		fmt.Fprintf(stderr, "gin-recon: fleet: freezing --config: %v\n", err)
		return cli.ExitOperationalError
	}
	defer cleanupConfig()
	effectiveTargetConfigDir, cleanupTargetConfigs, err := freezeFleetTargetConfigDir(opts.TargetConfigDir)
	if err != nil {
		fmt.Fprintf(stderr, "gin-recon: fleet: freezing --target-config-dir: %v\n", err)
		return cli.ExitOperationalError
	}
	defer cleanupTargetConfigs()
	// The shared --config is loaded up front (in addition to being passed
	// through to each target's own audit subprocess) to read
	// fleet.allowedRemoteHosts — docs/adr/0019-fleet-remote-targets.md's
	// config-reviewed scope for --allow-remote-targets — and, later below,
	// authMiddleware/authWrappers counts for fleet.html's own
	// AuthConfig note (docs/adr/0030-fleet-html-auth-config-visibility.md).
	// Every actual classification decision still only ever happens inside
	// the per-target audit subprocess itself; nothing here re-derives or
	// second-guesses it. --org needs this resolved before anything else,
	// since discovering an organization's repositories is itself a network
	// call authorized the same way (docs/adr/0021-fleet-org-enumeration.md).
	cfg, err := loadConfig(effectiveConfigPath)
	if err != nil {
		fmt.Fprintf(stderr, "gin-recon: %v\n", err)
		return cli.ExitOperationalError
	}
	allowedHosts := buildFleetAllowedHosts(cfg)

	// Capture the last committed aggregate before this run's fresh discovery
	// (docs/adr/0039-fleet-org-update.md). The aggregate—not the separately
	// written discovered-targets.json—is authoritative for prior pushedAt and
	// result data. A no-op, empty result when --update wasn't passed or no
	// prior complete run exists at this --out makes every target fall through
	// to a real scan.
	scanOpts := *opts
	scanOpts.ConfigPath = effectiveConfigPath
	scanOpts.TargetConfigDir = effectiveTargetConfigDir
	oldPushedAt, oldResults := loadFleetUpdateState(&scanOpts, stderr)

	manifestPath, manifest, manifestData, discoverySummary, exitCode := resolveFleetManifest(fleetContext, opts, allowedHosts, stderr)
	if exitCode != cli.ExitSuccess {
		return exitCode
	}

	// Loaded now, before anything below writes a single byte of this run's
	// own output — see fleet.LoadBaseline's own doc comment for why reading
	// it any later would risk comparing a run against itself.
	var baseline *fleet.Baseline
	if opts.Baseline != "" {
		baseline, err = fleet.LoadBaseline(opts.Baseline)
		if err != nil {
			fmt.Fprintf(stderr, "gin-recon: %v\n", err)
			return cli.ExitOperationalError
		}
	}

	// --out is the raw-artifacts root; when --render-html is passed, every
	// HTML file gin-recon fleet produces lands in the sibling <out>-html
	// directory instead (or, for --out ".", nested inside it — see
	// fleetHTMLSibling) (docs/adr/0023-fleet-raw-rendered-split.md).
	// Computing the path here is cheap (no I/O) and needed for the
	// conflict check below regardless of --render-html, but htmlOutDir is
	// only ever created/written to further down, gated on --render-html
	// (docs/adr/0037-fleet-html-opt-in.md) — fleet's own output is the raw
	// scan by default; rendering is a separate, explicit step, same as
	// `render` already is for a saved fleet.json.
	htmlOutDir, rawDirLink, err := fleetHTMLSibling(opts.OutDir)
	if err != nil {
		fmt.Fprintf(stderr, "gin-recon: %v\n", err)
		return cli.ExitOperationalError
	}
	aggregatePath := filepath.Join(opts.OutDir, fleetAggregateFilename)
	htmlPath := filepath.Join(htmlOutDir, fleetHTMLFilename)
	checkExists := []string{aggregatePath}
	if opts.RenderHTML {
		checkExists = append(checkExists, htmlPath)
	}
	if opts.Baseline != "" {
		checkExists = append(checkExists, filepath.Join(opts.OutDir, fleetDeltaFilename))
	}
	// --update skips this entirely, not just the interactive branch below:
	// like --force/--resume, it's itself a complete, self-sufficient answer
	// to "output already exists here" (docs/adr/0039-fleet-org-update.md) —
	// cli.Validate already refuses --update combined with either of the
	// other two, so there's no ambiguity about which answer wins.
	if !opts.Force && !opts.Resume && !opts.Update {
		var conflict string
		for _, p := range checkExists {
			if _, err := os.Stat(p); err == nil {
				conflict = p
				break
			}
		}
		if conflict != "" {
			// A real interactive terminal gets a choice instead of a flat
			// error — --force/--resume still work exactly as before, this
			// only covers the case neither was passed. Never prompts
			// outside a real TTY (CI, scripts, piped input): those keep
			// today's exact hard-error behavior, so nothing that already
			// depends on a deterministic non-zero exit here changes
			// (docs/adr/0034-fleet-interactive-conflict-prompt.md).
			if !isInteractiveTerminal() {
				fmt.Fprintf(stderr, "gin-recon: %s already exists; pass --force to overwrite or --resume to continue\n", conflict)
				return cli.ExitOperationalError
			}
			switch resolveFleetConflictInteractively(conflict, stdout) {
			case fleetConflictResume:
				opts.Resume = true
			case fleetConflictOverwrite:
				opts.Force = true
			default:
				fmt.Fprintf(stderr, "gin-recon: cancelled — %s already exists\n", conflict)
				return cli.ExitOperationalError
			}
		}
	}

	binaryPath := fleetBinaryPathForTests
	if binaryPath == "" {
		binaryPath, err = os.Executable()
		if err != nil {
			fmt.Fprintf(stderr, "gin-recon: fleet: resolving the gin-recon binary to re-exec per target: %v\n", err)
			return cli.ExitOperationalError
		}
	}

	targetFormats := make([]string, len(opts.Formats))
	for i, f := range opts.Formats {
		targetFormats[i] = string(f)
	}

	targetHTMLOutDir := ""
	if opts.RenderHTML {
		targetHTMLOutDir = htmlOutDir
	}
	// Built from the "before" state captured above, compared against this
	// run's own fresh discovery — a target whose GitHub pushedAt hasn't
	// moved gets its previous result preseeded (docs/adr/0039-fleet-org-update.md)
	// instead of being rescanned. nil (not an empty map) when --update
	// wasn't passed, so Aggregate.Update.Requested stays accurately false.
	var preseed map[string]fleet.TargetResult
	if opts.Update {
		preseed = map[string]fleet.TargetResult{}
		for _, t := range manifest.Targets {
			if old, ok := shouldPreseedTarget(opts.OutDir, targetHTMLOutDir, targetFormats, opts.RenderHTML, t, oldPushedAt, oldResults); ok {
				preseed[t.Name] = old
			}
		}
	}
	var stderrBuf bytes.Buffer
	progressWriter := io.Writer(stderr)
	progressFormat := opts.ProgressMode
	if progressFormat == "none" {
		progressWriter = nil
	} else if progressFormat == "auto" {
		if isInteractiveTerminal() {
			progressFormat = "plain"
		} else {
			progressFormat = "json"
		}
	}
	collectSuggestions := fleetSuggestionEnrichmentEnabled(opts)
	var draftWriter *targetConfigDraftWriter
	if collectSuggestions {
		draftWriter, err = newTargetConfigDraftWriter(opts.OutDir)
		if err != nil {
			fmt.Fprintf(stderr, "gin-recon: fleet: %v\n", err)
			return cli.ExitOperationalError
		}
	}
	agg, err := fleet.Run(fleetContext, fleet.RunOptions{
		ManifestPath:    manifestPath,
		Manifest:        manifest,
		ManifestData:    manifestData,
		ConfigPath:      effectiveConfigPath,
		Formats:         targetFormats,
		OutDir:          opts.OutDir,
		HTMLOutDir:      targetHTMLOutDir,
		Concurrency:     opts.Concurrency,
		Resume:          opts.Resume,
		BinaryPath:      binaryPath,
		ToolVersion:     report.ToolVersion,
		Stderr:          &stderrBuf,
		Progress:        progressWriter,
		ProgressFormat:  progressFormat,
		AllowRemote:     opts.AllowRemoteTargets,
		AllowedHosts:    allowedHosts,
		AllowDownloads:  opts.AllowDownloads,
		UseTargetConfig: opts.UseTargetConfig,
		TargetConfigDir: effectiveTargetConfigDir,
		RepoAttempts:    opts.RepoAttempts,
		RepoTimeout:     opts.RepoTimeout,
		Preseed:         preseed,
		SuggestAuth:     collectSuggestions,
		Clone:           fleetCloneForTests,
		OnTargetComplete: func(target fleet.Target, result fleet.TargetResult, reuse string) error {
			if draftWriter == nil {
				return nil
			}
			return draftWriter.Write(target, result, reuse)
		},
	})
	if stderrBuf.Len() > 0 {
		stderr.Write(stderrBuf.Bytes())
	}
	if err != nil {
		fmt.Fprintf(stderr, "gin-recon: %v\n", err)
		return cli.ExitOperationalError
	}

	// An --org run that hit --max-repos or the page cap never even
	// discovered every repository, which is a coarser kind of incompleteness
	// than any one target's own scanCoverage.complete — every target that
	// WAS scanned can finish perfectly clean while the fleet as a whole
	// still doesn't cover the organization. docs/adr/0021-fleet-org-enumeration.md
	// says this should read as coverage.complete: false; fold it in here so
	// --fail-on incomplete (and fleet.json/fleet.html) actually reflect it.
	discoveryIncomplete := discoverySummary != nil && !discoverySummary.Complete
	if discoveryIncomplete {
		agg.Coverage.Complete = false
	}
	// Recorded on the aggregate itself, not just used to render fleet.html
	// in this same run — see buildFleetScope's own doc comment
	// (docs/adr/0024-fleet-render.md).
	agg.Scope = buildFleetScope(opts, discoverySummary)
	if scopeFingerprint, err := fleetScopeFingerprint(opts); err != nil {
		fmt.Fprintf(stderr, "gin-recon: fleet: computing scope fingerprint: %v\n", err)
		return cli.ExitOperationalError
	} else {
		agg.ScopeFingerprint = scopeFingerprint
	}
	agg.AuthConfig.MiddlewareCount = len(cfg.AuthMiddleware)
	agg.AuthConfig.WrappersCount = len(cfg.AuthWrappers)
	if cfg.Analysis != nil {
		agg.FollowModulesCount = len(cfg.Analysis.FollowModules)
	}

	data, err := json.MarshalIndent(agg, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "gin-recon: fleet: encoding fleet.json: %v\n", err)
		return cli.ExitOperationalError
	}

	var fleetDelta *fleet.FleetDelta
	// Discovery/config snapshots are companion artifacts, not control state.
	// Write them only after scanning succeeds far enough to build an aggregate;
	// fleet.json remains the final commit marker below.
	if opts.Org != "" {
		if code := writeFleetDiscoveredTargets(opts, manifest, stderr); code != cli.ExitSuccess {
			return code
		}
		if code := writeFleetConfigSnapshot(opts, configSnapshot, stderr); code != cli.ExitSuccess {
			return code
		}
	}
	// Unlike the --org-only snapshots above, this runs for --targets too:
	// --target-config-dir holds individually reviewed authMiddleware
	// evidence, potentially for many repositories, that took real review
	// work to produce — not something a --targets manifest and its own
	// --config can be assumed to already keep durable together the way
	// writeFleetConfigSnapshot's own doc comment reasons about a single
	// shared --config file. A directory the operator points --out at is
	// exactly as capable of being lost as one they point --target-config-dir
	// at, so this run's own --out becomes the durable copy either way.
	if code := writeFleetTargetConfigSnapshot(opts, effectiveTargetConfigDir, stderr); code != cli.ExitSuccess {
		return code
	}
	if opts.Baseline != "" {
		fleetDelta, err = fleet.CompareFleetBaseline(baseline, opts.OutDir, agg)
		if err != nil {
			fmt.Fprintf(stderr, "gin-recon: %v\n", err)
			return cli.ExitOperationalError
		}
		deltaData, err := json.MarshalIndent(fleetDelta, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "gin-recon: fleet: encoding fleet-delta.json: %v\n", err)
			return cli.ExitOperationalError
		}
		if err := fleet.WriteFileAtomic(filepath.Join(opts.OutDir, fleetDeltaFilename), deltaData, 0o644); err != nil {
			fmt.Fprintf(stderr, "gin-recon: %v\n", err)
			return cli.ExitOperationalError
		}
	}

	// fleet.html is opt-in via --render-html, not automatic
	// (docs/adr/0037-fleet-html-opt-in.md) — fleet's own job is the raw
	// scan; rendering it is a separate, explicit decision, the same way
	// `render` already treats a saved fleet.json. When requested, it's
	// regenerated from the same agg/fleetDelta values already computed
	// above, nothing re-read from disk, into the sibling <out>-html
	// directory (docs/adr/0023-fleet-raw-rendered-split.md); RawDirLink is
	// the relative prefix its links to each target's raw routes.json need
	// to cross back into --out.
	if opts.RenderHTML {
		if err := os.MkdirAll(htmlOutDir, 0o755); err != nil {
			fmt.Fprintf(stderr, "gin-recon: %v\n", err)
			return cli.ExitOperationalError
		}
		htmlData, err := format.FleetHTML(agg, fleetDelta, agg.Scope, rawDirLink)
		if err != nil {
			fmt.Fprintf(stderr, "gin-recon: fleet: rendering fleet.html: %v\n", err)
			return cli.ExitOperationalError
		}
		if err := fleet.WriteFileAtomic(htmlPath, htmlData, 0o644); err != nil {
			fmt.Fprintf(stderr, "gin-recon: %v\n", err)
			return cli.ExitOperationalError
		}
	}

	// fleet.json is the commit marker for the run and is therefore written
	// last. A delta/render failure leaves the checkpoint available for a
	// retry and cannot publish a new aggregate that points at incomplete
	// companion artifacts.
	if err := fleet.WriteFileAtomic(aggregatePath, data, 0o644); err != nil {
		fmt.Fprintf(stderr, "gin-recon: %v\n", err)
		return cli.ExitOperationalError
	}
	if collectSuggestions {
		writeFleetAuthSuggestions(agg, opts.OutDir, stderr)
	}
	if agg.Coverage.Complete {
		if err := fleet.RemoveCheckpoint(opts.OutDir); err != nil {
			fmt.Fprintf(stderr, "gin-recon: %v\n", err)
			return cli.ExitOperationalError
		}
	}
	if err := fleetContext.Err(); err != nil {
		fmt.Fprintf(stderr, "gin-recon: fleet deadline exceeded after %s: %v\n", opts.FleetTimeout, err)
		return cli.ExitOperationalError
	}

	for _, sel := range opts.FailOn {
		switch sel {
		case "incomplete":
			if !agg.Coverage.Complete || (fleetDelta != nil && !fleetDelta.Coverage.Complete) {
				return cli.ExitGate
			}
		case "new":
			if fleetDelta.HasNew() {
				return cli.ExitGate
			}
		case "regression":
			if fleetDelta.HasRegression() {
				return cli.ExitGate
			}
		}
	}
	return cli.ExitSuccess
}

func fleetSuggestionEnrichmentEnabled(opts *cli.Options) bool {
	return opts.SuggestAuth || opts.Org != ""
}

// buildFleetAllowedHosts converts fleet.allowedRemoteHosts from --config
// into internal/fleet's own plain-data AllowedHost, so internal/fleet never
// needs to import internal/config (docs/adr/0019-fleet-remote-targets.md).
func buildFleetAllowedHosts(cfg *config.Config) []fleet.AllowedHost {
	if cfg.Fleet == nil {
		return nil
	}
	hosts := make([]fleet.AllowedHost, 0, len(cfg.Fleet.AllowedRemoteHosts))
	for _, h := range cfg.Fleet.AllowedRemoteHosts {
		tokenEnv := h.TokenEnv
		if (h.Host == "github.com" || h.Host == "api.github.com") && (tokenEnv == "GH_TOKEN" || tokenEnv == "GITHUB_TOKEN") {
			tokenEnv = fleetGitHubTokenEnv()
		}
		hosts = append(hosts, fleet.AllowedHost{Host: h.Host, TokenEnv: tokenEnv})
	}
	return hosts
}

// buildFleetScope builds fleet.html's Scope panel data for an --org run —
// nil for a plain --targets run, which has no comparable scope to
// summarize (docs/adr/0021-fleet-org-enumeration.md). Stored on the
// Aggregate itself (docs/adr/0024-fleet-render.md) so a later render pass
// over a saved fleet.json can restore this panel without still having the
// original CLI flags available.
func buildFleetScope(opts *cli.Options, discovery *fleet.DiscoverySummary) *fleet.Scope {
	if opts.Org == "" {
		return nil
	}
	scope := &fleet.Scope{
		Org:                    opts.Org,
		MaxRepos:               opts.MaxRepos,
		Concurrency:            opts.Concurrency,
		IncludeArchived:        opts.IncludeArchived,
		IncludeForks:           opts.IncludeForks,
		RepoInclude:            opts.RepoInclude,
		RepoExclude:            opts.RepoExclude,
		DiscoveryComplete:      discovery == nil || discovery.Complete,
		DiscoveryCompleteKnown: true,
		Discovery:              discovery,
	}
	if scope.MaxRepos == 0 {
		scope.MaxRepos = fleet.DefaultMaxRepos
	}
	return scope
}

func fleetScopeFingerprint(opts *cli.Options) (string, error) {
	type scopeIdentity struct {
		Mode            string   `json:"mode"`
		Organization    string   `json:"organization,omitempty"`
		ManifestPath    string   `json:"manifestPath,omitempty"`
		Repository      string   `json:"repository,omitempty"`
		Ref             string   `json:"ref,omitempty"`
		MaxRepos        int      `json:"maxRepos,omitempty"`
		IncludeArchived bool     `json:"includeArchived,omitempty"`
		IncludeForks    bool     `json:"includeForks,omitempty"`
		RepoInclude     []string `json:"repoInclude,omitempty"`
		RepoExclude     []string `json:"repoExclude,omitempty"`
	}
	identity := scopeIdentity{
		MaxRepos: opts.MaxRepos, IncludeArchived: opts.IncludeArchived,
		IncludeForks: opts.IncludeForks, RepoInclude: opts.RepoInclude, RepoExclude: opts.RepoExclude,
	}
	switch {
	case opts.Org != "":
		identity.Mode, identity.Organization = "github-org", strings.ToLower(opts.Org)
		if identity.MaxRepos == 0 {
			identity.MaxRepos = fleet.DefaultMaxRepos
		}
	case opts.Repo != "":
		identity.Mode, identity.Repository, identity.Ref = "repository", opts.Repo, opts.Ref
	default:
		identity.Mode = "manifest"
		path, err := filepath.Abs(opts.TargetsPath)
		if err != nil {
			return "", err
		}
		identity.ManifestPath = filepath.Clean(path)
	}
	data, err := json.Marshal(identity)
	if err != nil {
		return "", err
	}
	return fleet.FingerprintBytes(data), nil
}

// resolveFleetManifest implements cli.Validate's already-enforced "exactly
// one of --targets or --org" rule: it loads a hand-written manifest, or
// discovers one from a GitHub organization and persists it, so the rest of
// runFleet never needs to know which one happened.
func resolveFleetManifest(ctx context.Context, opts *cli.Options, allowedHosts []fleet.AllowedHost, stderr io.Writer) (manifestPath string, manifest *fleet.Manifest, manifestData []byte, discovery *fleet.DiscoverySummary, exitCode int) {
	if opts.Repo != "" {
		path, m, data, _, code := resolveFleetRepoManifest(opts, stderr)
		return path, m, data, nil, code
	}
	if opts.Org == "" {
		manifest, manifestData, err := fleet.LoadManifest(opts.TargetsPath)
		if err != nil {
			fmt.Fprintf(stderr, "gin-recon: %v\n", err)
			return "", nil, nil, nil, cli.ExitOperationalError
		}
		return opts.TargetsPath, manifest, manifestData, nil, cli.ExitSuccess
	}

	// --org's own network call is gated by the identical two-part rule
	// remote clones already use: --allow-remote-targets (checked by
	// cli.Validate before this function is ever reached) plus an explicit
	// api.github.com entry in fleet.allowedRemoteHosts.
	var token string
	found := false
	for _, h := range allowedHosts {
		if h.Host != "api.github.com" {
			continue
		}
		found = true
		if h.TokenEnv != "" {
			var ok bool
			token, ok = os.LookupEnv(h.TokenEnv)
			if !ok {
				fmt.Fprintf(stderr, "gin-recon: --org: environment variable %q named by fleet.allowedRemoteHosts is not set\n", h.TokenEnv)
				return "", nil, nil, nil, cli.ExitOperationalError
			}
		}
		break
	}
	if !found {
		fmt.Fprintf(stderr, "gin-recon: --org: \"api.github.com\" is not in fleet.allowedRemoteHosts (required to enumerate an organization's repositories)\n")
		return "", nil, nil, nil, cli.ExitOperationalError
	}

	result, err := fleet.DiscoverOrgRepos(ctx, fleet.DiscoverOptions{
		Org:             opts.Org,
		IncludeArchived: opts.IncludeArchived,
		IncludeForks:    opts.IncludeForks,
		RepoInclude:     opts.RepoInclude,
		RepoExclude:     opts.RepoExclude,
		MaxRepos:        opts.MaxRepos,
		Token:           token,
		APIBase:         fleetGitHubAPIBaseForTests,
	})
	if err != nil {
		fmt.Fprintf(stderr, "gin-recon: %v\n", err)
		return "", nil, nil, nil, cli.ExitOperationalError
	}
	if result.Incomplete {
		fmt.Fprintf(stderr, "gin-recon: --org %s: discovery is incomplete (--max-repos or the page cap was reached); rerun with a higher --max-repos for full coverage\n", opts.Org)
	}
	if len(result.SkippedBadName) > 0 {
		fmt.Fprintf(stderr, "gin-recon: --org %s: skipped %d repositories whose name doesn't fit a fleet target name\n", opts.Org, len(result.SkippedBadName))
	}
	if len(result.SkippedDisabled) > 0 {
		fmt.Fprintf(stderr, "gin-recon: --org %s: skipped %d disabled repositories\n", opts.Org, len(result.SkippedDisabled))
	}
	if len(result.SkippedEmpty) > 0 {
		fmt.Fprintf(stderr, "gin-recon: --org %s: skipped %d empty repositories\n", opts.Org, len(result.SkippedEmpty))
	}

	discoveredPath := filepath.Join(opts.OutDir, discoveredTargetsFilename)
	identityData, err := fleetManifestIdentityData(result.Manifest)
	if err != nil {
		fmt.Fprintf(stderr, "gin-recon: --org: %v\n", err)
		return "", nil, nil, nil, cli.ExitOperationalError
	}
	return discoveredPath, result.Manifest, identityData, &result.Summary, cli.ExitSuccess
}

func writeFleetDiscoveredTargets(opts *cli.Options, manifest *fleet.Manifest, stderr io.Writer) int {
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "gin-recon: --org: encoding discovered manifest: %v\n", err)
		return cli.ExitOperationalError
	}
	if err := fleet.WriteFileAtomic(filepath.Join(opts.OutDir, discoveredTargetsFilename), data, 0o644); err != nil {
		fmt.Fprintf(stderr, "gin-recon: %v\n", err)
		return cli.ExitOperationalError
	}
	return cli.ExitSuccess
}

// resolveFleetRepoManifest builds a one-target manifest in memory for
// --repo (docs/adr/0038-fleet-repo-shorthand.md) — the common case of
// auditing exactly one remote repository without hand-writing a manifest
// file first. Goes through fleet.ParseManifest, the identical validation a
// hand-written --targets file already gets (name pattern, https-only URL,
// no embedded userinfo), so nothing here can silently diverge from it; the
// actual clone is still gated by --allow-remote-targets/
// fleet.allowedRemoteHosts exactly as before, checked downstream in
// fleet.Run like any other git target.
func resolveFleetRepoManifest(opts *cli.Options, stderr io.Writer) (manifestPath string, manifest *fleet.Manifest, manifestData []byte, discoveryIncomplete bool, exitCode int) {
	url, name := cli.ParseFleetRepo(opts.Repo)
	data, err := json.Marshal(&fleet.Manifest{Version: 1, Targets: []fleet.Target{
		{Name: name, Git: &fleet.GitSource{URL: url, Ref: opts.Ref}},
	}})
	if err != nil {
		fmt.Fprintf(stderr, "gin-recon: --repo: encoding manifest: %v\n", err)
		return "", nil, nil, false, cli.ExitOperationalError
	}
	m, err := fleet.ParseManifest(data)
	if err != nil {
		fmt.Fprintf(stderr, "gin-recon: --repo: %v\n", err)
		return "", nil, nil, false, cli.ExitOperationalError
	}
	return filepath.Join(opts.OutDir, "repo-target.json"), m, data, false, cli.ExitSuccess
}

// fleetManifestIdentityData returns m's JSON encoding with every target's
// GitHub provenance block stripped, for use as the fleet checkpoint's
// ManifestHash input (docs/adr/0026-fleet-org-resume-ignores-provenance-drift.md).
// GitHubMeta (pushedAt, archived, visibility, ...) drifts on ordinary
// repository activity between two --org discovery calls with zero effect
// on what actually gets scanned — hashing the full discovered-targets.json
// (which keeps GitHubMeta, unaffected by this) made --resume refuse almost
// any real re-run against an active organization.
func fleetManifestIdentityData(m *fleet.Manifest) ([]byte, error) {
	stripped := &fleet.Manifest{Version: m.Version, Targets: make([]fleet.Target, len(m.Targets))}
	for i, t := range m.Targets {
		stripped.Targets[i] = fleet.Target{Name: t.Name, Src: t.Src, Git: t.Git}
	}
	return json.Marshal(stripped)
}

// loadFleetUpdateState reads the last complete fleet.json at opts.OutDir.
// Both GitHub pushedAt provenance and per-target results come from that one
// committed document; discovered-targets.json is only an audit companion and
// is never trusted as update control state (docs/adr/0039-fleet-org-update.md).
// Both returned maps are empty when --update was not requested, no prior run
// exists, or the prior state cannot be validated, making every target fall
// through to a real scan.
func loadFleetUpdateState(opts *cli.Options, stderr io.Writer) (pushedAt map[string]string, results map[string]fleet.TargetResult) {
	pushedAt = map[string]string{}
	results = map[string]fleet.TargetResult{}
	if !opts.Update {
		return pushedAt, results
	}
	data, err := fleet.ReadBoundedFile(filepath.Join(opts.OutDir, fleetAggregateFilename))
	if err != nil {
		return pushedAt, results
	}
	agg, parseErr := fleet.ParseAggregate(data, true)
	if parseErr != nil {
		fmt.Fprintf(stderr, "gin-recon: --update: previous fleet aggregate at %q is invalid (%v); performing a full rescan\n", opts.OutDir, parseErr)
		return pushedAt, results
	}
	// A prior run under a different toolVersion may have classified routes
	// under different rules entirely — reusing its results unchanged could
	// silently present outdated classification as current. Matches a
	// sibling tool's own real check here (confirmed directly against its
	// source, not assumed), adapted to gin-recon's own field name: refuse
	// every reuse rather than any, so the discrepancy can't go unnoticed
	// for only some targets.
	if agg.ToolVersion != "" && agg.ToolVersion != report.ToolVersion {
		fmt.Fprintf(stderr, "gin-recon: --update: previous run at %q used toolVersion %s, this binary is %s; performing a full rescan\n", opts.OutDir, agg.ToolVersion, report.ToolVersion)
		return pushedAt, results
	}
	// A --config change between the previous run and this one may mean a
	// route's proven/public/unknown classification is now stale — reusing it
	// unchanged would silently present an outdated classification as current.
	// A --format change means the previous run's own artifacts may not even
	// cover what this run was asked to produce (e.g. openapi newly added).
	// Both refuse every reuse, the same whole-run "refuse rather than guess"
	// toolVersion already applies above, mirroring --resume's identical
	// checkpoint-identity check (checkpoint.go's loadCheckpoint) — a
	// pre-fix fleet.json (empty ConfigHash/Formats) is treated as unknown,
	// also refusing reuse, once rather than every run after upgrading.
	currentConfigHash, hashErr := fleet.HashConfigFile(opts.ConfigPath)
	targetFormats := make([]string, len(opts.Formats))
	for i, f := range opts.Formats {
		targetFormats[i] = string(f)
	}
	if hashErr != nil || agg.ConfigHash != currentConfigHash {
		fmt.Fprintf(stderr, "gin-recon: --update: --config has changed since the previous run at %q; performing a full rescan\n", opts.OutDir)
		return pushedAt, results
	}
	if !slices.Equal(agg.Formats, targetFormats) {
		fmt.Fprintf(stderr, "gin-recon: --update: --format has changed since the previous run at %q; performing a full rescan\n", opts.OutDir)
		return pushedAt, results
	}
	targetConfigHash, hashErr := fleet.HashTargetConfigDirectory(opts.TargetConfigDir)
	if hashErr != nil || agg.TargetConfigHash != targetConfigHash || agg.AllowDownloads != opts.AllowDownloads || agg.UseTargetConfig != opts.UseTargetConfig || agg.RenderHTML != opts.RenderHTML || agg.RepoAttempts != opts.RepoAttempts || agg.RepoTimeout != opts.RepoTimeout.String() {
		fmt.Fprintf(stderr, "gin-recon: --update: scan or target-config options changed since the previous run at %q; performing a full rescan\n", opts.OutDir)
		return pushedAt, results
	}
	if agg.SchemaVersion != "1.0" || agg.Kind != "fleet" || agg.Tool != "gin-recon" || !agg.Coverage.Complete {
		fmt.Fprintf(stderr, "gin-recon: --update: previous fleet aggregate at %q is incompatible or incomplete; performing a full rescan\n", opts.OutDir)
		return pushedAt, results
	}
	seen := make(map[string]bool, len(agg.Targets))
	for _, t := range agg.Targets {
		if err := fleet.ValidTargetName(t.Name); err != nil || seen[t.Name] {
			fmt.Fprintf(stderr, "gin-recon: --update: previous fleet aggregate at %q has invalid or duplicate targets; performing a full rescan\n", opts.OutDir)
			return map[string]string{}, map[string]fleet.TargetResult{}
		}
		seen[t.Name] = true
		results[t.Name] = t
		if t.Repository != nil && t.Repository.PushedAt != "" {
			pushedAt[t.Name] = t.Repository.PushedAt
		}
	}
	return pushedAt, results
}

// shouldPreseedTarget decides whether t's previous result (from oldResults,
// keyed by the same --update state loadFleetUpdateState produces) should be
// reused instead of rescanning t: t must be an --org-discovered target
// (t.GitHub set) whose GitHub pushedAt exactly matches what it was at the
// previous complete run, whose previous status was ok or not-go-module, and
// whose exact artifact set for the requested formats still passes size and
// SHA-256 verification. Someone deleting or modifying part of --out's target
// tree must never produce a "complete" reused result with stale evidence.
func shouldPreseedTarget(outDir, htmlOutDir string, formats []string, renderHTML bool, t fleet.Target, oldPushedAt map[string]string, oldResults map[string]fleet.TargetResult) (fleet.TargetResult, bool) {
	if t.GitHub == nil || t.GitHub.PushedAt == "" {
		return fleet.TargetResult{}, false
	}
	old, ok := oldResults[t.Name]
	if !ok || (old.Status != fleet.StatusOK && old.Status != fleet.StatusNotGoModule) {
		return fleet.TargetResult{}, false
	}
	if oldPushedAt[t.Name] != t.GitHub.PushedAt {
		return fleet.TargetResult{}, false
	}
	if err := fleet.ValidateReusableTarget(outDir, htmlOutDir, old, t, formats, renderHTML); err != nil {
		return fleet.TargetResult{}, false
	}
	return old, true
}

// writeFleetConfigSnapshot copies opts.ConfigPath's exact bytes into --out
// as configSnapshotBasename, preserving the source's own extension, so an
// --org run's classification config survives independent of the original
// --config path later moving or changing — docs/adr/0025-fleet-org-config-snapshot.md.
// A no-op for a --targets run (its own manifest/config are expected to
// already be version-controlled together) or when --config wasn't given
// (--config is optional for fleet; nothing to snapshot).
func writeFleetConfigSnapshot(opts *cli.Options, data []byte, stderr io.Writer) int {
	if opts.Org == "" || opts.ConfigPath == "" {
		return cli.ExitSuccess
	}
	ext := filepath.Ext(opts.ConfigPath)
	if ext == "" {
		ext = ".json"
	}
	dest := filepath.Join(opts.OutDir, configSnapshotBasename+ext)
	if err := fleet.WriteFileAtomic(dest, data, 0o644); err != nil {
		fmt.Fprintf(stderr, "gin-recon: %v\n", err)
		return cli.ExitOperationalError
	}
	return cli.ExitSuccess
}

// isExistingDir reports whether path is an existing, real (non-symlink)
// directory — used only to detect a prior run's own published
// target-configs-snapshot/, never to validate untrusted input (that's
// cli.Validate's job for the --target-config-dir flag itself).
func isExistingDir(path string) bool {
	fi, err := os.Lstat(path)
	return err == nil && fi.IsDir()
}

func reusableTargetConfigSnapshot(path, aggregatePath string) (bool, error) {
	if !isExistingDir(path) {
		return false, nil
	}
	data, err := fleet.ReadBoundedFile(filepath.Join(path, targetConfigsSnapshotMarker))
	markedComplete := err == nil && string(data) == "target-config-snapshot-v1\n"
	// fleet.json's committed content hash remains the authority. The marker
	// distinguishes a staged publication from a legacy directory, but neither
	// is trusted unless its reviewed bytes still match the committed aggregate.
	aggregateData, readErr := fleet.ReadBoundedFile(aggregatePath)
	if readErr != nil {
		return false, fmt.Errorf("%s cannot be verified against %s: %w", path, aggregatePath, readErr)
	}
	var prior struct {
		TargetConfigHash string `json:"targetConfigHash"`
	}
	if err := json.Unmarshal(aggregateData, &prior); err != nil {
		return false, fmt.Errorf("%s exists without a completion marker and %s is invalid: %w", path, aggregatePath, err)
	}
	effective, cleanup, err := freezeFleetTargetConfigDir(path)
	if err != nil {
		return false, fmt.Errorf("verifying %s: %w", path, err)
	}
	defer cleanup()
	actualHash, err := fleet.HashTargetConfigDirectory(effective)
	if err != nil {
		return false, fmt.Errorf("hashing %s: %w", path, err)
	}
	if prior.TargetConfigHash == "" || actualHash != prior.TargetConfigHash {
		markerNote := ""
		if !markedComplete {
			markerNote = " without a completion marker"
		}
		return false, fmt.Errorf("%s exists%s and does not match the targetConfigHash in %s; pass an explicit reviewed --target-config-dir", path, markerNote, aggregatePath)
	}
	return true, nil
}

// writeFleetTargetConfigSnapshot copies sourceDir — the already-frozen,
// already-validated effective --target-config-dir (see
// freezeFleetTargetConfigDir: no symlinks, no path escapes, bounded size)
// — into --out/targetConfigsSnapshotDirName, so this run's own published
// output carries a durable copy of exactly which reviewed per-target configs
// produced it, independent of the operator's original directory later being
// moved, edited, or lost entirely. A no-op when --target-config-dir wasn't
// given (sourceDir is only ever "" in that case, mirroring
// freezeFleetTargetConfigDir's own contract).
func writeFleetTargetConfigSnapshot(opts *cli.Options, sourceDir string, stderr io.Writer) int {
	if sourceDir == "" {
		return cli.ExitSuccess
	}
	dest := filepath.Join(opts.OutDir, targetConfigsSnapshotDirName)
	staged, err := os.MkdirTemp(opts.OutDir, ".target-configs-snapshot-stage-*")
	if err != nil {
		fmt.Fprintf(stderr, "gin-recon: fleet: staging %s: %v\n", targetConfigsSnapshotDirName, err)
		return cli.ExitOperationalError
	}
	defer os.RemoveAll(staged)
	err = filepath.WalkDir(sourceDir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(sourceDir, path)
		if err != nil {
			return err
		}
		destPath := filepath.Join(staged, rel)
		if entry.IsDir() {
			return os.MkdirAll(destPath, 0o700)
		}
		data, err := fleet.ReadBoundedFile(path)
		if err != nil {
			return err
		}
		return fleet.WriteFileAtomic(destPath, data, 0o600)
	})
	if err != nil {
		fmt.Fprintf(stderr, "gin-recon: fleet: snapshotting --target-config-dir into %s: %v\n", targetConfigsSnapshotDirName, err)
		return cli.ExitOperationalError
	}
	if err := fleet.WriteFileAtomic(filepath.Join(staged, targetConfigsSnapshotMarker), []byte("target-config-snapshot-v1\n"), 0o600); err != nil {
		fmt.Fprintf(stderr, "gin-recon: fleet: completing %s: %v\n", targetConfigsSnapshotDirName, err)
		return cli.ExitOperationalError
	}
	if err := fleet.PublishDirectory(staged, dest); err != nil {
		fmt.Fprintf(stderr, "gin-recon: fleet: publishing %s: %v\n", targetConfigsSnapshotDirName, err)
		return cli.ExitOperationalError
	}
	return cli.ExitSuccess
}

func freezeFleetConfig(path string) (effective string, data []byte, cleanup func(), err error) {
	if path == "" {
		return "", nil, func() {}, nil
	}
	data, err = fleet.ReadBoundedFile(path)
	if err != nil {
		return "", nil, func() {}, err
	}
	dir, err := os.MkdirTemp("", "gin-recon-fleet-config-*")
	if err != nil {
		return "", nil, func() {}, err
	}
	cleanup = func() { _ = os.RemoveAll(dir) }
	effective = filepath.Join(dir, "config"+filepath.Ext(path))
	if err := fleet.WriteFileAtomic(effective, data, 0o600); err != nil {
		cleanup()
		return "", nil, func() {}, err
	}
	return effective, data, cleanup, nil
}

func freezeFleetTargetConfigDir(path string) (effective string, cleanup func(), err error) {
	if path == "" {
		return "", func() {}, nil
	}
	tempRoot, err := os.MkdirTemp("", "gin-recon-fleet-target-configs-*")
	if err != nil {
		return "", func() {}, err
	}
	cleanup = func() { _ = os.RemoveAll(tempRoot) }
	effective = filepath.Join(tempRoot, "configs")
	const maxFiles = 10_000
	const maxBytes int64 = 100 << 20
	files := 0
	var bytes int64
	err = filepath.WalkDir(path, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s is a symlink", current)
		}
		if !entry.IsDir() && entry.Name() == targetConfigsSnapshotMarker {
			return nil
		}
		rel, err := filepath.Rel(path, current)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return fmt.Errorf("%s escapes the target config directory", current)
		}
		destination := filepath.Join(effective, rel)
		if entry.IsDir() {
			return os.MkdirAll(destination, 0o700)
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("%s is not a regular file", current)
		}
		files++
		if files > maxFiles {
			return fmt.Errorf("directory exceeds %d files", maxFiles)
		}
		data, err := fleet.ReadBoundedFile(current)
		if err != nil {
			return err
		}
		bytes += int64(len(data))
		if bytes > maxBytes {
			return fmt.Errorf("directory exceeds %d bytes", maxBytes)
		}
		return fleet.WriteFileAtomic(destination, data, 0o600)
	})
	if err != nil {
		cleanup()
		return "", func() {}, err
	}
	return effective, cleanup, nil
}

// runFleetRender re-renders every target recorded `ok` in a saved
// fleet.json, without re-scanning any of them, then regenerates
// fleet.html — docs/adr/0024-fleet-render.md's fleet-shaped counterpart to
// runRender's own single-report path. data is opts.ReportPath's
// already-read bytes (runRender read them once to detect the report
// kind); reused here rather than read a second time.
func runFleetRender(opts *cli.Options, data []byte, stdout, stderr io.Writer) int {
	// No --out re-renders in place: --report's own directory (a saved
	// fleet.json's raw root, e.g. .gin-recon/<org>/fleet.json) is the
	// obvious default raw root to write back into, matching how a live
	// fleet run's --out already means "the raw root" — so
	// `render --report .gin-recon/<org>/fleet.json --force` alone
	// regenerates .gin-recon/<org>-html/ with no --out needed
	// (docs/adr/0028-gin-recon-default-output-directory.md).
	if opts.OutDir == "" {
		opts.OutDir = filepath.Dir(opts.ReportPath)
	}
	// A fleet render always overwrites every target's own already-computed
	// output (that is the entire operation) — requiring --force up front
	// avoids a confusing partial run that fails on the first target whose
	// file already exists.
	if !opts.Force {
		fmt.Fprintf(stderr, "gin-recon: fleet render: --force is required — a fleet render always overwrites each target's own previously rendered output\n")
		return cli.ExitOperationalError
	}
	aggPtr, err := fleet.ParseAggregate(data, true)
	if err != nil {
		fmt.Fprintf(stderr, "gin-recon: --report: decoding fleet.json: %v\n", err)
		return cli.ExitOperationalError
	}
	agg := *aggPtr

	cfg, err := loadConfig(opts.ConfigPath)
	if err != nil {
		fmt.Fprintf(stderr, "gin-recon: %v\n", err)
		return cli.ExitOperationalError
	}
	// Refreshed the same way Routes/Proven/Public/Unknown are below: this
	// render's own --config, not whatever the original fleet run's --config
	// happened to contain, is what actually governs the re-render fleet.html
	// is about to describe (docs/adr/0030-fleet-html-auth-config-visibility.md).
	agg.AuthConfig.MiddlewareCount = len(cfg.AuthMiddleware)
	agg.AuthConfig.WrappersCount = len(cfg.AuthWrappers)
	if cfg.Analysis != nil {
		agg.FollowModulesCount = len(cfg.Analysis.FollowModules)
	}
	for _, f := range opts.Formats {
		if !formatsImplemented[f] {
			fmt.Fprintf(stderr, "gin-recon: --format %s is not implemented yet; %s\n", f, implementedFormatsMessage)
			return cli.ExitOperationalError
		}
	}

	rawDir := opts.OutDir
	htmlOutDir, rawDirLink, err := fleetHTMLSibling(rawDir)
	if err != nil {
		fmt.Fprintf(stderr, "gin-recon: %v\n", err)
		return cli.ExitOperationalError
	}
	if err := os.MkdirAll(htmlOutDir, 0o755); err != nil {
		fmt.Fprintf(stderr, "gin-recon: %v\n", err)
		return cli.ExitOperationalError
	}
	// Each target's own already-computed routes.json is resolved relative
	// to the loaded fleet.json's own directory — the same convention
	// fleet.CompareBaseline already uses for a --baseline's targets.
	fleetJSONDir := filepath.Dir(opts.ReportPath)

	// --report is an arbitrary, potentially untrusted file (docs/threat-model.md
	// treats every scanned-repo/report input as adversarial): every target's
	// Name is validated up front, before any of it is used to build a
	// filesystem path below, and duplicates are rejected outright rather than
	// letting two targets silently clobber the same output directory.
	seenNames := make(map[string]bool, len(agg.Targets))
	for _, t := range agg.Targets {
		if err := fleet.ValidTargetName(t.Name); err != nil {
			fmt.Fprintf(stderr, "gin-recon: --report: %v\n", err)
			return cli.ExitOperationalError
		}
		if seenNames[t.Name] {
			fmt.Fprintf(stderr, "gin-recon: --report: duplicate target name %q\n", t.Name)
			return cli.ExitOperationalError
		}
		seenNames[t.Name] = true
	}

	// A saved fleet always retains routes.json as its canonical evidence,
	// even when this render asks only for a presentation format. This also
	// makes rendering to a different --out self-contained instead of leaving
	// its new fleet.json pointing back at the input tree.
	renderFormats := []cli.OutputFormat{cli.FormatJSON}
	for _, f := range opts.Formats {
		if f != cli.FormatJSON {
			renderFormats = append(renderFormats, f)
		}
	}
	hasOpenAPI := slices.Contains(renderFormats, cli.FormatOpenAPI)

	for i, t := range agg.Targets {
		if t.Status != fleet.StatusOK {
			continue // render reformats what exists; it does not retry a failed or non-module target
		}

		modules := append([]fleet.ModuleResult(nil), t.Modules...)
		if len(modules) == 0 {
			// Upgrade a pre-module-schema aggregate in memory. New aggregates
			// already carry this record even for a one-module repository.
			modules = []fleet.ModuleResult{{ID: "root", Path: ".", Status: t.Status, Complete: t.Complete, Report: t.Report}}
		}
		multiModule := len(modules) > 1

		agg.Targets[i].Routes, agg.Targets[i].Proven = 0, 0
		agg.Targets[i].Public, agg.Targets[i].Unknown = 0, 0
		agg.Targets[i].Specifications = nil
		agg.Targets[i].Report, agg.Targets[i].APIHTML = "", ""
		agg.Targets[i].Artifacts = nil

		for moduleIndex := range modules {
			moduleResult := &modules[moduleIndex]
			if multiModule {
				if err := fleet.ValidModuleID(moduleResult.ID); err != nil {
					fmt.Fprintf(stderr, "gin-recon: fleet render: target %q: %v\n", t.Name, err)
					return cli.ExitOperationalError
				}
			}
			if moduleResult.Status != fleet.StatusOK {
				// A successful application target can retain an unsuccessful
				// tooling/sibling module. It has no published report to render;
				// preserve the failure instead of inventing a routes.json path.
				moduleResult.Report, moduleResult.APIHTML = "", ""
				moduleResult.Artifacts, moduleResult.SuggestionArtifact = nil, nil
				moduleResult.Routes, moduleResult.Proven = 0, 0
				moduleResult.Public, moduleResult.Unknown = 0, 0
				continue
			}

			reportRel := filepath.Join("targets", t.Name, "routes.json")
			if multiModule {
				reportRel = filepath.Join("targets", t.Name, "modules", moduleResult.ID, "routes.json")
			}
			if moduleResult.Report != "" && filepath.Clean(filepath.FromSlash(moduleResult.Report)) != reportRel {
				fmt.Fprintf(stderr, "gin-recon: fleet render: target %q module %q has non-canonical report path %q\n", t.Name, moduleResult.ID, moduleResult.Report)
				return cli.ExitOperationalError
			}
			routesPath, err := fleet.ResolveArtifactPath(fleetJSONDir, reportRel)
			if err != nil {
				fmt.Fprintf(stderr, "gin-recon: fleet render: target %q: %v\n", t.Name, err)
				return cli.ExitOperationalError
			}
			if err := fleet.RegularFileNoSymlink(routesPath); err != nil {
				fmt.Fprintf(stderr, "gin-recon: fleet render: target %q: %v\n", t.Name, err)
				return cli.ExitOperationalError
			}
			rep, err := loadReportFile(routesPath)
			if err != nil {
				fmt.Fprintf(stderr, "gin-recon: fleet render: target %q: %v\n", t.Name, err)
				return cli.ExitOperationalError
			}
			if err := validateRenderedReport(rep); err != nil {
				fmt.Fprintf(stderr, "gin-recon: fleet render: target %q: %v\n", t.Name, err)
				return cli.ExitOperationalError
			}

			moduleResult.Routes, moduleResult.Proven = 0, 0
			moduleResult.Public, moduleResult.Unknown = 0, 0
			moduleResult.Specifications = rep.Specifications
			if rep.Summary != nil {
				moduleResult.Routes = rep.Summary.TotalRoutes
				moduleResult.Proven = rep.Summary.ProvenByConfirmedShape + rep.Summary.ProvenByAttestedUnresolved
				moduleResult.Public = rep.Summary.Public
				moduleResult.Unknown = rep.Summary.Unknown
			}
			moduleResult.Report = filepath.ToSlash(reportRel)
			moduleResult.APIHTML = ""
			moduleResult.Artifacts = nil
			if moduleResult.Specifications != nil {
				agg.Targets[i].Specifications = append(agg.Targets[i].Specifications, fleet.ModuleSpecificationSummary{ModuleID: moduleResult.ID, ModulePath: moduleResult.ModulePath, Catalog: moduleResult.Specifications})
			}

			targetRawOut, err := fleet.ResolveArtifactPath(rawDir, filepath.Dir(reportRel))
			if err != nil {
				fmt.Fprintf(stderr, "gin-recon: fleet render: target %q: %v\n", t.Name, err)
				return cli.ExitOperationalError
			}
			targetOpts := &cli.Options{Command: cli.CommandRender, OutDir: targetRawOut, Formats: renderFormats, Force: true}
			if code := writeReport(rep, targetOpts, cfg, stdout, stderr, cli.ExitSuccess); code != cli.ExitSuccess {
				return code
			}

			if hasOpenAPI {
				srcHTML := filepath.Join(targetRawOut, htmlCompanionFilename)
				htmlRel := filepath.Join(filepath.Dir(reportRel), htmlCompanionFilename)
				htmlData, err := fleet.ReadBoundedFile(srcHTML)
				if err != nil {
					fmt.Fprintf(stderr, "gin-recon: fleet render: target %q: reading rendered HTML: %v\n", t.Name, err)
					return cli.ExitOperationalError
				}
				destHTML, err := fleet.ResolveArtifactPath(htmlOutDir, htmlRel)
				if err != nil {
					fmt.Fprintf(stderr, "gin-recon: fleet render: target %q: %v\n", t.Name, err)
					return cli.ExitOperationalError
				}
				if err := fleet.WriteFileAtomic(destHTML, htmlData, 0o644); err != nil {
					fmt.Fprintf(stderr, "gin-recon: %v\n", err)
					return cli.ExitOperationalError
				}
				if err := os.Remove(srcHTML); err != nil {
					fmt.Fprintf(stderr, "gin-recon: %v\n", err)
					return cli.ExitOperationalError
				}
				moduleResult.APIHTML = filepath.ToSlash(htmlRel)
			}

			seenArtifacts := map[string]bool{}
			for _, f := range renderFormats {
				name := formatFilename(f)
				if seenArtifacts[name] {
					continue
				}
				seenArtifacts[name] = true
				artifactRel := filepath.Join(filepath.Dir(reportRel), name)
				artifact, err := fleet.RecordArtifact("raw", rawDir, artifactRel)
				if err != nil {
					fmt.Fprintf(stderr, "gin-recon: fleet render: target %q: recording %s integrity: %v\n", t.Name, name, err)
					return cli.ExitOperationalError
				}
				moduleResult.Artifacts = append(moduleResult.Artifacts, artifact)
			}
			if moduleResult.APIHTML != "" {
				artifact, err := fleet.RecordArtifact("html", htmlOutDir, moduleResult.APIHTML)
				if err != nil {
					fmt.Fprintf(stderr, "gin-recon: fleet render: target %q: recording HTML integrity: %v\n", t.Name, err)
					return cli.ExitOperationalError
				}
				moduleResult.Artifacts = append(moduleResult.Artifacts, artifact)
			}

			agg.Targets[i].Routes += moduleResult.Routes
			agg.Targets[i].Proven += moduleResult.Proven
			agg.Targets[i].Public += moduleResult.Public
			agg.Targets[i].Unknown += moduleResult.Unknown
			agg.Targets[i].Artifacts = append(agg.Targets[i].Artifacts, moduleResult.Artifacts...)
		}

		agg.Targets[i].Modules = modules
		if len(modules) == 1 {
			agg.Targets[i].Report = modules[0].Report
			agg.Targets[i].APIHTML = modules[0].APIHTML
		}
	}

	agg.Totals.Routes, agg.Totals.Proven, agg.Totals.Public, agg.Totals.Unknown = 0, 0, 0, 0
	agg.RepositoryStatus.OK, agg.RepositoryStatus.Failed = 0, 0
	agg.RepositoryStatus.Inconclusive, agg.RepositoryStatus.NotGoModule = 0, 0
	agg.Specifications.RepositoriesWithSpecifications, agg.Specifications.Specifications = 0, 0
	for _, t := range agg.Targets {
		agg.Totals.Routes += t.Routes
		agg.Totals.Proven += t.Proven
		agg.Totals.Public += t.Public
		agg.Totals.Unknown += t.Unknown
		switch t.Status {
		case fleet.StatusOK:
			agg.RepositoryStatus.OK++
		case fleet.StatusFailed:
			agg.RepositoryStatus.Failed++
		case fleet.StatusInconclusive:
			agg.RepositoryStatus.Inconclusive++
		case fleet.StatusNotGoModule:
			agg.RepositoryStatus.NotGoModule++
		}
		hasSpecifications := false
		for _, module := range t.Specifications {
			if module.Catalog == nil {
				continue
			}
			if n := len(module.Catalog.Specifications); n > 0 {
				agg.Specifications.Specifications += n
				hasSpecifications = true
			}
		}
		if hasSpecifications {
			agg.Specifications.RepositoriesWithSpecifications++
		}
	}
	agg.Formats = make([]string, len(opts.Formats))
	for i, f := range opts.Formats {
		agg.Formats[i] = string(f)
	}
	agg.RenderHTML = true
	agg.RepositoryGroups = fleet.GroupRepositories(agg.Targets)
	fleet.RefreshScanFingerprint(&agg)

	// fleet.json itself is updated too, not just fleet.html — each target's
	// APIHTML just changed, and docs/adr/0024-fleet-render.md's whole
	// premise (fleet.json as a complete, durable record) breaks if the
	// file on disk silently falls out of sync with what was just rendered.
	aggData, err := json.MarshalIndent(&agg, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "gin-recon: fleet render: encoding fleet.json: %v\n", err)
		return cli.ExitOperationalError
	}
	htmlData, err := format.FleetHTML(&agg, nil, agg.Scope, rawDirLink)
	if err != nil {
		fmt.Fprintf(stderr, "gin-recon: fleet render: rendering fleet.html: %v\n", err)
		return cli.ExitOperationalError
	}
	if err := fleet.WriteFileAtomic(filepath.Join(htmlOutDir, fleetHTMLFilename), htmlData, 0o644); err != nil {
		fmt.Fprintf(stderr, "gin-recon: %v\n", err)
		return cli.ExitOperationalError
	}
	// fleet.json is the render commit marker and is written only after every
	// target artifact and fleet.html have been durably replaced.
	if err := fleet.WriteFileAtomic(filepath.Join(rawDir, fleetAggregateFilename), aggData, 0o644); err != nil {
		fmt.Fprintf(stderr, "gin-recon: %v\n", err)
		return cli.ExitOperationalError
	}
	return cli.ExitSuccess
}
