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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

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

// runFleet is the command's entry point: resolve the target manifest (a
// hand-written file or a discovered --org), load any --baseline up front,
// run the fleet, then write its aggregate/delta/HTML outputs and evaluate
// --fail-on. Each step below is a named stage rather than one long
// sequence — resolveFleetManifest, buildFleetAllowedHosts, and
// buildFleetScope each own one concern so this function reads as the
// stages of a fleet run, not an undifferentiated block.
func runFleet(opts *cli.Options, stdout, stderr io.Writer) int {
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
	cfg, err := loadConfig(opts.ConfigPath)
	if err != nil {
		fmt.Fprintf(stderr, "gin-recon: %v\n", err)
		return cli.ExitOperationalError
	}
	allowedHosts := buildFleetAllowedHosts(cfg)

	manifestPath, manifest, manifestData, discoveryIncomplete, exitCode := resolveFleetManifest(opts, allowedHosts, stderr)
	if exitCode != cli.ExitSuccess {
		return exitCode
	}
	if code := writeFleetConfigSnapshot(opts, stderr); code != cli.ExitSuccess {
		return code
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

	// --out is the raw-artifacts root; every HTML file gin-recon fleet
	// produces lands in the sibling <out>-html directory instead (or, for
	// --out ".", nested inside it — see fleetHTMLSibling)
	// (docs/adr/0023-fleet-raw-rendered-split.md) — derived automatically,
	// no separate flag, no separate render step to remember to run.
	htmlOutDir, rawDirLink, err := fleetHTMLSibling(opts.OutDir)
	if err != nil {
		fmt.Fprintf(stderr, "gin-recon: %v\n", err)
		return cli.ExitOperationalError
	}
	aggregatePath := filepath.Join(opts.OutDir, fleetAggregateFilename)
	htmlPath := filepath.Join(htmlOutDir, fleetHTMLFilename)
	checkExists := []string{aggregatePath, htmlPath}
	if opts.Baseline != "" {
		checkExists = append(checkExists, filepath.Join(opts.OutDir, fleetDeltaFilename))
	}
	if !opts.Force && !opts.Resume {
		for _, p := range checkExists {
			if _, err := os.Stat(p); err == nil {
				fmt.Fprintf(stderr, "gin-recon: %s already exists; pass --force to overwrite or --resume to continue\n", p)
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

	var stderrBuf bytes.Buffer
	agg, err := fleet.Run(context.Background(), fleet.RunOptions{
		ManifestPath:    manifestPath,
		Manifest:        manifest,
		ManifestData:    manifestData,
		ConfigPath:      opts.ConfigPath,
		Formats:         targetFormats,
		OutDir:          opts.OutDir,
		HTMLOutDir:      htmlOutDir,
		Concurrency:     opts.Concurrency,
		Resume:          opts.Resume,
		BinaryPath:      binaryPath,
		ToolVersion:     report.ToolVersion,
		Stderr:          &stderrBuf,
		Progress:        stderr,
		AllowRemote:     opts.AllowRemoteTargets,
		AllowedHosts:    allowedHosts,
		AllowDownloads:  opts.AllowDownloads,
		UseTargetConfig: opts.UseTargetConfig,
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
	if discoveryIncomplete {
		agg.Coverage.Complete = false
	}
	// Recorded on the aggregate itself, not just used to render fleet.html
	// in this same run — see buildFleetScope's own doc comment
	// (docs/adr/0024-fleet-render.md).
	agg.Scope = buildFleetScope(opts, discoveryIncomplete)
	agg.AuthConfig.MiddlewareCount = len(cfg.AuthMiddleware)
	agg.AuthConfig.WrappersCount = len(cfg.AuthWrappers)

	data, err := json.MarshalIndent(agg, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "gin-recon: fleet: encoding fleet.json: %v\n", err)
		return cli.ExitOperationalError
	}
	if err := os.WriteFile(aggregatePath, data, 0o644); err != nil {
		fmt.Fprintf(stderr, "gin-recon: %v\n", err)
		return cli.ExitOperationalError
	}

	var fleetDelta *fleet.FleetDelta
	if opts.Baseline != "" {
		fleetDelta, err = fleet.CompareBaseline(baseline, opts.OutDir, agg.Targets)
		if err != nil {
			fmt.Fprintf(stderr, "gin-recon: %v\n", err)
			return cli.ExitOperationalError
		}
		deltaData, err := json.MarshalIndent(fleetDelta, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "gin-recon: fleet: encoding fleet-delta.json: %v\n", err)
			return cli.ExitOperationalError
		}
		if err := os.WriteFile(filepath.Join(opts.OutDir, fleetDeltaFilename), deltaData, 0o644); err != nil {
			fmt.Fprintf(stderr, "gin-recon: %v\n", err)
			return cli.ExitOperationalError
		}
	}

	// fleet.html is an unconditional companion to fleet.json, the same
	// relationship api.html already has with openapi.json
	// (docs/adr/0020-fleet-html-view.md) — no separate flag, always
	// regenerated from the same agg/fleetDelta values already computed
	// above, nothing re-read from disk. It lives in the sibling <out>-html
	// directory (docs/adr/0023-fleet-raw-rendered-split.md), so its links
	// to each target's raw routes.json cross back into --out; RawDirLink is
	// that relative prefix, computed once here rather than baked into
	// internal/format, which has no reason to know about this layout.
	if err := os.MkdirAll(htmlOutDir, 0o755); err != nil {
		fmt.Fprintf(stderr, "gin-recon: %v\n", err)
		return cli.ExitOperationalError
	}
	htmlData, err := format.FleetHTML(agg, fleetDelta, agg.Scope, rawDirLink)
	if err != nil {
		fmt.Fprintf(stderr, "gin-recon: fleet: rendering fleet.html: %v\n", err)
		return cli.ExitOperationalError
	}
	if err := os.WriteFile(htmlPath, htmlData, 0o644); err != nil {
		fmt.Fprintf(stderr, "gin-recon: %v\n", err)
		return cli.ExitOperationalError
	}

	for _, sel := range opts.FailOn {
		switch sel {
		case "incomplete":
			if !agg.Coverage.Complete {
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

// buildFleetAllowedHosts converts fleet.allowedRemoteHosts from --config
// into internal/fleet's own plain-data AllowedHost, so internal/fleet never
// needs to import internal/config (docs/adr/0019-fleet-remote-targets.md).
func buildFleetAllowedHosts(cfg *config.Config) []fleet.AllowedHost {
	if cfg.Fleet == nil {
		return nil
	}
	hosts := make([]fleet.AllowedHost, 0, len(cfg.Fleet.AllowedRemoteHosts))
	for _, h := range cfg.Fleet.AllowedRemoteHosts {
		hosts = append(hosts, fleet.AllowedHost{Host: h.Host, TokenEnv: h.TokenEnv})
	}
	return hosts
}

// buildFleetScope builds fleet.html's Scope panel data for an --org run —
// nil for a plain --targets run, which has no comparable scope to
// summarize (docs/adr/0021-fleet-org-enumeration.md). Stored on the
// Aggregate itself (docs/adr/0024-fleet-render.md) so a later render pass
// over a saved fleet.json can restore this panel without still having the
// original CLI flags available.
func buildFleetScope(opts *cli.Options, discoveryIncomplete bool) *fleet.Scope {
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
		DiscoveryComplete:      !discoveryIncomplete,
		DiscoveryCompleteKnown: true,
	}
	if scope.MaxRepos == 0 {
		scope.MaxRepos = fleet.DefaultMaxRepos
	}
	return scope
}

// resolveFleetManifest implements cli.Validate's already-enforced "exactly
// one of --targets or --org" rule: it loads a hand-written manifest, or
// discovers one from a GitHub organization and persists it, so the rest of
// runFleet never needs to know which one happened.
func resolveFleetManifest(opts *cli.Options, allowedHosts []fleet.AllowedHost, stderr io.Writer) (manifestPath string, manifest *fleet.Manifest, manifestData []byte, discoveryIncomplete bool, exitCode int) {
	if opts.Org == "" {
		manifest, manifestData, err := fleet.LoadManifest(opts.TargetsPath)
		if err != nil {
			fmt.Fprintf(stderr, "gin-recon: %v\n", err)
			return "", nil, nil, false, cli.ExitOperationalError
		}
		return opts.TargetsPath, manifest, manifestData, false, cli.ExitSuccess
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
				return "", nil, nil, false, cli.ExitOperationalError
			}
		}
		break
	}
	if !found {
		fmt.Fprintf(stderr, "gin-recon: --org: \"api.github.com\" is not in fleet.allowedRemoteHosts (required to enumerate an organization's repositories)\n")
		return "", nil, nil, false, cli.ExitOperationalError
	}

	result, err := fleet.DiscoverOrgRepos(context.Background(), fleet.DiscoverOptions{
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
		return "", nil, nil, false, cli.ExitOperationalError
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

	if err := os.MkdirAll(opts.OutDir, 0o755); err != nil {
		fmt.Fprintf(stderr, "gin-recon: %v\n", err)
		return "", nil, nil, false, cli.ExitOperationalError
	}
	data, err := json.MarshalIndent(result.Manifest, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "gin-recon: --org: encoding discovered manifest: %v\n", err)
		return "", nil, nil, false, cli.ExitOperationalError
	}
	discoveredPath := filepath.Join(opts.OutDir, discoveredTargetsFilename)
	if err := os.WriteFile(discoveredPath, data, 0o644); err != nil {
		fmt.Fprintf(stderr, "gin-recon: %v\n", err)
		return "", nil, nil, false, cli.ExitOperationalError
	}
	identityData, err := fleetManifestIdentityData(result.Manifest)
	if err != nil {
		fmt.Fprintf(stderr, "gin-recon: --org: %v\n", err)
		return "", nil, nil, false, cli.ExitOperationalError
	}
	return discoveredPath, result.Manifest, identityData, result.Incomplete, cli.ExitSuccess
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

// writeFleetConfigSnapshot copies opts.ConfigPath's exact bytes into --out
// as configSnapshotBasename, preserving the source's own extension, so an
// --org run's classification config survives independent of the original
// --config path later moving or changing — docs/adr/0025-fleet-org-config-snapshot.md.
// A no-op for a --targets run (its own manifest/config are expected to
// already be version-controlled together) or when --config wasn't given
// (--config is optional for fleet; nothing to snapshot).
func writeFleetConfigSnapshot(opts *cli.Options, stderr io.Writer) int {
	if opts.Org == "" || opts.ConfigPath == "" {
		return cli.ExitSuccess
	}
	data, err := os.ReadFile(opts.ConfigPath)
	if err != nil {
		fmt.Fprintf(stderr, "gin-recon: %v\n", err)
		return cli.ExitOperationalError
	}
	ext := filepath.Ext(opts.ConfigPath)
	if ext == "" {
		ext = ".json"
	}
	dest := filepath.Join(opts.OutDir, configSnapshotBasename+ext)
	if err := os.WriteFile(dest, data, 0o644); err != nil {
		fmt.Fprintf(stderr, "gin-recon: %v\n", err)
		return cli.ExitOperationalError
	}
	return cli.ExitSuccess
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
	var agg fleet.Aggregate
	if err := json.Unmarshal(data, &agg); err != nil {
		fmt.Fprintf(stderr, "gin-recon: --report: decoding fleet.json: %v\n", err)
		return cli.ExitOperationalError
	}

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

	for i, t := range agg.Targets {
		if t.Status != fleet.StatusOK {
			continue // render reformats what exists; it does not retry a failed or not-go-module target
		}

		rep, err := loadReportFile(filepath.Join(fleetJSONDir, "targets", t.Name, "routes.json"))
		if err != nil {
			fmt.Fprintf(stderr, "gin-recon: fleet render: target %q: %v\n", t.Name, err)
			return cli.ExitOperationalError
		}
		if err := validateRenderedReport(rep); err != nil {
			fmt.Fprintf(stderr, "gin-recon: fleet render: target %q: %v\n", t.Name, err)
			return cli.ExitOperationalError
		}

		// Refreshed from this target's own already-computed routes.json —
		// not recomputed, and not a second scan — so a fleet.json written
		// before docs/adr/0028-gin-recon-default-output-directory.md's
		// fleet.html redesign (Routes/Proven/Public/Unknown all zero) picks
		// up real values the next time it's rendered.
		if rep.Summary != nil {
			agg.Targets[i].Routes = rep.Summary.TotalRoutes
			agg.Targets[i].Proven = rep.Summary.ProvenByConfirmedShape + rep.Summary.ProvenByAttestedUnresolved
			agg.Targets[i].Public = rep.Summary.Public
			agg.Targets[i].Unknown = rep.Summary.Unknown
		}

		targetRawOut := filepath.Join(rawDir, "targets", t.Name)
		targetOpts := &cli.Options{Command: cli.CommandRender, OutDir: targetRawOut, Formats: opts.Formats, Force: true}
		if code := writeReport(rep, targetOpts, cfg, stdout, stderr, cli.ExitSuccess); code != cli.ExitSuccess {
			return code
		}

		// api.html moves into the rendered tree exactly the way a live
		// fleet run already moves it (docs/adr/0023-fleet-raw-rendered-split.md)
		// — render's own output must be indistinguishable from what a live
		// run with the same --format would have produced.
		srcHTML := filepath.Join(targetRawOut, htmlCompanionFilename)
		if _, statErr := os.Stat(srcHTML); statErr == nil {
			destDir := filepath.Join(htmlOutDir, "targets", t.Name)
			if err := os.MkdirAll(destDir, 0o755); err != nil {
				fmt.Fprintf(stderr, "gin-recon: %v\n", err)
				return cli.ExitOperationalError
			}
			destHTML := filepath.Join(destDir, htmlCompanionFilename)
			if err := os.Rename(srcHTML, destHTML); err != nil {
				fmt.Fprintf(stderr, "gin-recon: %v\n", err)
				return cli.ExitOperationalError
			}
			agg.Targets[i].APIHTML = filepath.Join("targets", t.Name, htmlCompanionFilename)
		} else {
			// --format on this render no longer includes openapi: any
			// previously-recorded link would now point at nothing.
			agg.Targets[i].APIHTML = ""
		}
	}

	agg.Totals.Routes, agg.Totals.Proven, agg.Totals.Public, agg.Totals.Unknown = 0, 0, 0, 0
	for _, t := range agg.Targets {
		agg.Totals.Routes += t.Routes
		agg.Totals.Proven += t.Proven
		agg.Totals.Public += t.Public
		agg.Totals.Unknown += t.Unknown
	}

	// fleet.json itself is updated too, not just fleet.html — each target's
	// APIHTML just changed, and docs/adr/0024-fleet-render.md's whole
	// premise (fleet.json as a complete, durable record) breaks if the
	// file on disk silently falls out of sync with what was just rendered.
	aggData, err := json.MarshalIndent(&agg, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "gin-recon: fleet render: encoding fleet.json: %v\n", err)
		return cli.ExitOperationalError
	}
	if err := os.WriteFile(filepath.Join(rawDir, fleetAggregateFilename), aggData, 0o644); err != nil {
		fmt.Fprintf(stderr, "gin-recon: %v\n", err)
		return cli.ExitOperationalError
	}

	htmlData, err := format.FleetHTML(&agg, nil, agg.Scope, rawDirLink)
	if err != nil {
		fmt.Fprintf(stderr, "gin-recon: fleet render: rendering fleet.html: %v\n", err)
		return cli.ExitOperationalError
	}
	if err := os.WriteFile(filepath.Join(htmlOutDir, fleetHTMLFilename), htmlData, 0o644); err != nil {
		fmt.Fprintf(stderr, "gin-recon: %v\n", err)
		return cli.ExitOperationalError
	}
	return cli.ExitSuccess
}
