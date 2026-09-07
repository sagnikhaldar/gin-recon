package fleet

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Status classifies one target's outcome. A target that isn't a Go module at
// all is distinguished from a real scan failure — it never enters as
// evidence against recall/precision the way an actual failure does
// (docs/adr/0018-fleet-scanning.md).
type Status string

const (
	StatusOK           Status = "ok"
	StatusNotGoModule  Status = "not-go-module"
	StatusInconclusive Status = "inconclusive"
	StatusFailed       Status = "failed"
)

// Artifact records the integrity metadata required before a completed result
// may be reused from checkpoint or update state.
type Artifact struct {
	Tree   string `json:"tree,omitempty"`
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

// ModuleKind separates repositories that are not Gin applications from Gin
// dependencies where no mounted routes were discovered. A zero-route Gin
// library is not silently counted as an application with perfect coverage.
type ModuleKind string

const (
	ModuleGo             ModuleKind = "go-module"
	ModuleGinNoRoutes    ModuleKind = "gin-module-no-routes"
	ModuleGinApplication ModuleKind = "gin-application"
)

// ModuleResult is one independently analyzed Go module within a repository.
// ID is stable for the module's repository-relative path and is safe for use
// in output paths; Path remains the human-readable repository-relative path.
type ModuleResult struct {
	ID         string     `json:"id"`
	Path       string     `json:"path"`
	ModulePath string     `json:"modulePath"`
	Kind       ModuleKind `json:"kind"`
	Status     Status     `json:"status"`
	Error      string     `json:"error,omitempty"`
	Complete   bool       `json:"complete"`
	Report     string     `json:"report,omitempty"`
	APIHTML    string     `json:"apiHtml,omitempty"`
	Routes     int        `json:"routes,omitempty"`
	Proven     int        `json:"proven,omitempty"`
	Public     int        `json:"public,omitempty"`
	Unknown    int        `json:"unknown,omitempty"`
	Artifacts  []Artifact `json:"artifacts,omitempty"`
}

type RepositoryInventory struct {
	Kind        RepositoryKind `json:"kind"`
	Complete    bool           `json:"complete"`
	GoFiles     int            `json:"goFiles"`
	Modules     int            `json:"modules"`
	Directories int            `json:"directories"`
	Files       int            `json:"files"`
	Bytes       int64          `json:"bytes"`
	HasGoWork   bool           `json:"hasGoWork,omitempty"`
}

type RepositoryProvenance struct {
	ID            int64  `json:"id,omitempty"`
	FullName      string `json:"fullName,omitempty"`
	DefaultBranch string `json:"defaultBranch,omitempty"`
	Ref           string `json:"ref,omitempty"`
	PushedAt      string `json:"pushedAt,omitempty"`
	Private       bool   `json:"private,omitempty"`
	Visibility    string `json:"visibility,omitempty"`
	Archived      bool   `json:"archived,omitempty"`
	Fork          bool   `json:"fork,omitempty"`
	ScannedCommit string `json:"scannedCommit,omitempty"`
}

// TargetResult is one target's outcome in the aggregate.
type TargetResult struct {
	Name              string                `json:"name"`
	Src               string                `json:"src"`
	GitURL            string                `json:"gitUrl,omitempty"` // the manifest's original git.url, for a remote target only — Src is its (already-removed) clone path, not useful to display
	Status            Status                `json:"status"`
	Error             string                `json:"error,omitempty"`
	Complete          bool                  `json:"complete"`
	Report            string                `json:"report,omitempty"`  // path to this target's own routes.json, relative to --out (the raw directory)
	APIHTML           string                `json:"apiHtml,omitempty"` // path to this target's own api.html, relative to --out-html (docs/adr/0023-fleet-raw-rendered-split.md) — set only when this target's own --format included openapi
	Inventory         RepositoryInventory   `json:"inventory"`
	Repository        *RepositoryProvenance `json:"repository,omitempty"`
	Modules           []ModuleResult        `json:"modules,omitempty"`
	Artifacts         []Artifact            `json:"artifacts,omitempty"`
	SourceFingerprint string                `json:"sourceFingerprint,omitempty"`
	Attempts          int                   `json:"attempts,omitempty"`
	DurationMS        int64                 `json:"durationMs,omitempty"`

	// Routes/Proven/Public/Unknown are this target's own routes.json
	// summary, copied up so fleet.html can show each target's assurance
	// breakdown without a reader having to open every target's own report
	// individually (docs/adr/0028-gin-recon-default-output-directory.md's
	// accompanying fleet.html redesign). Proven is
	// provenByConfirmedShape+provenByAttestedUnresolved combined — fleet
	// scope cares whether a route's auth was established at all, not which
	// of the two enforcement-shape mechanisms established it (that detail
	// is still in the target's own routes.json, one click away). Set only
	// for a StatusOK target; zero value for every other status, same as an
	// empty repository would report.
	Routes  int `json:"routes,omitempty"`
	Proven  int `json:"proven,omitempty"`
	Public  int `json:"public,omitempty"`
	Unknown int `json:"unknown,omitempty"`

	// TargetConfig is true when --use-target-config found and used this
	// target's own targetConfigFilename instead of the fleet-wide --config
	// (docs/adr/0031-fleet-per-target-config.md). Recorded so a reader of
	// fleet.json/fleet.html can tell which targets' classification came
	// from evidence the target's own repository supplied, not a config
	// reviewed independently of it — a real, different trust provenance
	// worth being able to see, not just infer.
	TargetConfig bool `json:"targetConfig,omitempty"`

	// TargetConfigDir is true when --target-config-dir found and used an
	// entry for this target — outranks TargetConfig above when both would
	// otherwise apply (docs/adr/0033-fleet-target-config-dir.md), since an
	// operator-owned directory outside every scanned repository is
	// stronger evidence than a file the repository itself supplied.
	TargetConfigDir bool `json:"targetConfigDir,omitempty"`
}

// Scope is the --org configuration a fleet run used, recorded on the
// Aggregate so a later `render` pass over a saved fleet.json can
// reconstruct fleet.html's Scope panel without it — nothing derived from
// CLI flags a render invocation wouldn't otherwise have any way to know
// (docs/adr/0024-fleet-render.md). Nil for a plain --targets run, which has
// no comparable scope to record.
type Scope struct {
	Org             string   `json:"org"`
	MaxRepos        int      `json:"maxRepos,omitempty"`
	Concurrency     int      `json:"concurrency,omitempty"`
	IncludeArchived bool     `json:"includeArchived,omitempty"`
	IncludeForks    bool     `json:"includeForks,omitempty"`
	RepoInclude     []string `json:"repoInclude,omitempty"`
	RepoExclude     []string `json:"repoExclude,omitempty"`
	// DiscoveryComplete is false when --max-repos or the page cap cut
	// enumeration short of the whole organization — a coarser
	// incompleteness than any one target's own scanCoverage.complete
	// (docs/adr/0021-fleet-org-enumeration.md), surfaced on the Scope panel
	// itself so a reader doesn't have to infer it from Coverage.Complete
	// being false for an unrelated reason (a target scan failure).
	// DiscoveryCompleteKnown distinguishes a real "false" (this run's own
	// discovery was actually incomplete) from a fleet.json predating this
	// field entirely, which would otherwise unmarshal DiscoveryComplete's
	// zero value as a confident, wrong "incomplete" claim about a run that
	// was never actually checked — false is a normal Go zero value, not a
	// safe "unknown" sentinel, so it needs an explicit companion rather
	// than being trusted on its own (docs/adr/0030-fleet-html-auth-config-visibility.md).
	// Left untouched by render, which never redoes discovery and so has no
	// way to learn this about a run it didn't perform.
	DiscoveryComplete      bool              `json:"discoveryComplete,omitempty"`
	DiscoveryCompleteKnown bool              `json:"discoveryCompleteKnown,omitempty"`
	Discovery              *DiscoverySummary `json:"discovery,omitempty"`
}

// Aggregate is the fleet.json shape.
type Aggregate struct {
	SchemaVersion string         `json:"schemaVersion"`
	Kind          string         `json:"kind"`
	Tool          string         `json:"tool"`
	ToolVersion   string         `json:"toolVersion"`
	Targets       []TargetResult `json:"targets"`
	Scope         *Scope         `json:"scope,omitempty"`
	Coverage      struct {
		Complete bool `json:"complete"`
	} `json:"coverage"`
	Resume struct {
		Requested  bool `json:"requested"`
		Reused     int  `json:"reused"`
		Checkpoint bool `json:"checkpoint"`
	} `json:"resume"`
	// Update mirrors Resume, for --org --update
	// (docs/adr/0039-fleet-org-update.md): Reused counts targets whose
	// GitHub pushedAt was unchanged since the previous complete run in
	// this same --out, so their prior result was reused instead of
	// rescanned. Requested is set even when Reused ends up 0 (no prior run
	// found, or every target actually changed) — the same "did the caller
	// even ask" transparency Resume.Requested already provides.
	Update struct {
		Requested bool `json:"requested"`
		Reused    int  `json:"reused"`
	} `json:"update"`

	// ConfigHash/Formats are this run's own identity (the same fields
	// --resume's checkpoint already computes, checkpoint.go's identity
	// struct) — persisted here too, unlike the checkpoint itself (deleted
	// once a run completes), so a *later* --update run has something to
	// compare its own current identity against. Before this field existed,
	// --update could only ever detect a toolVersion change; a --config or
	// --format change between two runs was invisible to it, silently
	// reusing a target's classification under what could by then be a
	// stale auth config.
	ConfigHash       string   `json:"configHash"`
	Formats          []string `json:"formats"`
	ScopeFingerprint string   `json:"scopeFingerprint"`
	ScanFingerprint  string   `json:"scanFingerprint"`
	TargetConfigHash string   `json:"targetConfigHash,omitempty"`
	AllowDownloads   bool     `json:"allowDownloads"`
	UseTargetConfig  bool     `json:"useTargetConfig"`
	RenderHTML       bool     `json:"renderHtml"`
	RepoAttempts     int      `json:"repoAttempts"`
	RepoTimeout      string   `json:"repoTimeout"`
	// Totals sums every target's own Routes/Proven/Public/Unknown — the
	// fleet-wide evidence rollup fleet.html's metrics row shows. Computed
	// once after every target finishes (Run), not recomputed by a later
	// render pass, since render never re-reads a target's routes.json for
	// any other purpose either — it trusts fleet.json's own record.
	Totals struct {
		Routes  int `json:"routes"`
		Proven  int `json:"proven"`
		Public  int `json:"public"`
		Unknown int `json:"unknown"`
	} `json:"totals"`
	// AuthConfig records how many authMiddleware/authWrappers entries this
	// run's --config actually configured — not read back by anything, only
	// so fleet.html can explain a fleet-wide Totals.Proven of zero as "no
	// authMiddleware was configured for this run" rather than leaving a
	// reader to wonder whether every scanned route is genuinely
	// unauthenticated (docs/adr/0030-fleet-html-auth-config-visibility.md).
	// Populated by cmd/gin-recon, not here: internal/fleet deliberately
	// never imports internal/config (ADR-0019's own decoupling), and cfg is
	// already loaded one layer up regardless.
	AuthConfig struct {
		MiddlewareCount int `json:"middlewareCount"`
		WrappersCount   int `json:"wrappersCount"`
	} `json:"authConfig"`

	// FollowModulesCount is the number of analysis.followModules glob
	// patterns this run's --config actually configured — the second
	// silently-narrowing config knob found live, alongside AuthConfig
	// above: a service that imports and mounts another module's routes
	// (a real, common pattern in this org — las-be-flow calling
	// las-be-lender-bfin/-dsp/-hero/-sib's own Init(router, ...)) only
	// gets those routes counted if followModules names the dependency;
	// without it, both the library scanned alone (structurally, always)
	// and the consumer scanned without this set under-report real routes.
	// fleet.html surfaces this the same way it already does for
	// authMiddleware, rather than leaving a reader to reverse-engineer a
	// route-count gap the way this field's own addition required
	// (docs/adr/0036-fleet-html-follow-modules-visibility.md).
	FollowModulesCount int `json:"followModulesCount,omitempty"`
}

// AllowedHost is one entry of a reviewed fleet.allowedRemoteHosts config
// list, carried into this package as plain data so internal/fleet never
// needs to import internal/config (docs/adr/0019-fleet-remote-targets.md).
type AllowedHost struct {
	Host     string
	TokenEnv string
}

// CloneFunc shallow-clones one remote target. The default, gitClone, is
// overridden in tests so Run's orchestration (allowlist enforcement,
// concurrency, checkpointing) can be tested without invoking a real git
// binary or the network.
type CloneFunc func(ctx context.Context, gitURL, ref, destDir string, token string) error

// RunOptions configures one fleet orchestration pass.
type RunOptions struct {
	ManifestPath string
	Manifest     *Manifest
	ManifestData []byte
	ConfigPath   string
	Formats      []string // passed through to every target's own audit subprocess; "json" is always included regardless (docs/adr/0023-fleet-raw-rendered-split.md)
	OutDir       string
	HTMLOutDir   string // sibling directory every HTML artifact moves into; empty disables the split (docs/adr/0023-fleet-raw-rendered-split.md)
	Concurrency  int
	Resume       bool
	BinaryPath   string // the gin-recon binary to re-exec per target, e.g. a resolved os.Args[0]
	ToolVersion  string

	// AllowDownloads mirrors --allow-downloads, passed through to every
	// target's own audit subprocess exactly like Formats/ConfigPath — a
	// real Go module fleet scans against typically still needs this the
	// same way a direct audit invocation would.
	AllowDownloads bool
	Stderr         *bytes.Buffer // per-target stderr tails are captured here for the caller to surface; may be nil

	// Progress, when non-nil, gets one line per target the moment that
	// target finishes (or is reused from a --resume checkpoint) — a fleet
	// run against a real organization can take minutes with zero other
	// output otherwise. Deliberately a separate writer from Stderr above,
	// written to directly and live rather than buffered: Stderr's whole
	// point is to collect per-target error tails so the caller can dump
	// them together in one predictable block after Run returns, which a
	// live-interleaved progress line would defeat. Safe for concurrent
	// writes from every target's own goroutine — guarded by the same mu
	// that already serializes checkpoint saves below.
	Progress io.Writer
	// ProgressFormat is "plain" (default) or "json". Callers disable
	// progress by leaving Progress nil.
	ProgressFormat string

	// UseTargetConfig mirrors --use-target-config
	// (docs/adr/0031-fleet-per-target-config.md): when true, a target whose
	// own source tree contains targetConfigFilename uses it instead of
	// ConfigPath for that target only. Off by default — a target's own
	// source is exactly the kind of untrusted input docs/threat-model.md
	// already treats scanned repositories as, so honoring a
	// repository-embedded config at all is its own capability switch, not
	// automatic just because ConfigPath happens to be set.
	UseTargetConfig bool

	// TargetConfigDir mirrors --target-config-dir
	// (docs/adr/0033-fleet-target-config-dir.md): a local, operator-owned
	// directory holding one config file per target
	// (<dir>/<target-name>.json), outside every scanned repository. Wins
	// over both UseTargetConfig's repository-embedded file and ConfigPath
	// for a target it has an entry for — a target's own committed file is
	// still real reviewed evidence, but this directory is evidence the
	// operator running fleet controls directly, a strictly stronger trust
	// position, and needs no commit/PR/merge into the target's own repo.
	TargetConfigDir string
	RepoAttempts    int
	RepoTimeout     time.Duration

	// Preseed is fleet --org --update only (docs/adr/0039-fleet-org-update.md):
	// already-known results, by target name, for targets cmd/gin-recon has
	// determined are unchanged since the previous complete run in the same
	// --out (same GitHub pushedAt now as then). Checked as a fallback after
	// this run's own checkpoint (cp.Complete) — same reuse mechanism
	// --resume already uses, just sourced from a prior *complete* run
	// instead of an in-progress one.
	Preseed map[string]TargetResult

	// Remote targets (docs/adr/0019-fleet-remote-targets.md). AllowRemote
	// mirrors --allow-remote-targets: the capability switch. AllowedHosts
	// is the actual scope, from fleet.allowedRemoteHosts in a reviewed
	// config file — a target whose host isn't listed here fails clearly
	// even when AllowRemote is true. Clone defaults to gitClone; tests
	// substitute a fake.
	AllowRemote  bool
	AllowedHosts []AllowedHost
	Clone        CloneFunc
}

func (o RunOptions) allowedHost(host string) (AllowedHost, bool) {
	for _, h := range o.AllowedHosts {
		if h.Host == host {
			return h, true
		}
	}
	return AllowedHost{}, false
}

// stderrTailLimit bounds how much of a failed target's stderr is kept in the
// aggregate — enough to be useful, small enough that one hostile or noisy
// target can't bloat fleet.json.
const stderrTailLimit = 4096

// targetConfigFilename is the conventional per-target config file
// UseTargetConfig looks for at the root of each target's own resolved
// source (docs/adr/0031-fleet-per-target-config.md) — chosen to match a
// real, already-existing convention across several targets in the org
// this was built for, rather than invent a new name nothing on disk uses
// yet.
const targetConfigFilename = ".gin-recon-reconcile-config.json"

// fileExists reports whether path names a regular, readable file — used
// only to probe for targetConfigFilename, never to distinguish "doesn't
// exist" from any other stat error (either way, that target simply falls
// back to opts.ConfigPath).
func fileExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular()
}

// Run orchestrates one audit invocation per target, bounded by
// opts.Concurrency, and returns the aggregate. It creates opts.OutDir and a
// per-target subdirectory under it, and maintains a checkpoint for --resume.
func Run(ctx context.Context, opts RunOptions) (*Aggregate, error) {
	if opts.Concurrency < 1 {
		opts.Concurrency = 1
	}
	if opts.RepoAttempts < 1 {
		opts.RepoAttempts = 1
	}
	if opts.RepoTimeout <= 0 {
		opts.RepoTimeout = 10 * time.Minute
	}
	if err := ensureDirectoryNoSymlink(opts.OutDir, 0o755); err != nil {
		return nil, fmt.Errorf("fleet: creating --out: %w", err)
	}

	configHash, err := hashFile(opts.ConfigPath)
	if err != nil {
		return nil, err
	}
	targetConfigHash, err := hashConfigDirectory(opts.TargetConfigDir)
	if err != nil {
		return nil, err
	}
	want := identity{
		ManifestHash:     hashBytes(opts.ManifestData),
		ConfigHash:       configHash,
		Formats:          append([]string{}, opts.Formats...),
		ToolVersion:      opts.ToolVersion,
		TargetConfigHash: targetConfigHash,
		AllowDownloads:   opts.AllowDownloads,
		UseTargetConfig:  opts.UseTargetConfig,
		RenderHTML:       opts.HTMLOutDir != "",
		RepoAttempts:     opts.RepoAttempts,
		RepoTimeout:      opts.RepoTimeout.String(),
	}

	var cp *checkpoint
	if opts.Resume {
		cp, err = loadCheckpoint(opts.OutDir, want)
		if err != nil {
			return nil, err
		}
	} else {
		cp = &checkpoint{Version: 2, Identity: want, Complete: map[string]TargetResult{}}
	}

	manifestDir := filepath.Dir(opts.ManifestPath)
	targets := opts.Manifest.Targets
	results := make([]TargetResult, len(targets))
	reused := 0
	updateReused := 0

	sem := make(chan struct{}, opts.Concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex // guards cp, saveCheckpoint, and completed/opts.Progress below
	completed := 0
	var checkpointErr error

	// reportProgress prints one line for a target the moment it's known —
	// reused from a checkpoint or --update comparison, or just finished —
	// so a long fleet run isn't silent until it exits. Must be called with
	// mu held (it reads/updates completed itself, so callers pass a
	// pre-locked closure instead of locking around it, keeping every call
	// site symmetric). reused, when non-empty, names why no goroutine ran
	// for this target at all ("resumed" from this run's own checkpoint, or
	// "unchanged" via --update's previous-run comparison,
	// docs/adr/0039-fleet-org-update.md) — distinct provenance worth a
	// reader being able to tell apart, not both collapsed into one label.
	reportProgress := func(t Target, res TargetResult, reused string) {
		completed++
		if opts.Progress == nil {
			return
		}
		if opts.ProgressFormat == "json" {
			line := struct {
				Kind       string `json:"kind"`
				Current    int    `json:"current"`
				Total      int    `json:"total"`
				Target     string `json:"target"`
				Status     Status `json:"status"`
				Reuse      string `json:"reuse,omitempty"`
				Routes     int    `json:"routes"`
				Complete   bool   `json:"complete"`
				Attempts   int    `json:"attempts,omitempty"`
				DurationMS int64  `json:"durationMs,omitempty"`
			}{"fleet-progress", completed, len(targets), t.Name, res.Status, reused, res.Routes, res.Complete, res.Attempts, res.DurationMS}
			data, _ := json.Marshal(line)
			fmt.Fprintln(opts.Progress, string(data))
			return
		}
		suffix := ""
		if reused != "" {
			suffix = " (" + reused + ")"
		} else if res.Status == StatusOK {
			suffix = fmt.Sprintf(" (%d routes)", res.Routes)
		}
		fmt.Fprintf(opts.Progress, "[%d/%d] %s: %s%s\n", completed, len(targets), t.Name, res.Status, suffix)
	}

	for i, t := range targets {
		mu.Lock()
		done, ok := cp.Complete[t.Name]
		reuseReason := "resumed"
		if !ok && opts.Preseed != nil {
			done, ok = opts.Preseed[t.Name]
			reuseReason = "unchanged"
		}
		if ok {
			currentFingerprint := targetFingerprint(t)
			var fingerprintErr error
			if done.Name != t.Name {
				fingerprintErr = fmt.Errorf("saved result name %q does not match target %q", done.Name, t.Name)
			}
			if t.Git == nil && fingerprintErr == nil {
				src, resolveErr := resolveLocalSource(manifestDir, t.Src)
				if resolveErr != nil {
					fingerprintErr = resolveErr
				}
				var currentDiscovery repositoryDiscovery
				if fingerprintErr == nil {
					currentDiscovery, fingerprintErr = discoverRepositoryContext(ctx, src)
				}
				if fingerprintErr == nil {
					currentFingerprint = resolvedSourceFingerprint(t, currentDiscovery.Fingerprint)
				}
			}
			if fingerprintErr != nil {
				if opts.Stderr != nil {
					fmt.Fprintf(opts.Stderr, "gin-recon: fleet: target %s source identity could not be verified (%v); rescanning\n", t.Name, fingerprintErr)
				}
				delete(cp.Complete, t.Name)
				ok = false
			} else if err := reusableTarget(opts.OutDir, opts.HTMLOutDir, done, currentFingerprint, opts.Formats, opts.HTMLOutDir != ""); err != nil {
				if opts.Stderr != nil {
					fmt.Fprintf(opts.Stderr, "gin-recon: fleet: target %s saved result is not reusable (%v); rescanning\n", t.Name, err)
				}
				delete(cp.Complete, t.Name)
				ok = false
			}
		}
		if ok {
			reportProgress(t, done, reuseReason)
		}
		mu.Unlock()
		if ok {
			results[i] = done
			if reuseReason == "unchanged" {
				updateReused++
			} else {
				reused++
			}
			continue
		}
		i, t := i, t
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			result := TargetResult{
				Name: t.Name, Src: t.Src, Status: StatusInconclusive, Complete: false,
				SourceFingerprint: targetFingerprint(t), Error: fmt.Sprintf("fleet deadline reached before target started: %v", ctx.Err()),
			}
			if t.Git != nil {
				result.GitURL = t.Git.URL
			}
			results[i] = result
			mu.Lock()
			reportProgress(t, result, "")
			mu.Unlock()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			res := runOneTarget(ctx, opts, manifestDir, t)
			results[i] = res

			mu.Lock()
			reportProgress(t, res, "")
			mu.Unlock()

			if res.Complete && (res.Status == StatusOK || res.Status == StatusNotGoModule) {
				mu.Lock()
				cp.Complete[t.Name] = res
				saveErr := saveCheckpoint(opts.OutDir, cp)
				if saveErr != nil && checkpointErr == nil {
					checkpointErr = saveErr
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if checkpointErr != nil {
		return nil, checkpointErr
	}

	scanIdentity := want
	scanIdentity.ManifestHash = ""
	identityData, _ := json.Marshal(scanIdentity)
	agg := &Aggregate{
		SchemaVersion: "1.0", Kind: "fleet", Tool: "gin-recon",
		ToolVersion: opts.ToolVersion, Targets: results,
		ConfigHash: want.ConfigHash, Formats: want.Formats,
		ScanFingerprint:  hashBytes(identityData),
		TargetConfigHash: want.TargetConfigHash, AllowDownloads: want.AllowDownloads,
		UseTargetConfig: want.UseTargetConfig, RenderHTML: want.RenderHTML,
		RepoAttempts: want.RepoAttempts, RepoTimeout: want.RepoTimeout,
	}
	agg.Coverage.Complete = true
	for _, r := range results {
		if r.Status == StatusFailed || r.Status == StatusInconclusive || !r.Complete {
			agg.Coverage.Complete = false
		}
		agg.Totals.Routes += r.Routes
		agg.Totals.Proven += r.Proven
		agg.Totals.Public += r.Public
		agg.Totals.Unknown += r.Unknown
	}
	agg.Resume.Requested = opts.Resume
	agg.Resume.Reused = reused
	agg.Resume.Checkpoint = !agg.Coverage.Complete
	agg.Update.Requested = opts.Preseed != nil
	agg.Update.Reused = updateReused

	sortByManifestOrder(agg.Targets, targets)
	return agg, nil
}

// RefreshScanFingerprint re-derives the aggregate's scan identity after an
// offline render changes identity-bearing output choices such as Formats or
// RenderHTML. Manifest membership is intentionally absent, matching Run's
// fingerprint: scope compatibility is checked separately.
func RefreshScanFingerprint(agg *Aggregate) {
	scanIdentity := identity{
		ConfigHash:       agg.ConfigHash,
		Formats:          append([]string{}, agg.Formats...),
		ToolVersion:      agg.ToolVersion,
		TargetConfigHash: agg.TargetConfigHash,
		AllowDownloads:   agg.AllowDownloads,
		UseTargetConfig:  agg.UseTargetConfig,
		RenderHTML:       agg.RenderHTML,
		RepoAttempts:     agg.RepoAttempts,
		RepoTimeout:      agg.RepoTimeout,
	}
	identityData, _ := json.Marshal(scanIdentity)
	agg.ScanFingerprint = hashBytes(identityData)
}

func sortByManifestOrder(results []TargetResult, targets []Target) {
	order := make(map[string]int, len(targets))
	for i, t := range targets {
		order[t.Name] = i
	}
	sort.SliceStable(results, func(i, j int) bool { return order[results[i].Name] < order[results[j].Name] })
}

// runOneTarget resolves one target's source — a local directory (ADR 0018)
// or a remote clone (ADR 0019) — classifies it, and for a real Go module
// re-execs the gin-recon binary's own audit command against it. This is the
// one place fleet ever spawns a subprocess; there is no in-process call
// into internal/analyzer anywhere in this package, per ADR 0018's isolation
// decision.
func runOneTarget(ctx context.Context, opts RunOptions, manifestDir string, t Target) TargetResult {
	started := time.Now()
	timeout := opts.RepoTimeout
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	targetContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	attempts := opts.RepoAttempts
	if attempts < 1 {
		attempts = 1
	}
	var result TargetResult
	for attempt := 1; attempt <= attempts; attempt++ {
		result = runOneTargetAttempt(targetContext, opts, manifestDir, t)
		result.Attempts = attempt
		if result.Status != StatusFailed || t.Git == nil || attempt == attempts || targetContext.Err() != nil {
			break
		}
		timer := time.NewTimer(time.Duration(attempt) * 200 * time.Millisecond)
		select {
		case <-targetContext.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
	if targetContext.Err() != nil && result.Status == StatusFailed {
		result.Error = fmt.Sprintf("repository deadline exceeded after %s: %s", timeout, result.Error)
	}
	result.DurationMS = time.Since(started).Milliseconds()
	return result
}

func runOneTargetAttempt(ctx context.Context, opts RunOptions, manifestDir string, t Target) TargetResult {
	res := TargetResult{Name: t.Name}
	if t.Git != nil {
		res.GitURL = t.Git.URL
	}
	if t.GitHub != nil {
		res.Repository = &RepositoryProvenance{
			ID: t.GitHub.ID, FullName: t.GitHub.FullName,
			DefaultBranch: t.GitHub.DefaultBranch, PushedAt: t.GitHub.PushedAt,
			Private: t.GitHub.Private, Visibility: t.GitHub.Visibility,
			Archived: t.GitHub.Archived, Fork: t.GitHub.Fork,
		}
	}

	src, cleanup, err := resolveSource(ctx, opts, manifestDir, t)
	if err != nil {
		res.Status = StatusFailed
		res.Error = err.Error()
		return res
	}
	if cleanup != nil {
		defer cleanup()
	}
	res.Src = src
	if t.Git != nil {
		if res.Repository == nil {
			res.Repository = &RepositoryProvenance{}
		}
		res.Repository.Ref = t.Git.Ref
		commit, commitErr := sourceCommit(ctx, src)
		if commitErr != nil && opts.Clone == nil {
			res.Status = StatusFailed
			res.Error = fmt.Sprintf("resolving checked-out commit: %v", commitErr)
			return res
		}
		if commitErr == nil {
			res.Repository.ScannedCommit = commit
		}
	}

	discovery, err := discoverRepositoryContext(ctx, src)
	if err != nil {
		res.Status = StatusInconclusive
		res.Error = err.Error()
		res.Complete = false
		return res
	}
	res.SourceFingerprint = resolvedSourceFingerprint(t, discovery.Fingerprint)
	res.Inventory = RepositoryInventory{
		Kind: discovery.Kind, Complete: true, GoFiles: discovery.GoFiles,
		Modules: len(discovery.Modules), Directories: discovery.Directories,
		Files: discovery.Files, Bytes: discovery.Bytes, HasGoWork: discovery.HasGoWork,
	}
	if len(discovery.Modules) == 0 {
		res.Status = StatusNotGoModule
		res.Complete = true
		return res
	}

	targetOut, err := SafeTargetDir(opts.OutDir, t.Name)
	if err != nil {
		res.Status = StatusFailed
		res.Error = err.Error()
		return res
	}
	if err := ensureDirectoryNoSymlink(filepath.Dir(targetOut), 0o755); err != nil {
		res.Status = StatusFailed
		res.Error = err.Error()
		return res
	}
	stagedRaw, err := os.MkdirTemp(filepath.Dir(targetOut), "."+t.Name+"-stage-*")
	if err != nil {
		res.Status = StatusFailed
		res.Error = fmt.Sprintf("creating target staging directory: %v", err)
		return res
	}
	defer os.RemoveAll(stagedRaw)

	var targetHTMLOut, stagedHTML string
	if opts.HTMLOutDir != "" {
		targetHTMLOut, err = SafeTargetDir(opts.HTMLOutDir, t.Name)
		if err != nil {
			res.Status = StatusFailed
			res.Error = err.Error()
			return res
		}
		if err := ensureDirectoryNoSymlink(filepath.Dir(targetHTMLOut), 0o755); err != nil {
			res.Status = StatusFailed
			res.Error = err.Error()
			return res
		}
		stagedHTML, err = os.MkdirTemp(filepath.Dir(targetHTMLOut), "."+t.Name+"-stage-*")
		if err != nil {
			res.Status = StatusFailed
			res.Error = fmt.Sprintf("creating target HTML staging directory: %v", err)
			return res
		}
		defer os.RemoveAll(stagedHTML)
	}

	targetConfigPath := opts.ConfigPath
	if opts.UseTargetConfig {
		if candidate := filepath.Join(src, targetConfigFilename); fileExists(candidate) {
			targetConfigPath = candidate
			res.TargetConfig = true
		}
	}
	if opts.TargetConfigDir != "" {
		for _, ext := range []string{".json", ".yaml", ".yml"} {
			candidate := filepath.Join(opts.TargetConfigDir, t.Name+ext)
			if fileExists(candidate) {
				targetConfigPath = candidate
				res.TargetConfigDir = true
				res.TargetConfig = false // this target's own repo file, if any, was outranked
				break
			}
		}
	}
	if res.TargetConfig {
		frozenConfig, cleanupConfig, err := freezeTargetConfigFile(targetConfigPath)
		if err != nil {
			res.Status = StatusFailed
			res.Error = fmt.Sprintf("freezing repository-provided target config: %v", err)
			return res
		}
		defer cleanupConfig()
		targetConfigPath = frozenConfig
	}

	res.Status = StatusOK
	res.Complete = true
	for _, module := range discovery.Modules {
		moduleOut := stagedRaw
		moduleHTMLOut := stagedHTML
		if len(discovery.Modules) > 1 {
			moduleOut = filepath.Join(stagedRaw, "modules", module.ID)
			if stagedHTML != "" {
				moduleHTMLOut = filepath.Join(stagedHTML, "modules", module.ID)
			}
		}
		mr := runModule(ctx, opts, t, module, moduleOut, moduleHTMLOut, targetConfigPath, len(discovery.Modules) > 1)
		res.Modules = append(res.Modules, mr)
		res.Routes += mr.Routes
		res.Proven += mr.Proven
		res.Public += mr.Public
		res.Unknown += mr.Unknown
		if mr.Status != StatusOK {
			res.Status = StatusFailed
			res.Complete = false
			if res.Error == "" {
				res.Error = fmt.Sprintf("module %s: %s", mr.Path, mr.Error)
			}
		} else if !mr.Complete {
			res.Complete = false
		}
	}
	if res.Status != StatusOK {
		for i := range res.Modules {
			res.Modules[i].Report = ""
			res.Modules[i].APIHTML = ""
			res.Modules[i].Artifacts = nil
		}
		return res
	}
	if t.Git == nil {
		after, err := discoverRepositoryContext(ctx, src)
		if err != nil || after.Fingerprint != discovery.Fingerprint {
			res.Status = StatusInconclusive
			res.Complete = false
			if err != nil {
				res.Error = fmt.Sprintf("verifying source stability after analysis: %v", err)
			} else {
				res.Error = "local source changed while analysis was running; staged evidence was not published"
			}
			for i := range res.Modules {
				res.Modules[i].Report = ""
				res.Modules[i].APIHTML = ""
			}
			return res
		}
	}
	clearEvidence := func() {
		res.Artifacts = nil
		res.Report = ""
		res.APIHTML = ""
		for i := range res.Modules {
			res.Modules[i].Artifacts = nil
			res.Modules[i].Report = ""
			res.Modules[i].APIHTML = ""
		}
	}
	formats := formatsWithJSON(opts.Formats)
	for i := range res.Modules {
		stagedModuleDir := ""
		if len(res.Modules) > 1 {
			stagedModuleDir = filepath.Join("modules", res.Modules[i].ID)
		}
		for _, name := range expectedRawArtifacts(formats) {
			stagedRel := filepath.Join(stagedModuleDir, name)
			finalRel := filepath.Join(filepath.Dir(res.Modules[i].Report), name)
			artifact, err := artifactForStagedTree("", stagedRaw, stagedRel, finalRel)
			if err != nil {
				res.Status = StatusFailed
				res.Complete = false
				res.Error = fmt.Sprintf("validating staged artifact %s: %v", name, err)
				clearEvidence()
				return res
			}
			res.Modules[i].Artifacts = append(res.Modules[i].Artifacts, artifact)
			res.Artifacts = append(res.Artifacts, artifact)
		}
		if res.Modules[i].APIHTML != "" {
			stagedRel := filepath.Join(stagedModuleDir, "api.html")
			artifact, err := artifactForStagedTree("html", stagedHTML, stagedRel, res.Modules[i].APIHTML)
			if err != nil {
				res.Status = StatusFailed
				res.Complete = false
				res.Error = fmt.Sprintf("validating staged HTML artifact: %v", err)
				clearEvidence()
				return res
			}
			res.Modules[i].Artifacts = append(res.Modules[i].Artifacts, artifact)
			res.Artifacts = append(res.Artifacts, artifact)
		}
	}
	publications := []directoryPublication{{staged: stagedRaw, destination: targetOut}}
	if stagedHTML != "" {
		publications = append(publications, directoryPublication{staged: stagedHTML, destination: targetHTMLOut})
	}
	if err := publishDirectories(publications...); err != nil {
		res.Status = StatusFailed
		res.Complete = false
		res.Error = fmt.Sprintf("publishing target artifacts: %v", err)
		clearEvidence()
		return res
	}
	// Publication moved both staging trees; deferred cleanup becomes a no-op.
	stagedRaw = ""
	if stagedHTML != "" {
		stagedHTML = ""
	}
	if len(res.Modules) == 1 {
		res.Report = res.Modules[0].Report
		res.APIHTML = res.Modules[0].APIHTML
	}
	return res
}

func freezeTargetConfigFile(path string) (string, func(), error) {
	data, err := ReadBoundedFile(path)
	if err != nil {
		return "", func() {}, err
	}
	dir, err := os.MkdirTemp("", "gin-recon-target-config-*")
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	destination := filepath.Join(dir, "config"+filepath.Ext(path))
	if err := WriteFileAtomic(destination, data, 0o600); err != nil {
		cleanup()
		return "", func() {}, err
	}
	return destination, cleanup, nil
}

func runModule(ctx context.Context, opts RunOptions, target Target, module moduleRoot, moduleOut, moduleHTMLOut, targetConfigPath string, nestedOutput bool) ModuleResult {
	res := ModuleResult{ID: module.ID, Path: module.RelPath, ModulePath: module.ModulePath, Kind: ModuleGo}
	if err := ensureDirectoryNoSymlink(moduleOut, 0o755); err != nil {
		res.Status = StatusFailed
		res.Error = err.Error()
		return res
	}
	formats := formatsWithJSON(opts.Formats)
	args := []string{"audit", "--src", module.AbsPath, "--format", strings.Join(formats, ","), "--out", moduleOut, "--force"}
	if targetConfigPath != "" {
		args = append(args, "--config", targetConfigPath)
	}
	if opts.AllowDownloads {
		args = append(args, "--allow-downloads")
	}

	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, opts.BinaryPath, args...)
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	if runErr != nil {
		res.Status = StatusFailed
		res.Error = tail(stderr.String(), stderrTailLimit)
		if res.Error == "" {
			res.Error = runErr.Error()
		}
		return res
	}

	reportPath := filepath.Join(moduleOut, "routes.json")
	data, err := ReadBoundedFile(reportPath)
	if err != nil {
		res.Status = StatusFailed
		res.Error = fmt.Sprintf("audit exited 0 but %s could not be read: %v", reportPath, err)
		return res
	}
	var decoded struct {
		ScanCoverage struct {
			Complete bool `json:"complete"`
		} `json:"scanCoverage"`
		Summary *struct {
			TotalRoutes                int `json:"totalRoutes"`
			ProvenByConfirmedShape     int `json:"provenByConfirmedShape"`
			ProvenByAttestedUnresolved int `json:"provenByAttestedUnresolved"`
			Public                     int `json:"public"`
			Unknown                    int `json:"unknown"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		res.Status = StatusFailed
		res.Error = fmt.Sprintf("audit exited 0 but %s could not be parsed: %v", reportPath, err)
		return res
	}

	res.Status = StatusOK
	res.Complete = decoded.ScanCoverage.Complete
	if nestedOutput {
		res.Report = filepath.Join("targets", target.Name, "modules", module.ID, "routes.json")
	} else {
		res.Report = filepath.Join("targets", target.Name, "routes.json")
	}
	if decoded.Summary != nil {
		res.Routes = decoded.Summary.TotalRoutes
		res.Proven = decoded.Summary.ProvenByConfirmedShape + decoded.Summary.ProvenByAttestedUnresolved
		res.Public = decoded.Summary.Public
		res.Unknown = decoded.Summary.Unknown
	}
	if res.Routes > 0 {
		res.Kind = ModuleGinApplication
	} else if module.UsesGin {
		res.Kind = ModuleGinNoRoutes
	}

	// api.html is staged alongside this target's raw tree and only published
	// after every module has completed, so an interrupted update cannot mix
	// old and new module artifacts.
	if moduleHTMLOut != "" {
		srcHTML := filepath.Join(moduleOut, "api.html")
		if _, statErr := os.Stat(srcHTML); statErr == nil {
			if err := ensureDirectoryNoSymlink(moduleHTMLOut, 0o755); err != nil {
				res.Status = StatusFailed
				res.Complete = false
				res.Error = fmt.Sprintf("staging HTML output: %v", err)
				return res
			}
			destHTML := filepath.Join(moduleHTMLOut, "api.html")
			if err := os.Rename(srcHTML, destHTML); err != nil {
				res.Status = StatusFailed
				res.Complete = false
				res.Error = fmt.Sprintf("staging HTML output: %v", err)
				return res
			}
			if nestedOutput {
				res.APIHTML = filepath.Join("targets", target.Name, "modules", module.ID, "api.html")
			} else {
				res.APIHTML = filepath.Join("targets", target.Name, "api.html")
			}
		}
	}
	return res
}

func expectedRawArtifacts(formats []string) []string {
	seen := map[string]bool{}
	var names []string
	for _, format := range formats {
		name := ""
		switch format {
		case "json":
			name = "routes.json"
		case "md":
			name = "routes.md"
		case "openapi":
			name = "openapi.json"
		case "sarif":
			name = "results.sarif"
		case "pretty":
			name = "routes.txt"
		}
		if name != "" && !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	return names
}

// formatsWithJSON returns formats with "json" included exactly once —
// fleet always needs a target's own routes.json for its aggregate
// regardless of what else was requested (docs/adr/0023-fleet-raw-rendered-split.md).
func formatsWithJSON(formats []string) []string {
	for _, f := range formats {
		if f == "json" {
			return formats
		}
	}
	return append([]string{"json"}, formats...)
}

// resolveSource turns one target into a local directory to scan: a local
// path resolved relative to the manifest (ADR 0018), or a fresh shallow
// clone (ADR 0019). The returned cleanup, when non-nil, removes the clone
// once the caller is done with it — a fleet run's disk footprint from
// remote targets never exceeds one clone per concurrency slot at a time.
func resolveSource(ctx context.Context, opts RunOptions, manifestDir string, t Target) (src string, cleanup func(), err error) {
	if t.Git == nil {
		src, err = resolveLocalSource(manifestDir, t.Src)
		return src, nil, err
	}

	if !opts.AllowRemote {
		return "", nil, fmt.Errorf("target %q names a remote git source, but --allow-remote-targets was not given", t.Name)
	}
	host := t.Host()
	allowed, ok := opts.allowedHost(host)
	if !ok {
		return "", nil, fmt.Errorf("target %q: host %q is not in fleet.allowedRemoteHosts", t.Name, host)
	}
	var token string
	if allowed.TokenEnv != "" {
		token, ok = os.LookupEnv(allowed.TokenEnv)
		if !ok {
			return "", nil, fmt.Errorf("target %q: environment variable %q named by fleet.allowedRemoteHosts is not set", t.Name, allowed.TokenEnv)
		}
	}

	clonesRoot := filepath.Join(opts.OutDir, ".clones")
	if err := ensureDirectoryNoSymlink(clonesRoot, 0o700); err != nil {
		return "", nil, fmt.Errorf("target %q: preparing clone scratch root: %w", t.Name, err)
	}
	destDir := filepath.Join(clonesRoot, t.Name)
	if err := os.RemoveAll(destDir); err != nil {
		return "", nil, fmt.Errorf("target %q: clearing clone scratch directory: %w", t.Name, err)
	}
	clone := opts.Clone
	if clone == nil {
		clone = gitClone
	}
	if err := clone(ctx, t.Git.URL, t.Git.Ref, destDir, token); err != nil {
		_ = os.RemoveAll(destDir)
		return "", nil, fmt.Errorf("target %q: %w", t.Name, err)
	}
	if err := validateGitMetadataBounds(destDir); err != nil {
		_ = os.RemoveAll(destDir)
		return "", nil, fmt.Errorf("target %q: %w", t.Name, err)
	}
	return destDir, func() { os.RemoveAll(destDir) }, nil
}

func resolveLocalSource(manifestDir, source string) (string, error) {
	if !filepath.IsAbs(source) {
		source = filepath.Join(manifestDir, source)
	}
	absolute, err := filepath.Abs(source)
	if err != nil {
		return "", err
	}
	real, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", fmt.Errorf("resolving local source %q: %w", source, err)
	}
	info, err := os.Stat(real)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("local source %q is not a directory", source)
	}
	return real, nil
}

const maxGitMetadataBytes int64 = 1 << 30

func validateGitMetadataBounds(repository string) error {
	gitDir := filepath.Join(repository, ".git")
	if _, err := os.Lstat(gitDir); os.IsNotExist(err) {
		// Injected Clone functions are allowed in tests and embeddings; the
		// production gitClone always creates .git and is independently checked
		// for an exact HEAD before analysis.
		return nil
	} else if err != nil {
		return fmt.Errorf("checking git metadata: %w", err)
	}
	var files int
	var bytes int64
	if err := filepath.WalkDir(gitDir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("git metadata contains symlink %s", path)
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("git metadata contains non-regular file %s", path)
		}
		files++
		if files > maxDiscoveryFiles {
			return fmt.Errorf("git metadata contains more than %d files", maxDiscoveryFiles)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		bytes += info.Size()
		if bytes > maxGitMetadataBytes {
			return fmt.Errorf("git metadata exceeds %d bytes", maxGitMetadataBytes)
		}
		return nil
	}); err != nil {
		return fmt.Errorf("validating bounded git metadata: %w", err)
	}
	return nil
}

// gitClone is CloneFunc's default implementation: a shallow, single-branch,
// sanitized-environment clone (docs/adr/0019-fleet-remote-targets.md). A
// non-empty token is passed as a scoped Authorization header via git's own
// -c http.<url>.extraHeader, never written to any config file on disk and
// never logged — a failed clone's captured stderr is bounded the same way
// an audit subprocess's own stderr already is, so a token embedded in a
// verbose git error has the same small blast radius as any other captured
// failure text.
func gitClone(ctx context.Context, gitURL, ref, destDir, token string) error {
	args := []string{}
	env := []string{
		"GIT_TERMINAL_PROMPT=0",
		"GIT_LFS_SKIP_SMUDGE=1",
		"GIT_CONFIG_NOSYSTEM=1",
	}
	if token != "" {
		header := "Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+token))
		u, err := url.Parse(gitURL)
		if err != nil {
			return fmt.Errorf("git clone: %w", err)
		}
		scope := u.Scheme + "://" + u.Host + "/"
		env = append(env,
			"GIT_CONFIG_COUNT=1",
			"GIT_CONFIG_KEY_0=http."+scope+".extraHeader",
			"GIT_CONFIG_VALUE_0="+header,
		)
	}
	args = append(args, "clone", "--depth", "1", "--single-branch", "--filter=blob:limit=10485760")
	if ref != "" {
		args = append(args, "--branch", ref)
	}
	args = append(args, gitURL, destDir)

	home, err := os.MkdirTemp("", "gin-recon-fleet-git-home-*")
	if err != nil {
		return fmt.Errorf("git clone: preparing an isolated HOME: %w", err)
	}
	defer os.RemoveAll(home)

	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Env = append(env,
		"HOME="+home,
		"PATH="+os.Getenv("PATH"),
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := sanitizeDiagnostic(tail(stderr.String(), stderrTailLimit), token)
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("git clone: %s", msg)
	}
	return nil
}

func sanitizeDiagnostic(message, secret string) string {
	if secret != "" {
		message = strings.ReplaceAll(message, secret, "[REDACTED]")
		encoded := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + secret))
		message = strings.ReplaceAll(message, encoded, "[REDACTED]")
	}
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || r >= 0x20 {
			return r
		}
		return -1
	}, message)
}

func tail(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return s[len(s)-limit:]
}
