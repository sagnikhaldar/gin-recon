package fleet

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Status classifies one target's outcome. A target that isn't a Go module at
// all is distinguished from a real scan failure — it never enters as
// evidence against recall/precision the way an actual failure does
// (docs/adr/0018-fleet-scanning.md).
type Status string

const (
	StatusOK          Status = "ok"
	StatusNotGoModule Status = "not-go-module"
	StatusFailed      Status = "failed"
)

// TargetResult is one target's outcome in the aggregate.
type TargetResult struct {
	Name     string `json:"name"`
	Src      string `json:"src"`
	GitURL   string `json:"gitUrl,omitempty"` // the manifest's original git.url, for a remote target only — Src is its (already-removed) clone path, not useful to display
	Status   Status `json:"status"`
	Error    string `json:"error,omitempty"`
	Complete bool   `json:"complete"`
	Report   string `json:"report,omitempty"`  // path to this target's own routes.json, relative to --out (the raw directory)
	APIHTML  string `json:"apiHtml,omitempty"` // path to this target's own api.html, relative to --out-html (docs/adr/0023-fleet-raw-rendered-split.md) — set only when this target's own --format included openapi
}

// Aggregate is the fleet.json shape.
type Aggregate struct {
	Tool        string         `json:"tool"`
	ToolVersion string         `json:"toolVersion"`
	Targets     []TargetResult `json:"targets"`
	Coverage    struct {
		Complete bool `json:"complete"`
	} `json:"coverage"`
	Resume struct {
		Requested  bool `json:"requested"`
		Reused     int  `json:"reused"`
		Checkpoint bool `json:"checkpoint"`
	} `json:"resume"`
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
	Stderr       *bytes.Buffer // per-target stderr tails are captured here for the caller to surface; may be nil

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

// Run orchestrates one audit invocation per target, bounded by
// opts.Concurrency, and returns the aggregate. It creates opts.OutDir and a
// per-target subdirectory under it, and maintains a checkpoint for --resume.
func Run(ctx context.Context, opts RunOptions) (*Aggregate, error) {
	if opts.Concurrency < 1 {
		opts.Concurrency = 1
	}
	if err := os.MkdirAll(opts.OutDir, 0o755); err != nil {
		return nil, fmt.Errorf("fleet: creating --out: %w", err)
	}

	configHash, err := hashFile(opts.ConfigPath)
	if err != nil {
		return nil, err
	}
	want := identity{
		ManifestHash: hashBytes(opts.ManifestData),
		ConfigHash:   configHash,
		Formats:      append([]string{}, opts.Formats...),
	}

	var cp *checkpoint
	if opts.Resume {
		cp, err = loadCheckpoint(opts.OutDir, want)
		if err != nil {
			return nil, err
		}
	} else {
		cp = &checkpoint{Version: 1, Identity: want, Complete: map[string]TargetResult{}}
	}

	manifestDir := filepath.Dir(opts.ManifestPath)
	targets := opts.Manifest.Targets
	results := make([]TargetResult, len(targets))
	reused := 0

	sem := make(chan struct{}, opts.Concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex // guards cp and saveCheckpoint below

	for i, t := range targets {
		if done, ok := cp.Complete[t.Name]; ok {
			results[i] = done
			reused++
			continue
		}
		i, t := i, t
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			res := runOneTarget(ctx, opts, manifestDir, t)
			results[i] = res

			if res.Status == StatusOK || res.Status == StatusNotGoModule {
				mu.Lock()
				cp.Complete[t.Name] = res
				saveErr := saveCheckpoint(opts.OutDir, cp)
				mu.Unlock()
				if saveErr != nil && opts.Stderr != nil {
					fmt.Fprintf(opts.Stderr, "gin-recon: fleet: %v\n", saveErr)
				}
			}
		}()
	}
	wg.Wait()

	agg := &Aggregate{Tool: "gin-recon", ToolVersion: opts.ToolVersion, Targets: results}
	agg.Coverage.Complete = true
	for _, r := range results {
		if r.Status == StatusFailed || (r.Status == StatusOK && !r.Complete) {
			agg.Coverage.Complete = false
		}
	}
	agg.Resume.Requested = opts.Resume
	agg.Resume.Reused = reused
	agg.Resume.Checkpoint = !agg.Coverage.Complete

	if agg.Coverage.Complete {
		if err := removeCheckpoint(opts.OutDir); err != nil && opts.Stderr != nil {
			fmt.Fprintf(opts.Stderr, "gin-recon: fleet: %v\n", err)
		}
	}

	sortByManifestOrder(agg.Targets, targets)
	return agg, nil
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
	res := TargetResult{Name: t.Name}
	if t.Git != nil {
		res.GitURL = t.Git.URL
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

	if _, err := os.Stat(filepath.Join(src, "go.mod")); err != nil {
		res.Status = StatusNotGoModule
		res.Complete = true
		return res
	}

	targetOut := filepath.Join(opts.OutDir, "targets", t.Name)
	if err := os.MkdirAll(targetOut, 0o755); err != nil {
		res.Status = StatusFailed
		res.Error = err.Error()
		return res
	}

	formats := formatsWithJSON(opts.Formats)
	args := []string{"audit", "--src", src, "--format", strings.Join(formats, ","), "--out", targetOut, "--force"}
	if opts.ConfigPath != "" {
		args = append(args, "--config", opts.ConfigPath)
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

	reportPath := filepath.Join(targetOut, "routes.json")
	data, err := os.ReadFile(reportPath)
	if err != nil {
		res.Status = StatusFailed
		res.Error = fmt.Sprintf("audit exited 0 but %s could not be read: %v", reportPath, err)
		return res
	}
	var decoded struct {
		ScanCoverage struct {
			Complete bool `json:"complete"`
		} `json:"scanCoverage"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		res.Status = StatusFailed
		res.Error = fmt.Sprintf("audit exited 0 but %s could not be parsed: %v", reportPath, err)
		return res
	}

	res.Status = StatusOK
	res.Complete = decoded.ScanCoverage.Complete
	res.Report = filepath.Join("targets", t.Name, "routes.json")

	// api.html (written alongside openapi.json in targetOut, if "openapi"
	// was requested) moves into the sibling rendered tree — a plain file
	// move, not a second scan, per docs/adr/0023-fleet-raw-rendered-split.md.
	// A failed move degrades silently (res.APIHTML just stays empty, and
	// fleet.html renders that target with no rendered-view link) rather
	// than surfacing an error here: runOneTarget runs concurrently across
	// goroutines with no lock of its own, and opts.Stderr is only ever
	// safely written from within Run's own mutex-guarded section.
	if opts.HTMLOutDir != "" {
		srcHTML := filepath.Join(targetOut, "api.html")
		if _, statErr := os.Stat(srcHTML); statErr == nil {
			destDir := filepath.Join(opts.HTMLOutDir, "targets", t.Name)
			if err := os.MkdirAll(destDir, 0o755); err == nil {
				destHTML := filepath.Join(destDir, "api.html")
				if err := os.Rename(srcHTML, destHTML); err == nil {
					res.APIHTML = filepath.Join("targets", t.Name, "api.html")
				}
			}
		}
	}
	return res
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
		src = t.Src
		if !filepath.IsAbs(src) {
			src = filepath.Join(manifestDir, src)
		}
		return src, nil, nil
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

	destDir := filepath.Join(opts.OutDir, ".clones", t.Name)
	if err := os.RemoveAll(destDir); err != nil {
		return "", nil, fmt.Errorf("target %q: clearing clone scratch directory: %w", t.Name, err)
	}
	if err := os.MkdirAll(filepath.Dir(destDir), 0o755); err != nil {
		return "", nil, fmt.Errorf("target %q: preparing clone scratch directory: %w", t.Name, err)
	}

	clone := opts.Clone
	if clone == nil {
		clone = gitClone
	}
	if err := clone(ctx, t.Git.URL, t.Git.Ref, destDir, token); err != nil {
		return "", nil, fmt.Errorf("target %q: %w", t.Name, err)
	}
	return destDir, func() { os.RemoveAll(destDir) }, nil
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
	if token != "" {
		header := "Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+token))
		u, err := url.Parse(gitURL)
		if err != nil {
			return fmt.Errorf("git clone: %w", err)
		}
		scope := u.Scheme + "://" + u.Host + "/"
		args = append(args, "-c", "http."+scope+".extraHeader="+header)
	}
	args = append(args, "clone", "--depth", "1", "--single-branch")
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
	cmd.Env = []string{
		"GIT_TERMINAL_PROMPT=0",
		"GIT_LFS_SKIP_SMUDGE=1",
		"GIT_CONFIG_NOSYSTEM=1",
		"HOME=" + home,
		"PATH=" + os.Getenv("PATH"),
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := tail(stderr.String(), stderrTailLimit)
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("git clone: %s", msg)
	}
	return nil
}

func tail(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return s[len(s)-limit:]
}
