package fleet

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
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
	Status   Status `json:"status"`
	Error    string `json:"error,omitempty"`
	Complete bool   `json:"complete"`
	Report   string `json:"report,omitempty"` // path to this target's own routes.json, relative to --out
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

// RunOptions configures one fleet orchestration pass.
type RunOptions struct {
	ManifestPath string
	Manifest     *Manifest
	ManifestData []byte
	ConfigPath   string
	Formats      []string
	OutDir       string
	Concurrency  int
	Resume       bool
	BinaryPath   string // the gin-recon binary to re-exec per target, e.g. a resolved os.Args[0]
	ToolVersion  string
	Stderr       *bytes.Buffer // per-target stderr tails are captured here for the caller to surface; may be nil
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

// runOneTarget resolves one target's --src, classifies it, and — for a real
// Go module — re-execs the gin-recon binary's own audit command against it.
// This is the one place fleet ever spawns a subprocess; there is no
// in-process call into internal/analyzer anywhere in this package, per
// docs/adr/0018-fleet-scanning.md's isolation decision.
func runOneTarget(ctx context.Context, opts RunOptions, manifestDir string, t Target) TargetResult {
	src := t.Src
	if !filepath.IsAbs(src) {
		src = filepath.Join(manifestDir, src)
	}

	res := TargetResult{Name: t.Name, Src: src}

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

	args := []string{"audit", "--src", src, "--format", "json", "--out", targetOut, "--force"}
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
	return res
}

func tail(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return s[len(s)-limit:]
}
