package fleet

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// fakeAuditSource is a minimal stand-in for gin-recon's real "audit"
// subcommand, compiled once per test run and pointed at by RunOptions.
// BinaryPath. Real end-to-end behavior against the actual binary is already
// exercised by hand (docs/adr/0018-fleet-scanning.md's own validation); this
// keeps Run's own orchestration (concurrency, checkpointing, status
// classification, ordering) fast and hermetic to test in isolation. Each
// target directory carries a "behavior" file this fake reads to decide what
// to do, keyed by --src.
const fakeAuditSource = `package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		os.Exit(1)
	}
	if os.Args[1] == "suggest-auth" {
		fs := flag.NewFlagSet("suggest-auth", flag.ExitOnError)
		out := fs.String("out", "", "")
		fs.String("src", "", "")
		fs.Bool("force", false, "")
		fs.String("config", "", "")
		fs.Bool("allow-downloads", false, "")
		fs.Parse(os.Args[2:])
		os.MkdirAll(*out, 0o755)
		os.WriteFile(filepath.Join(*out, "suggestions.json"), []byte(` + "`" + `{"candidates":[]}` + "`" + `), 0o644)
		return
	}
	if os.Args[1] != "audit" {
		fmt.Fprintln(os.Stderr, "fake-audit: expected \"audit\" as the first argument")
		os.Exit(1)
	}
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	src := fs.String("src", "", "")
	out := fs.String("out", "", "")
	format := fs.String("format", "", "")
	fs.Bool("force", false, "")
	config := fs.String("config", "", "")
	fs.Parse(os.Args[2:])

	behavior, err := os.ReadFile(filepath.Join(*src, "behavior"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "fake-audit: no behavior file")
		os.Exit(1)
	}
	complete := "false"
	summary := ""
	switch string(behavior) {
	case "fail":
		fmt.Fprintln(os.Stderr, "fake-audit: simulated failure")
		os.Exit(1)
	case "complete":
		complete = "true"
	case "incomplete":
		complete = "false"
	case "with-routes":
		complete = "true"
		summary = ` + "`" + `,"summary":{"totalRoutes":5,"provenByConfirmedShape":2,"provenByAttestedUnresolved":1,"public":1,"unknown":1}` + "`" + `
	default:
		fmt.Fprintln(os.Stderr, "fake-audit: unknown behavior")
		os.Exit(1)
	}
	os.MkdirAll(*out, 0o755)
	os.WriteFile(filepath.Join(*out, "routes.json"), []byte(` + "`" + `{"scanCoverage":{"complete":` + "`" + `+complete+` + "`" + `}` + "`" + `+summary+` + "`" + `}` + "`" + `), 0o644)
	os.WriteFile(filepath.Join(*out, "config-used.txt"), []byte(*config), 0o644)
	if strings.Contains(*format, "openapi") {
		os.WriteFile(filepath.Join(*out, "openapi.json"), []byte("{}"), 0o644)
		os.WriteFile(filepath.Join(*out, "api.html"), []byte("<html></html>"), 0o644)
	}
	if strings.Contains(*format, "md") {
		os.WriteFile(filepath.Join(*out, "routes.md"), []byte("# routes"), 0o644)
	}
	if strings.Contains(*format, "sarif") {
		os.WriteFile(filepath.Join(*out, "results.sarif"), []byte("{}"), 0o644)
	}
}
`

func buildFakeAudit(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "main.go")
	if err := os.WriteFile(srcPath, []byte(fakeAuditSource), 0o644); err != nil {
		t.Fatal(err)
	}
	binPath := filepath.Join(dir, "fake-audit")
	cmd := exec.Command("go", "build", "-o", binPath, srcPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building fake audit helper: %v\n%s", err, out)
	}
	return binPath
}

func targetDir(t *testing.T, behavior string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module fixture\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if behavior != "" {
		if err := os.WriteFile(filepath.Join(dir, "behavior"), []byte(behavior), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// TestRunMovesAPIHTMLIntoHTMLOutDir exercises
// docs/adr/0023-fleet-raw-rendered-split.md end to end: a target whose own
// --format included "openapi" gets its api.html moved out of the raw
// --out tree into the sibling HTMLOutDir, with the raw openapi.json left
// behind — a plain file move, not a second scan.
func TestRunMovesAPIHTMLIntoHTMLOutDir(t *testing.T) {
	bin := buildFakeAudit(t)
	manifest := &Manifest{Version: 1, Targets: []Target{
		{Name: "svc-a", Src: targetDir(t, "complete")},
	}}
	outDir := t.TempDir()
	htmlOutDir := t.TempDir()

	agg, err := Run(context.Background(), RunOptions{
		ManifestPath: filepath.Join(t.TempDir(), "targets.json"),
		Manifest:     manifest,
		ManifestData: []byte("fixture"),
		Formats:      []string{"json", "openapi"},
		OutDir:       outDir,
		HTMLOutDir:   htmlOutDir,
		Concurrency:  1,
		BinaryPath:   bin,
		ToolVersion:  "test",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	got := agg.Targets[0]
	if got.APIHTML != filepath.Join("targets", "svc-a", "api.html") {
		t.Errorf("APIHTML = %q, want targets/svc-a/api.html", got.APIHTML)
	}
	if _, err := os.Stat(filepath.Join(htmlOutDir, "targets", "svc-a", "api.html")); err != nil {
		t.Errorf("api.html was not moved into HTMLOutDir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outDir, "targets", "svc-a", "api.html")); !os.IsNotExist(err) {
		t.Error("api.html should no longer exist in the raw --out tree after the move")
	}
	if _, err := os.Stat(filepath.Join(outDir, "targets", "svc-a", "openapi.json")); err != nil {
		t.Errorf("openapi.json (raw evidence) should stay in --out: %v", err)
	}
}

func TestRunLeavesAPIHTMLFieldEmptyWithoutHTMLOutDir(t *testing.T) {
	bin := buildFakeAudit(t)
	manifest := &Manifest{Version: 1, Targets: []Target{
		{Name: "svc-a", Src: targetDir(t, "complete")},
	}}
	agg, err := Run(context.Background(), RunOptions{
		ManifestPath: filepath.Join(t.TempDir(), "targets.json"),
		Manifest:     manifest,
		ManifestData: []byte("fixture"),
		Formats:      []string{"json", "openapi"},
		OutDir:       t.TempDir(),
		Concurrency:  1,
		BinaryPath:   bin,
		ToolVersion:  "test",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if agg.Targets[0].APIHTML != "" {
		t.Errorf("APIHTML = %q, want empty when HTMLOutDir was never set", agg.Targets[0].APIHTML)
	}
}

func TestFormatsWithJSONAddsJSONOnce(t *testing.T) {
	cases := [][]string{
		{"openapi"},
		{"json", "openapi"},
		{"openapi", "json"},
		{},
	}
	for _, in := range cases {
		out := formatsWithJSON(in)
		count := 0
		for _, f := range out {
			if f == "json" {
				count++
			}
		}
		if count != 1 {
			t.Errorf("formatsWithJSON(%v) = %v, want exactly one \"json\"", in, out)
		}
	}
}

func TestRunClassifiesEveryStatus(t *testing.T) {
	bin := buildFakeAudit(t)
	notGoModule := t.TempDir() // no go.mod at all

	manifest := &Manifest{Version: 1, Targets: []Target{
		{Name: "ok", Src: targetDir(t, "complete")},
		{Name: "incomplete", Src: targetDir(t, "incomplete")},
		{Name: "failed", Src: targetDir(t, "fail")},
		{Name: "not-go", Src: notGoModule},
	}}
	outDir := t.TempDir()

	agg, err := Run(context.Background(), RunOptions{
		ManifestPath: filepath.Join(t.TempDir(), "targets.json"),
		Manifest:     manifest,
		ManifestData: []byte("fixture"),
		Formats:      []string{"json"},
		OutDir:       outDir,
		Concurrency:  2,
		BinaryPath:   bin,
		ToolVersion:  "test",
	})
	if err != nil {
		t.Fatalf("Run: unexpected error: %v", err)
	}

	if len(agg.Targets) != 4 {
		t.Fatalf("Targets = %d, want 4", len(agg.Targets))
	}
	want := map[string]Status{"ok": StatusOK, "incomplete": StatusOK, "failed": StatusFailed, "not-go": StatusNotGoModule}
	for _, r := range agg.Targets {
		if r.Status != want[r.Name] {
			t.Errorf("target %q: Status = %v, want %v", r.Name, r.Status, want[r.Name])
		}
	}
	// Manifest order must survive concurrent execution.
	for i, name := range []string{"ok", "incomplete", "failed", "not-go"} {
		if agg.Targets[i].Name != name {
			t.Errorf("Targets[%d].Name = %q, want %q (order must match the manifest)", i, agg.Targets[i].Name, name)
		}
	}
	if agg.Coverage.Complete {
		t.Error("Coverage.Complete = true, want false: one target failed and one reported incomplete coverage")
	}

	failed := agg.Targets[2]
	if failed.Error == "" {
		t.Error("failed target has no captured stderr")
	}
}

// TestRunPopulatesRouteEvidenceCounts covers fleet.html's redesigned
// metrics/table (docs/adr/0028-gin-recon-default-output-directory.md's
// accompanying change): each OK target's own routes.json "summary" block
// is copied onto its TargetResult, and Aggregate.Totals is the sum across
// every target — not recomputed from anything else, so a target reporting
// zero routes (no "summary" key at all, the "complete"/"incomplete"
// behaviors above) must not contribute anything but zeros.
func TestRunPopulatesRouteEvidenceCounts(t *testing.T) {
	bin := buildFakeAudit(t)
	manifest := &Manifest{Version: 1, Targets: []Target{
		{Name: "with-routes", Src: targetDir(t, "with-routes")},
		{Name: "empty", Src: targetDir(t, "complete")},
	}}
	outDir := t.TempDir()

	agg, err := Run(context.Background(), RunOptions{
		ManifestPath: filepath.Join(t.TempDir(), "targets.json"),
		Manifest:     manifest,
		ManifestData: []byte("fixture"),
		Formats:      []string{"json"},
		OutDir:       outDir,
		Concurrency:  2,
		BinaryPath:   bin,
		ToolVersion:  "test",
	})
	if err != nil {
		t.Fatalf("Run: unexpected error: %v", err)
	}

	withRoutes := agg.Targets[0]
	if withRoutes.Routes != 5 || withRoutes.Proven != 3 || withRoutes.Public != 1 || withRoutes.Unknown != 1 {
		t.Errorf("with-routes target = %+v, want Routes=5 Proven=3 Public=1 Unknown=1", withRoutes)
	}
	empty := agg.Targets[1]
	if empty.Routes != 0 || empty.Proven != 0 || empty.Public != 0 || empty.Unknown != 0 {
		t.Errorf("empty target = %+v, want all-zero evidence counts", empty)
	}

	if agg.Totals.Routes != 5 || agg.Totals.Proven != 3 || agg.Totals.Public != 1 || agg.Totals.Unknown != 1 {
		t.Errorf("Totals = %+v, want Routes=5 Proven=3 Public=1 Unknown=1", agg.Totals)
	}
}

// TestRunUsesTargetOwnConfigWhenPresent is a regression test for
// docs/adr/0031-fleet-per-target-config.md: with --use-target-config, a
// target whose own source tree commits targetConfigFilename must use it
// instead of the fleet-wide --config — real per-repository evidence a
// human already reviewed, the same thing a direct `audit --config
// <that repo's own file>` invocation would use for that one repository.
func TestRunUsesTargetOwnConfigWhenPresent(t *testing.T) {
	bin := buildFakeAudit(t)

	withOwn := targetDir(t, "complete")
	ownConfig := filepath.Join(withOwn, targetConfigFilename)
	if err := os.WriteFile(ownConfig, []byte(`{"version":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	withoutOwn := targetDir(t, "complete")

	sharedConfig := filepath.Join(t.TempDir(), "shared-config.json")
	if err := os.WriteFile(sharedConfig, []byte(`{"version":1}`), 0o644); err != nil {
		t.Fatal(err)
	}

	manifest := &Manifest{Version: 1, Targets: []Target{
		{Name: "has-own-config", Src: withOwn},
		{Name: "no-own-config", Src: withoutOwn},
	}}
	outDir := t.TempDir()

	agg, err := Run(context.Background(), RunOptions{
		ManifestPath:    filepath.Join(t.TempDir(), "targets.json"),
		Manifest:        manifest,
		ManifestData:    []byte("fixture"),
		ConfigPath:      sharedConfig,
		Formats:         []string{"json"},
		OutDir:          outDir,
		Concurrency:     2,
		BinaryPath:      bin,
		ToolVersion:     "test",
		UseTargetConfig: true,
	})
	if err != nil {
		t.Fatalf("Run: unexpected error: %v", err)
	}

	usedByHasOwn, err := os.ReadFile(filepath.Join(outDir, "targets", "has-own-config", "config-used.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(usedByHasOwn) == sharedConfig || filepath.Ext(string(usedByHasOwn)) != filepath.Ext(ownConfig) {
		t.Errorf("has-own-config target's audit subprocess used --config %q, want an immutable snapshot of its own %q", usedByHasOwn, ownConfig)
	}
	if !agg.Targets[0].TargetConfig {
		t.Error("agg.Targets[0].TargetConfig = false, want true")
	}

	usedByNoOwn, err := os.ReadFile(filepath.Join(outDir, "targets", "no-own-config", "config-used.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(usedByNoOwn) != sharedConfig {
		t.Errorf("no-own-config target's audit subprocess used --config %q, want the shared config %q", usedByNoOwn, sharedConfig)
	}
	if agg.Targets[1].TargetConfig {
		t.Error("agg.Targets[1].TargetConfig = true, want false: this target has no own-config file")
	}
}

// TestRunIgnoresTargetOwnConfigWithoutFlag confirms --use-target-config
// actually gates the behavior: without it, a target's own committed
// targetConfigFilename must be ignored entirely, same as before this ADR.
func TestRunIgnoresTargetOwnConfigWithoutFlag(t *testing.T) {
	bin := buildFakeAudit(t)

	withOwn := targetDir(t, "complete")
	if err := os.WriteFile(filepath.Join(withOwn, targetConfigFilename), []byte(`{"version":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	sharedConfig := filepath.Join(t.TempDir(), "shared-config.json")
	if err := os.WriteFile(sharedConfig, []byte(`{"version":1}`), 0o644); err != nil {
		t.Fatal(err)
	}

	manifest := &Manifest{Version: 1, Targets: []Target{{Name: "has-own-config", Src: withOwn}}}
	outDir := t.TempDir()

	agg, err := Run(context.Background(), RunOptions{
		ManifestPath: filepath.Join(t.TempDir(), "targets.json"),
		Manifest:     manifest,
		ManifestData: []byte("fixture"),
		ConfigPath:   sharedConfig,
		Formats:      []string{"json"},
		OutDir:       outDir,
		Concurrency:  1,
		BinaryPath:   bin,
		ToolVersion:  "test",
		// UseTargetConfig deliberately left false.
	})
	if err != nil {
		t.Fatalf("Run: unexpected error: %v", err)
	}

	used, err := os.ReadFile(filepath.Join(outDir, "targets", "has-own-config", "config-used.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(used) != sharedConfig {
		t.Errorf("used --config %q, want the shared config %q: --use-target-config was not set", used, sharedConfig)
	}
	if agg.Targets[0].TargetConfig {
		t.Error("TargetConfig = true, want false: --use-target-config was not set")
	}
}

// TestRunTargetConfigDirOutranksRepoOwnConfig is the core regression test
// for docs/adr/0033-fleet-target-config-dir.md: an operator-owned
// --target-config-dir entry must win over a target's own repo-committed
// config when both exist for the same target — stronger, independently
// controlled evidence takes precedence over evidence the scanned
// repository itself supplied.
func TestRunTargetConfigDirOutranksRepoOwnConfig(t *testing.T) {
	bin := buildFakeAudit(t)

	src := targetDir(t, "complete")
	repoConfig := filepath.Join(src, targetConfigFilename)
	if err := os.WriteFile(repoConfig, []byte(`{"version":1}`), 0o644); err != nil {
		t.Fatal(err)
	}

	targetConfigDir := t.TempDir()
	dirConfig := filepath.Join(targetConfigDir, "has-both.json")
	if err := os.WriteFile(dirConfig, []byte(`{"version":1}`), 0o644); err != nil {
		t.Fatal(err)
	}

	manifest := &Manifest{Version: 1, Targets: []Target{{Name: "has-both", Src: src}}}
	outDir := t.TempDir()

	agg, err := Run(context.Background(), RunOptions{
		ManifestPath:    filepath.Join(t.TempDir(), "targets.json"),
		Manifest:        manifest,
		ManifestData:    []byte("fixture"),
		Formats:         []string{"json"},
		OutDir:          outDir,
		Concurrency:     1,
		BinaryPath:      bin,
		ToolVersion:     "test",
		UseTargetConfig: true,
		TargetConfigDir: targetConfigDir,
	})
	if err != nil {
		t.Fatalf("Run: unexpected error: %v", err)
	}

	used, err := os.ReadFile(filepath.Join(outDir, "targets", "has-both", "config-used.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(used) != dirConfig {
		t.Errorf("used --config %q, want the target-config-dir file %q to win", used, dirConfig)
	}
	if !agg.Targets[0].TargetConfigDir {
		t.Error("TargetConfigDir = false, want true")
	}
	if agg.Targets[0].TargetConfig {
		t.Error("TargetConfig = true, want false: outranked by TargetConfigDir")
	}
}

// TestRunTargetConfigDirFallsBackWithoutEntry confirms a target with no
// matching file in --target-config-dir still falls back correctly (to its
// own repo config if --use-target-config found one, else the shared
// --config) rather than silently using nothing.
func TestRunTargetConfigDirFallsBackWithoutEntry(t *testing.T) {
	bin := buildFakeAudit(t)

	sharedConfig := filepath.Join(t.TempDir(), "shared-config.json")
	if err := os.WriteFile(sharedConfig, []byte(`{"version":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	targetConfigDir := t.TempDir() // empty — no entry for "no-entry"

	manifest := &Manifest{Version: 1, Targets: []Target{{Name: "no-entry", Src: targetDir(t, "complete")}}}
	outDir := t.TempDir()

	agg, err := Run(context.Background(), RunOptions{
		ManifestPath:    filepath.Join(t.TempDir(), "targets.json"),
		Manifest:        manifest,
		ManifestData:    []byte("fixture"),
		ConfigPath:      sharedConfig,
		Formats:         []string{"json"},
		OutDir:          outDir,
		Concurrency:     1,
		BinaryPath:      bin,
		ToolVersion:     "test",
		TargetConfigDir: targetConfigDir,
	})
	if err != nil {
		t.Fatalf("Run: unexpected error: %v", err)
	}

	used, err := os.ReadFile(filepath.Join(outDir, "targets", "no-entry", "config-used.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(used) != sharedConfig {
		t.Errorf("used --config %q, want fallback to the shared config %q", used, sharedConfig)
	}
	if agg.Targets[0].TargetConfigDir {
		t.Error("TargetConfigDir = true, want false: no matching file in the directory")
	}
}

func TestRunResumeSkipsCompletedTargets(t *testing.T) {
	bin := buildFakeAudit(t)
	manifestPath := filepath.Join(t.TempDir(), "targets.json")
	manifest := &Manifest{Version: 1, Targets: []Target{
		{Name: "a", Src: targetDir(t, "complete")},
		{Name: "b", Src: targetDir(t, "fail")},
	}}
	outDir := t.TempDir()
	base := RunOptions{
		ManifestPath: manifestPath,
		Manifest:     manifest,
		ManifestData: []byte("fixture"),
		Formats:      []string{"json"},
		OutDir:       outDir,
		Concurrency:  1,
		BinaryPath:   bin,
		ToolVersion:  "test",
	}

	if _, err := Run(context.Background(), base); err != nil {
		t.Fatalf("first Run: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outDir, CheckpointFilename)); err != nil {
		t.Fatalf("expected a checkpoint after an incomplete run: %v", err)
	}

	// Fix "b" so a resumed run can actually complete, then confirm "a" is
	// reused from the checkpoint rather than re-executed (its target
	// directory's behavior file no longer matters if it's skipped).
	if err := os.WriteFile(filepath.Join(manifest.Targets[1].Src, "behavior"), []byte("complete"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(manifest.Targets[0].Src, "behavior"), []byte("fail"), 0o644); err != nil {
		t.Fatal(err)
	}

	resumeOpts := base
	resumeOpts.Resume = true
	agg, err := Run(context.Background(), resumeOpts)
	if err != nil {
		t.Fatalf("resumed Run: %v", err)
	}
	if agg.Resume.Reused != 1 {
		t.Errorf("Resume.Reused = %d, want 1", agg.Resume.Reused)
	}
	a := agg.Targets[0]
	if a.Status != StatusOK {
		t.Errorf("target %q: Status = %v, want ok (reused from checkpoint despite its behavior file now saying fail)", a.Name, a.Status)
	}
	if !agg.Coverage.Complete {
		t.Error("Coverage.Complete = false, want true after both targets succeeded")
	}
	if _, err := os.Stat(filepath.Join(outDir, CheckpointFilename)); err != nil {
		t.Errorf("checkpoint should remain until the caller durably writes fleet.json: %v", err)
	}
	if err := RemoveCheckpoint(outDir); err != nil {
		t.Fatalf("RemoveCheckpoint: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outDir, CheckpointFilename)); !os.IsNotExist(err) {
		t.Error("RemoveCheckpoint should remove the journal after durable output")
	}
}

// TestRunReportsProgress is a regression test for a real complaint: a fleet
// run produced no output at all until it finished, which for a long,
// many-target run reads as a hang. Progress must print one line per target
// live as each one finishes (or is reused from a --resume checkpoint), not
// batched up for the end — checked here with Concurrency: 1 so completion
// order is deterministic.
func TestRunReportsProgress(t *testing.T) {
	bin := buildFakeAudit(t)
	manifestPath := filepath.Join(t.TempDir(), "targets.json")
	manifest := &Manifest{Version: 1, Targets: []Target{
		{Name: "a", Src: targetDir(t, "with-routes")},
		{Name: "b", Src: targetDir(t, "fail")},
	}}
	outDir := t.TempDir()
	var progress bytes.Buffer

	agg, err := Run(context.Background(), RunOptions{
		ManifestPath: manifestPath,
		Manifest:     manifest,
		ManifestData: []byte("fixture"),
		Formats:      []string{"json"},
		OutDir:       outDir,
		Concurrency:  1,
		BinaryPath:   bin,
		ToolVersion:  "test",
		Progress:     &progress,
	})
	if err != nil {
		t.Fatalf("Run: unexpected error: %v", err)
	}
	if agg.Targets[0].Status != StatusOK || agg.Targets[1].Status != StatusFailed {
		t.Fatalf("unexpected statuses: %+v", agg.Targets)
	}

	want := "[stage] a: discover\n[stage] a: audit: discover+classify\n[stage] a: publish\n[1/2] a: ok (5 routes)\n[stage] b: discover\n[stage] b: audit: discover+classify\n[2/2] b: failed\n"
	if progress.String() != want {
		t.Errorf("progress output = %q, want %q", progress.String(), want)
	}
}

// TestRunReportsProgressForResumedTargets confirms a target reused from a
// --resume checkpoint still gets its own progress line, marked distinctly,
// rather than silently vanishing from the count.
func TestRunReportsProgressForResumedTargets(t *testing.T) {
	bin := buildFakeAudit(t)
	manifestPath := filepath.Join(t.TempDir(), "targets.json")
	manifest := &Manifest{Version: 1, Targets: []Target{
		{Name: "a", Src: targetDir(t, "complete")},
		{Name: "b", Src: targetDir(t, "fail")},
	}}
	outDir := t.TempDir()
	base := RunOptions{
		ManifestPath: manifestPath,
		Manifest:     manifest,
		ManifestData: []byte("fixture"),
		Formats:      []string{"json"},
		OutDir:       outDir,
		Concurrency:  1,
		BinaryPath:   bin,
		ToolVersion:  "test",
	}
	if _, err := Run(context.Background(), base); err != nil {
		t.Fatalf("first Run: %v", err)
	}
	if err := os.WriteFile(filepath.Join(manifest.Targets[1].Src, "behavior"), []byte("complete"), 0o644); err != nil {
		t.Fatal(err)
	}

	var progress bytes.Buffer
	resumeOpts := base
	resumeOpts.Resume = true
	resumeOpts.Progress = &progress
	if _, err := Run(context.Background(), resumeOpts); err != nil {
		t.Fatalf("resumed Run: %v", err)
	}

	want := "[1/2] a: ok (resumed)\n[stage] b: discover\n[stage] b: audit: discover+classify\n[stage] b: publish\n[2/2] b: ok (0 routes)\n"
	if progress.String() != want {
		t.Errorf("progress output = %q, want %q", progress.String(), want)
	}
}

// TestRunPreseedReusesUnchangedTarget is the core regression test for
// docs/adr/0039-fleet-org-update.md: a target present in Preseed (cmd/gin-recon's
// own "unchanged since the previous complete run" determination, based on
// GitHub pushedAt) must be reused exactly like a --resume checkpoint hit —
// no goroutine spawned, no rescan — while a target with no Preseed entry
// still runs normally. Progress must label the two differently ("resumed"
// vs "unchanged") since they're different provenance.
func TestRunPreseedReusesUnchangedTarget(t *testing.T) {
	bin := buildFakeAudit(t)
	manifest := &Manifest{Version: 1, Targets: []Target{
		{Name: "unchanged", Src: targetDir(t, "fail")}, // would fail if actually rescanned
		{Name: "changed", Src: targetDir(t, "complete")},
	}}
	outDir := t.TempDir()
	reportDir := filepath.Join(outDir, "targets", "unchanged")
	if err := os.MkdirAll(reportDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(reportDir, "routes.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	artifact, err := artifactForFile(outDir, filepath.Join("targets", "unchanged", "routes.json"))
	if err != nil {
		t.Fatal(err)
	}
	discovery, err := discoverRepository(manifest.Targets[0].Src)
	if err != nil {
		t.Fatal(err)
	}
	preseededResult := TargetResult{
		Name: "unchanged", Status: StatusOK, Complete: true, Routes: 9,
		SourceFingerprint: resolvedSourceFingerprint(manifest.Targets[0], discovery.Fingerprint), Artifacts: []Artifact{artifact},
		Modules: []ModuleResult{{
			ID: "root", Path: ".", ModulePath: "fixture", Kind: ModuleGo,
			Status: StatusOK, Complete: true,
			Report: filepath.ToSlash(filepath.Join("targets", "unchanged", "routes.json")), Artifacts: []Artifact{artifact},
		}},
	}
	var progress bytes.Buffer

	agg, err := Run(context.Background(), RunOptions{
		ManifestPath: filepath.Join(t.TempDir(), "targets.json"),
		Manifest:     manifest,
		ManifestData: []byte("fixture"),
		Formats:      []string{"json"},
		OutDir:       outDir,
		Concurrency:  1,
		BinaryPath:   bin,
		ToolVersion:  "test",
		Progress:     &progress,
		Preseed:      map[string]TargetResult{"unchanged": preseededResult},
	})
	if err != nil {
		t.Fatalf("Run: unexpected error: %v", err)
	}

	if !reflect.DeepEqual(agg.Targets[0], preseededResult) {
		t.Errorf("Targets[0] = %+v, want the preseeded result verbatim (not rescanned)", agg.Targets[0])
	}
	if agg.Targets[1].Status != StatusOK {
		t.Errorf("Targets[1].Status = %v, want ok: a target with no Preseed entry must still run normally", agg.Targets[1].Status)
	}
	if !agg.Update.Requested {
		t.Error("Update.Requested = false, want true: Preseed was set")
	}
	if agg.Update.Reused != 1 {
		t.Errorf("Update.Reused = %d, want 1", agg.Update.Reused)
	}
	if agg.Resume.Reused != 0 {
		t.Errorf("Resume.Reused = %d, want 0: this wasn't a checkpoint resume", agg.Resume.Reused)
	}

	want := "[1/2] unchanged: ok (unchanged)\n[stage] changed: discover\n[stage] changed: audit: discover+classify\n[stage] changed: publish\n[2/2] changed: ok (0 routes)\n"
	if progress.String() != want {
		t.Errorf("progress output = %q, want %q", progress.String(), want)
	}
}

func TestRunScansEveryNestedModuleWithoutRootGoMod(t *testing.T) {
	bin := buildFakeAudit(t)
	repo := t.TempDir()
	for _, module := range []struct{ path, behavior string }{
		{"services/api", "with-routes"},
		{"workers/jobs", "complete"},
	} {
		dir := filepath.Join(repo, module.path)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/"+filepath.Base(module.path)+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "behavior"), []byte(module.behavior), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	manifest := &Manifest{Version: 1, Targets: []Target{{Name: "monorepo", Src: repo}}}
	outDir := t.TempDir()
	agg, err := Run(context.Background(), RunOptions{
		ManifestPath: filepath.Join(t.TempDir(), "targets.json"), Manifest: manifest,
		ManifestData: []byte("fixture"), Formats: []string{"json"}, OutDir: outDir,
		Concurrency: 1, BinaryPath: bin, ToolVersion: "test",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	result := agg.Targets[0]
	if result.Status != StatusOK || !result.Complete {
		t.Fatalf("target = %+v, want complete multi-module result", result)
	}
	if result.Inventory.Kind != RepositoryMultiModule || len(result.Modules) != 2 {
		t.Fatalf("inventory/modules = %+v / %+v", result.Inventory, result.Modules)
	}
	if result.Routes != 5 || result.Report != "" {
		t.Fatalf("rollup routes/report = %d/%q, want 5 and no misleading single report", result.Routes, result.Report)
	}
	for _, module := range result.Modules {
		if module.Report == "" {
			t.Fatalf("module has no report: %+v", module)
		}
		if _, err := os.Stat(filepath.Join(outDir, filepath.FromSlash(module.Report))); err != nil {
			t.Fatalf("module report %s missing: %v", module.Report, err)
		}
	}
}

// TestRunNonGinModuleFailureDoesNotFailSiblingGinModule is a real, confirmed
// case found auditing a live organization, not a hypothetical one: a
// repository with a sibling "tools" go.mod (a common Go idiom pinning
// devtool versions behind a //go:build tools tag, never requiring
// github.com/gin-gonic/gin) that fails to load — its "./..." matches zero
// buildable packages under a normal build context — used to fail the
// *entire* target, discarding a genuinely separate, fully complete,
// zero-error scan of the repository's actual Gin application module. A
// module that never required gin in its own go.mod can never define a real
// Gin route, so its own tooling problem must never be allowed to discard an
// unrelated sibling module's real, complete evidence.
func TestRunNonGinModuleFailureDoesNotFailSiblingGinModule(t *testing.T) {
	bin := buildFakeAudit(t)
	repo := t.TempDir()

	appDir := filepath.Join(repo, "app")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appDir, "go.mod"), []byte("module example.com/app\n\nrequire github.com/gin-gonic/gin v1.9.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appDir, "behavior"), []byte("with-routes"), 0o644); err != nil {
		t.Fatal(err)
	}

	toolsDir := filepath.Join(repo, "tools")
	if err := os.MkdirAll(toolsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(toolsDir, "go.mod"), []byte("module example.com/tools\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(toolsDir, "behavior"), []byte("fail"), 0o644); err != nil {
		t.Fatal(err)
	}

	manifest := &Manifest{Version: 1, Targets: []Target{{Name: "monorepo", Src: repo}}}
	outDir := t.TempDir()
	agg, err := Run(context.Background(), RunOptions{
		ManifestPath: filepath.Join(t.TempDir(), "targets.json"), Manifest: manifest,
		ManifestData: []byte("fixture"), Formats: []string{"json"}, OutDir: outDir,
		Concurrency: 1, BinaryPath: bin, ToolVersion: "test",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	result := agg.Targets[0]
	if result.Status != StatusOK {
		t.Fatalf("Status = %v, want ok: a non-Gin sibling module's failure must not fail the target", result.Status)
	}
	if result.Complete {
		t.Error("Complete = true, want false: one module genuinely could not be analyzed")
	}
	if result.Routes != 5 || result.Proven != 3 {
		t.Errorf("rollup routes/proven = %d/%d, want 5/3 from the surviving app module alone", result.Routes, result.Proven)
	}
	if len(result.Modules) != 2 {
		t.Fatalf("Modules = %+v, want both the failed tools module and the successful app module recorded", result.Modules)
	}
	for _, module := range result.Modules {
		switch module.Path {
		case "app":
			if module.Status != StatusOK || module.Report == "" {
				t.Errorf("app module = %+v, want ok with a real report", module)
			}
			if _, err := os.Stat(filepath.Join(outDir, filepath.FromSlash(module.Report))); err != nil {
				t.Errorf("app module report %s missing: %v", module.Report, err)
			}
		case "tools":
			if module.Status != StatusFailed || module.Report != "" {
				t.Errorf("tools module = %+v, want failed with no report", module)
			}
		default:
			t.Errorf("unexpected module path %q", module.Path)
		}
	}
}

func TestRunRetriesRemoteTargetAndRecordsAttempts(t *testing.T) {
	bin := buildFakeAudit(t)
	attempts := 0
	clone := func(ctx context.Context, gitURL, ref, destDir, token string) error {
		attempts++
		if attempts == 1 {
			return fmt.Errorf("transient clone failure")
		}
		if err := os.MkdirAll(destDir, 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(destDir, "go.mod"), []byte("module fixture\n"), 0o644); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(destDir, "behavior"), []byte("complete"), 0o644)
	}
	target := Target{Name: "remote", Git: &GitSource{URL: "https://github.com/acme/remote.git", Ref: "main"}}
	agg, err := Run(context.Background(), RunOptions{
		ManifestPath: "targets.json", Manifest: &Manifest{Version: 1, Targets: []Target{target}}, ManifestData: []byte("fixture"),
		Formats: []string{"json"}, OutDir: t.TempDir(), BinaryPath: bin, ToolVersion: "test",
		AllowRemote: true, AllowedHosts: []AllowedHost{{Host: "github.com"}}, Clone: clone,
		RepoAttempts: 2, RepoTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 2 || agg.Targets[0].Status != StatusOK || agg.Targets[0].Attempts != 2 {
		t.Fatalf("attempts/result = %d / %+v", attempts, agg.Targets[0])
	}
}

func TestRunBoundsRemoteTargetByDeadline(t *testing.T) {
	clone := func(ctx context.Context, gitURL, ref, destDir, token string) error {
		<-ctx.Done()
		return ctx.Err()
	}
	target := Target{Name: "remote", Git: &GitSource{URL: "https://github.com/acme/remote.git", Ref: "main"}}
	agg, err := Run(context.Background(), RunOptions{
		ManifestPath: "targets.json", Manifest: &Manifest{Version: 1, Targets: []Target{target}}, ManifestData: []byte("fixture"),
		Formats: []string{"json"}, OutDir: t.TempDir(), BinaryPath: "unused", ToolVersion: "test",
		AllowRemote: true, AllowedHosts: []AllowedHost{{Host: "github.com"}}, Clone: clone,
		RepoAttempts: 3, RepoTimeout: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if agg.Targets[0].Status != StatusFailed || !strings.Contains(agg.Targets[0].Error, "deadline exceeded") {
		t.Fatalf("deadline result = %+v", agg.Targets[0])
	}
}

func TestRunResumeRejectsChangedManifest(t *testing.T) {
	bin := buildFakeAudit(t)
	outDir := t.TempDir()
	// At least one target must actually succeed so a checkpoint file exists
	// at all for a resumed run to compare its identity against — a run
	// where everything failed leaves no checkpoint on disk, and resuming
	// into "no checkpoint yet" is legitimately not an identity mismatch.
	manifest := &Manifest{Version: 1, Targets: []Target{
		{Name: "a", Src: targetDir(t, "complete")},
		{Name: "b", Src: targetDir(t, "fail")},
	}}
	base := RunOptions{
		ManifestPath: filepath.Join(t.TempDir(), "targets.json"),
		Manifest:     manifest,
		ManifestData: []byte("v1"),
		Formats:      []string{"json"},
		OutDir:       outDir,
		Concurrency:  1,
		BinaryPath:   bin,
		ToolVersion:  "test",
	}
	if _, err := Run(context.Background(), base); err != nil {
		t.Fatalf("first Run: %v", err)
	}

	resumeOpts := base
	resumeOpts.Resume = true
	resumeOpts.ManifestData = []byte("v2")
	if _, err := Run(context.Background(), resumeOpts); err == nil {
		t.Fatal("expected Run to refuse resume after the manifest changed")
	}
}

func fakeClone(behavior string) CloneFunc {
	return func(ctx context.Context, gitURL, ref, destDir, token string) error {
		switch behavior {
		case "fail":
			return fmt.Errorf("simulated clone failure")
		default:
			if err := os.MkdirAll(destDir, 0o755); err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(destDir, "go.mod"), []byte("module cloned\n"), 0o644)
		}
	}
}

func TestRunRejectsGitTargetWithoutAllowRemote(t *testing.T) {
	bin := buildFakeAudit(t)
	manifest := &Manifest{Version: 1, Targets: []Target{
		{Name: "remote", Git: &GitSource{URL: "https://github.com/example/repo.git"}},
	}}
	agg, err := Run(context.Background(), RunOptions{
		ManifestPath: filepath.Join(t.TempDir(), "targets.json"),
		Manifest:     manifest,
		ManifestData: []byte("fixture"),
		Formats:      []string{"json"},
		OutDir:       t.TempDir(),
		Concurrency:  1,
		BinaryPath:   bin,
		ToolVersion:  "test",
		Clone:        fakeClone("ok"),
		// AllowRemote left false.
	})
	if err != nil {
		t.Fatalf("Run: unexpected error: %v", err)
	}
	if agg.Targets[0].Status != StatusFailed {
		t.Fatalf("Status = %v, want failed", agg.Targets[0].Status)
	}
	if !strings.Contains(agg.Targets[0].Error, "--allow-remote-targets") {
		t.Errorf("Error = %q, want it to mention --allow-remote-targets", agg.Targets[0].Error)
	}
}

func TestRunRejectsGitTargetWithUnlistedHost(t *testing.T) {
	bin := buildFakeAudit(t)
	manifest := &Manifest{Version: 1, Targets: []Target{
		{Name: "remote", Git: &GitSource{URL: "https://gitlab.example.com/example/repo.git"}},
	}}
	agg, err := Run(context.Background(), RunOptions{
		ManifestPath: filepath.Join(t.TempDir(), "targets.json"),
		Manifest:     manifest,
		ManifestData: []byte("fixture"),
		Formats:      []string{"json"},
		OutDir:       t.TempDir(),
		Concurrency:  1,
		BinaryPath:   bin,
		ToolVersion:  "test",
		Clone:        fakeClone("ok"),
		AllowRemote:  true,
		AllowedHosts: []AllowedHost{{Host: "github.com"}}, // does not include gitlab.example.com
	})
	if err != nil {
		t.Fatalf("Run: unexpected error: %v", err)
	}
	if agg.Targets[0].Status != StatusFailed {
		t.Fatalf("Status = %v, want failed", agg.Targets[0].Status)
	}
	if !strings.Contains(agg.Targets[0].Error, "allowedRemoteHosts") {
		t.Errorf("Error = %q, want it to mention allowedRemoteHosts", agg.Targets[0].Error)
	}
}

func TestRunClonesAllowedGitTarget(t *testing.T) {
	bin := buildFakeAudit(t)
	// The fake clone materializes a go.mod but no "behavior" file, so
	// runOneTarget's own post-clone audit invocation would fail — this test
	// only needs to prove the clone was attempted and allowed through,
	// which the resulting "failed" (not "not-go-module", not a
	// remote-target-policy error) status already demonstrates: policy
	// checks passed, the clone ran, and only the subsequent audit step
	// (no behavior file for the fake audit binary to read) failed.
	manifest := &Manifest{Version: 1, Targets: []Target{
		{Name: "remote", Git: &GitSource{URL: "https://github.com/example/repo.git"}},
	}}
	outDir := t.TempDir()
	agg, err := Run(context.Background(), RunOptions{
		ManifestPath: filepath.Join(t.TempDir(), "targets.json"),
		Manifest:     manifest,
		ManifestData: []byte("fixture"),
		Formats:      []string{"json"},
		OutDir:       outDir,
		Concurrency:  1,
		BinaryPath:   bin,
		ToolVersion:  "test",
		Clone:        fakeClone("ok"),
		AllowRemote:  true,
		AllowedHosts: []AllowedHost{{Host: "github.com"}},
	})
	if err != nil {
		t.Fatalf("Run: unexpected error: %v", err)
	}
	got := agg.Targets[0]
	if got.Status != StatusFailed || !strings.Contains(got.Error, "fake-audit") {
		t.Fatalf("target = %+v, want a failed status from the fake audit binary (proving the clone itself was allowed and ran)", got)
	}
	if _, err := os.Stat(filepath.Join(outDir, ".clones", "remote")); !os.IsNotExist(err) {
		t.Error("clone scratch directory should be removed after the target finishes")
	}
	// GitURL must survive into the result even though Src ends up pointing
	// at the (now-removed) ephemeral clone directory — it's the only field
	// that still means anything to a human reading the report afterward.
	if got.GitURL != "https://github.com/example/repo.git" {
		t.Errorf("GitURL = %q, want the manifest's original git.url", got.GitURL)
	}
}

func TestRunPropagatesCloneFailure(t *testing.T) {
	bin := buildFakeAudit(t)
	manifest := &Manifest{Version: 1, Targets: []Target{
		{Name: "remote", Git: &GitSource{URL: "https://github.com/example/repo.git"}},
	}}
	agg, err := Run(context.Background(), RunOptions{
		ManifestPath: filepath.Join(t.TempDir(), "targets.json"),
		Manifest:     manifest,
		ManifestData: []byte("fixture"),
		Formats:      []string{"json"},
		OutDir:       t.TempDir(),
		Concurrency:  1,
		BinaryPath:   bin,
		ToolVersion:  "test",
		Clone:        fakeClone("fail"),
		AllowRemote:  true,
		AllowedHosts: []AllowedHost{{Host: "github.com"}},
	})
	if err != nil {
		t.Fatalf("Run: unexpected error: %v", err)
	}
	if agg.Targets[0].Status != StatusFailed || !strings.Contains(agg.Targets[0].Error, "simulated clone failure") {
		t.Fatalf("target = %+v, want a failed status carrying the clone error", agg.Targets[0])
	}
}

func TestRunRejectsGitTargetWithMissingTokenEnv(t *testing.T) {
	bin := buildFakeAudit(t)
	manifest := &Manifest{Version: 1, Targets: []Target{
		{Name: "remote", Git: &GitSource{URL: "https://github.com/example/repo.git"}},
	}}
	agg, err := Run(context.Background(), RunOptions{
		ManifestPath: filepath.Join(t.TempDir(), "targets.json"),
		Manifest:     manifest,
		ManifestData: []byte("fixture"),
		Formats:      []string{"json"},
		OutDir:       t.TempDir(),
		Concurrency:  1,
		BinaryPath:   bin,
		ToolVersion:  "test",
		Clone:        fakeClone("ok"),
		AllowRemote:  true,
		AllowedHosts: []AllowedHost{{Host: "github.com", TokenEnv: "GIN_RECON_TEST_TOKEN_DOES_NOT_EXIST"}},
	})
	if err != nil {
		t.Fatalf("Run: unexpected error: %v", err)
	}
	if agg.Targets[0].Status != StatusFailed || !strings.Contains(agg.Targets[0].Error, "GIN_RECON_TEST_TOKEN_DOES_NOT_EXIST") {
		t.Fatalf("target = %+v, want a failed status naming the missing token env var", agg.Targets[0])
	}
}

func TestRunFailOnDoesNotMutateAggregateJSON(t *testing.T) {
	bin := buildFakeAudit(t)
	manifest := &Manifest{Version: 1, Targets: []Target{{Name: "a", Src: targetDir(t, "complete")}}}
	agg, err := Run(context.Background(), RunOptions{
		ManifestPath: filepath.Join(t.TempDir(), "targets.json"),
		Manifest:     manifest,
		ManifestData: []byte("fixture"),
		Formats:      []string{"json"},
		OutDir:       t.TempDir(),
		Concurrency:  1,
		BinaryPath:   bin,
		ToolVersion:  "test",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	data, err := json.Marshal(agg)
	if err != nil {
		t.Fatalf("encoding aggregate: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("decoding aggregate: %v", err)
	}
	if decoded["tool"] != "gin-recon" {
		t.Errorf(`tool = %v, want "gin-recon"`, decoded["tool"])
	}
}

func TestRunFailedTargetPreservesPreviouslyPublishedArtifacts(t *testing.T) {
	bin := buildFakeAudit(t)
	target := Target{Name: "service", Src: targetDir(t, "fail")}
	outDir := t.TempDir()
	published := filepath.Join(outDir, "targets", target.Name)
	if err := os.MkdirAll(published, 0o755); err != nil {
		t.Fatal(err)
	}
	want := []byte("previous complete report")
	if err := os.WriteFile(filepath.Join(published, "routes.json"), want, 0o644); err != nil {
		t.Fatal(err)
	}

	agg, err := Run(context.Background(), RunOptions{
		ManifestPath: filepath.Join(t.TempDir(), "targets.json"),
		Manifest:     &Manifest{Version: 1, Targets: []Target{target}}, ManifestData: []byte("fixture"),
		Formats: []string{"json"}, OutDir: outDir, Concurrency: 1, BinaryPath: bin, ToolVersion: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if agg.Targets[0].Status != StatusFailed {
		t.Fatalf("status = %s, want failed", agg.Targets[0].Status)
	}
	got, err := os.ReadFile(filepath.Join(published, "routes.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("failed scan replaced prior artifact: got %q, want %q", got, want)
	}
}

func TestRunResumeRescansChangedLocalSource(t *testing.T) {
	bin := buildFakeAudit(t)
	src := targetDir(t, "complete")
	if err := os.WriteFile(filepath.Join(src, "source.go"), []byte("package fixture\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	target := Target{Name: "service", Src: src}
	outDir := t.TempDir()
	opts := RunOptions{
		ManifestPath: filepath.Join(t.TempDir(), "targets.json"),
		Manifest:     &Manifest{Version: 1, Targets: []Target{target}}, ManifestData: []byte("fixture"),
		Formats: []string{"json"}, OutDir: outDir, Concurrency: 1, BinaryPath: bin, ToolVersion: "test",
	}
	if _, err := Run(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "source.go"), []byte("package fixture\n\nconst Changed = true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "behavior"), []byte("fail"), 0o644); err != nil {
		t.Fatal(err)
	}
	opts.Resume = true
	agg, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if agg.Resume.Reused != 0 || agg.Targets[0].Status != StatusFailed {
		t.Fatalf("changed local source was reused: resume=%+v target=%+v", agg.Resume, agg.Targets[0])
	}
}

func TestRunClassifiesGinModuleWithoutRoutesSeparately(t *testing.T) {
	bin := buildFakeAudit(t)
	src := targetDir(t, "complete")
	goMod := "module fixture\n\nrequire github.com/gin-gonic/gin v1.10.0\n"
	if err := os.WriteFile(filepath.Join(src, "go.mod"), []byte(goMod), 0o644); err != nil {
		t.Fatal(err)
	}
	agg, err := Run(context.Background(), RunOptions{
		ManifestPath: filepath.Join(t.TempDir(), "targets.json"),
		Manifest:     &Manifest{Version: 1, Targets: []Target{{Name: "library", Src: src}}}, ManifestData: []byte("fixture"),
		Formats: []string{"json"}, OutDir: t.TempDir(), Concurrency: 1, BinaryPath: bin, ToolVersion: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := agg.Targets[0].Modules[0].Kind; got != ModuleGinNoRoutes {
		t.Fatalf("module kind = %q, want %q", got, ModuleGinNoRoutes)
	}
}

func TestRunEmitsMachineReadableProgress(t *testing.T) {
	bin := buildFakeAudit(t)
	target := Target{Name: "service", Src: targetDir(t, "complete")}
	var progress bytes.Buffer
	_, err := Run(context.Background(), RunOptions{
		ManifestPath: filepath.Join(t.TempDir(), "targets.json"),
		Manifest:     &Manifest{Version: 1, Targets: []Target{target}}, ManifestData: []byte("fixture"),
		Formats: []string{"json"}, OutDir: t.TempDir(), Concurrency: 1, BinaryPath: bin, ToolVersion: "test",
		Progress: &progress, ProgressFormat: "json",
	})
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(progress.Bytes()), []byte("\n"))
	if len(lines) != 4 {
		t.Fatalf("progress events = %d, want three stages plus completion: %q", len(lines), progress.String())
	}
	var event struct {
		Kind    string `json:"kind"`
		Target  string `json:"target"`
		Status  Status `json:"status"`
		Current int    `json:"current"`
		Total   int    `json:"total"`
	}
	if err := json.Unmarshal(lines[len(lines)-1], &event); err != nil {
		t.Fatalf("progress is not JSON: %v: %q", err, progress.String())
	}
	if event.Kind != "fleet-progress" || event.Target != "service" || event.Status != StatusOK || event.Current != 1 || event.Total != 1 {
		t.Fatalf("progress event = %+v", event)
	}
}

func TestRunCompletionCallbackFailureIsOperational(t *testing.T) {
	bin := buildFakeAudit(t)
	target := Target{Name: "service", Src: targetDir(t, "complete")}
	_, err := Run(context.Background(), RunOptions{
		ManifestPath: filepath.Join(t.TempDir(), "targets.json"),
		Manifest:     &Manifest{Version: 1, Targets: []Target{target}}, ManifestData: []byte("fixture"),
		Formats: []string{"json"}, OutDir: t.TempDir(), Concurrency: 1, BinaryPath: bin, ToolVersion: "test",
		OnTargetComplete: func(Target, TargetResult, string) error { return fmt.Errorf("draft unavailable") },
	})
	if err == nil || !strings.Contains(err.Error(), "draft unavailable") {
		t.Fatalf("completion publication error = %v", err)
	}
}

func TestRunResumeRescansMissingSuggestionArtifact(t *testing.T) {
	bin := buildFakeAudit(t)
	target := Target{Name: "service", Src: targetDir(t, "complete")}
	outDir := t.TempDir()
	opts := RunOptions{
		ManifestPath: filepath.Join(t.TempDir(), "targets.json"),
		Manifest:     &Manifest{Version: 1, Targets: []Target{target}}, ManifestData: []byte("fixture"),
		Formats: []string{"json"}, OutDir: outDir, Concurrency: 1, BinaryPath: bin, ToolVersion: "test", SuggestAuth: true,
	}
	if _, err := Run(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(outDir, "targets", "service", "suggestions.json")); err != nil {
		t.Fatal(err)
	}
	opts.Resume = true
	agg, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if agg.Resume.Reused != 0 {
		t.Fatalf("resume reused target with missing suggestions: %+v", agg.Resume)
	}
	if _, err := os.Stat(filepath.Join(outDir, "targets", "service", "suggestions.json")); err != nil {
		t.Fatalf("rescan did not regenerate suggestions: %v", err)
	}
}
