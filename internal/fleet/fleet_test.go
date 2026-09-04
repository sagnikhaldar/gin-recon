package fleet

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
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
	if len(os.Args) < 2 || os.Args[1] != "audit" {
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
	if string(usedByHasOwn) != ownConfig {
		t.Errorf("has-own-config target's audit subprocess used --config %q, want its own file %q", usedByHasOwn, ownConfig)
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
	if _, err := os.Stat(filepath.Join(outDir, CheckpointFilename)); !os.IsNotExist(err) {
		t.Error("checkpoint should be removed once the fleet is complete")
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

	want := "[1/2] a: ok (5 routes)\n[2/2] b: failed\n"
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

	want := "[1/2] a: ok (resumed)\n[2/2] b: ok (0 routes)\n"
	if progress.String() != want {
		t.Errorf("progress output = %q, want %q", progress.String(), want)
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
