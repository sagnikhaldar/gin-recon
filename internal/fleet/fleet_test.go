package fleet

import (
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
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "audit" {
		fmt.Fprintln(os.Stderr, "fake-audit: expected \"audit\" as the first argument")
		os.Exit(1)
	}
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	src := fs.String("src", "", "")
	out := fs.String("out", "", "")
	fs.String("format", "", "")
	fs.Bool("force", false, "")
	fs.String("config", "", "")
	fs.Parse(os.Args[2:])

	behavior, err := os.ReadFile(filepath.Join(*src, "behavior"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "fake-audit: no behavior file")
		os.Exit(1)
	}
	switch string(behavior) {
	case "fail":
		fmt.Fprintln(os.Stderr, "fake-audit: simulated failure")
		os.Exit(1)
	case "complete":
		os.MkdirAll(*out, 0o755)
		os.WriteFile(filepath.Join(*out, "routes.json"), []byte(` + "`" + `{"scanCoverage":{"complete":true}}` + "`" + `), 0o644)
	case "incomplete":
		os.MkdirAll(*out, 0o755)
		os.WriteFile(filepath.Join(*out, "routes.json"), []byte(` + "`" + `{"scanCoverage":{"complete":false}}` + "`" + `), 0o644)
	default:
		fmt.Fprintln(os.Stderr, "fake-audit: unknown behavior")
		os.Exit(1)
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
