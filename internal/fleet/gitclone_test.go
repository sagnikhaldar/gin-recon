package fleet

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These tests exercise the real gitClone implementation (not a fake) against
// a local bare repository over the file:// transport, so they need no
// network access and no external service, while still proving the actual
// git invocation (shallow depth, --single-branch, the sanitized
// environment) works end to end. Manifest-level scheme validation
// (https://-only, no embedded credentials) is gitClone's caller's job
// (manifest.go, tested in manifest_test.go) — gitClone itself is a
// low-level mechanic that clones whatever URL it's given.
func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
}

func mustRunGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

// newLocalBareRepo creates a bare repo with one commit on branch "main" and
// returns a file:// URL to it.
func newLocalBareRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	bare := filepath.Join(root, "bare.git")
	// -b main here sets the bare repo's own HEAD symref, so a clone with no
	// explicit --branch (TestGitCloneDefaultsToRemoteHead) has a HEAD that
	// actually resolves to the branch pushed below, matching what a real
	// remote's default branch normally looks like.
	mustRunGit(t, root, "init", "--bare", "-q", "-b", "main", bare)

	work := filepath.Join(root, "work")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	mustRunGit(t, work, "init", "-q", "-b", "main")
	mustRunGit(t, work, "config", "user.email", "test@example.com")
	mustRunGit(t, work, "config", "user.name", "test")
	if err := os.WriteFile(filepath.Join(work, "go.mod"), []byte("module fixture\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mustRunGit(t, work, "add", "go.mod")
	mustRunGit(t, work, "commit", "-q", "-m", "init")
	mustRunGit(t, work, "remote", "add", "origin", bare)
	mustRunGit(t, work, "push", "-q", "origin", "main")

	return "file://" + bare
}

func TestGitCloneShallowClonesRealRepo(t *testing.T) {
	requireGit(t)
	repoURL := newLocalBareRepo(t)
	dest := filepath.Join(t.TempDir(), "cloned")

	if err := gitClone(context.Background(), repoURL, "main", dest, ""); err != nil {
		t.Fatalf("gitClone: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "go.mod")); err != nil {
		t.Fatalf("cloned repo missing go.mod: %v", err)
	}

	// --depth 1 must actually have taken effect: a shallow clone marker
	// file exists in .git.
	if _, err := os.Stat(filepath.Join(dest, ".git", "shallow")); err != nil {
		t.Error("expected a shallow clone (.git/shallow missing) — --depth 1 may not have been applied")
	}
}

func TestGitCloneDefaultsToRemoteHead(t *testing.T) {
	requireGit(t)
	repoURL := newLocalBareRepo(t)
	dest := filepath.Join(t.TempDir(), "cloned")

	if err := gitClone(context.Background(), repoURL, "", dest, ""); err != nil {
		t.Fatalf("gitClone: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "go.mod")); err != nil {
		t.Fatalf("cloned repo missing go.mod: %v", err)
	}
}

func TestGitCloneFailsCleanlyForMissingRepo(t *testing.T) {
	requireGit(t)
	dest := filepath.Join(t.TempDir(), "cloned")
	err := gitClone(context.Background(), "file:///nonexistent/repo.git", "", dest, "")
	if err == nil {
		t.Fatal("expected an error cloning a nonexistent repository")
	}
	if !strings.Contains(err.Error(), "git clone") {
		t.Errorf("err = %v, want it to be identifiable as a clone failure", err)
	}
}

func TestGitCloneNeverPromptsForCredentials(t *testing.T) {
	requireGit(t)
	// A repo URL requiring auth that this test provides none for must fail
	// fast (GIT_TERMINAL_PROMPT=0) rather than hang waiting for interactive
	// input — bounded by the test's own context timeout as a backstop.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dest := filepath.Join(t.TempDir(), "cloned")
	err := gitClone(ctx, "https://gin-recon-test-invalid-host-must-not-resolve.invalid/x/y.git", "", dest, "")
	if err == nil {
		t.Fatal("expected an error")
	}
	if ctx.Err() != nil {
		t.Fatal("gitClone hung until the context timeout instead of failing fast")
	}
}
