package fleet

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

func targetFingerprint(target Target) string {
	// GitHub metadata is provenance, not source resolution. pushedAt and
	// visibility can drift between organization enumerations without changing
	// the manifest's name/URL/ref mapping; --update evaluates pushedAt
	// separately. Keeping it out also matches the checkpoint manifest hash.
	identity := struct {
		Name string     `json:"name"`
		Src  string     `json:"src,omitempty"`
		Git  *GitSource `json:"git,omitempty"`
	}{Name: target.Name, Src: target.Src, Git: target.Git}
	data, _ := json.Marshal(identity)
	return hashBytes(data)
}

func resolvedSourceFingerprint(target Target, repositoryFingerprint string) string {
	if target.Git != nil || repositoryFingerprint == "" {
		return targetFingerprint(target)
	}
	return hashBytes([]byte(targetFingerprint(target) + "\x00" + repositoryFingerprint))
}

// FingerprintBytes exposes the fleet artifact fingerprint algorithm for the
// CLI layer's canonical scope identity without duplicating hash details.
func FingerprintBytes(data []byte) string { return hashBytes(data) }

// TargetFingerprint is the stable manifest/discovery identity recorded with
// a target result and checked before cross-run reuse.
func TargetFingerprint(target Target) string { return targetFingerprint(target) }

func artifactForFile(root, relativePath string) (Artifact, error) {
	return artifactForTree("", root, relativePath)
}

func artifactForTree(tree, root, relativePath string) (Artifact, error) {
	path, err := safeRelativeArtifactPath(root, relativePath)
	if err != nil {
		return Artifact{}, err
	}
	data, err := ReadBoundedFile(path)
	if err != nil {
		return Artifact{}, err
	}
	return Artifact{Tree: tree, Path: filepath.ToSlash(relativePath), Bytes: int64(len(data)), SHA256: hashBytes(data)}, nil
}

// artifactForStagedTree hashes a file in a target's unpublished staging
// tree while recording the path it will have beneath the final output root.
// Validating all expected files before the directory transaction starts
// ensures a formatter bug or I/O error cannot replace the previous complete
// target and only then discover that the new evidence is unusable.
func artifactForStagedTree(tree, stagedRoot, stagedRelativePath, finalRelativePath string) (Artifact, error) {
	path, err := safeRelativeArtifactPath(stagedRoot, stagedRelativePath)
	if err != nil {
		return Artifact{}, err
	}
	data, err := ReadBoundedFile(path)
	if err != nil {
		return Artifact{}, err
	}
	artifact := Artifact{Tree: tree, Path: filepath.ToSlash(finalRelativePath), Bytes: int64(len(data)), SHA256: hashBytes(data)}
	if err := validateArtifactRecord(artifact); err != nil {
		return Artifact{}, err
	}
	return artifact, nil
}

// RecordArtifact returns the integrity record used by fleet checkpoints and
// aggregates for one file beneath a declared output tree. It is exported for
// the render command, which rewrites saved fleet artifacts without rescanning
// source and must therefore refresh their hashes before committing fleet.json.
func RecordArtifact(tree, root, relativePath string) (Artifact, error) {
	if tree != "" && tree != "raw" && tree != "html" {
		return Artifact{}, fmt.Errorf("unknown artifact tree %q", tree)
	}
	if tree == "raw" {
		tree = ""
	}
	return artifactForTree(tree, root, relativePath)
}

func verifyArtifact(rawRoot, htmlRoot string, artifact Artifact) error {
	root := rawRoot
	if artifact.Tree == "html" {
		root = htmlRoot
	}
	if root == "" {
		return fmt.Errorf("artifact %s requires missing %s output root", artifact.Path, artifact.Tree)
	}
	actual, err := artifactForTree(artifact.Tree, root, artifact.Path)
	if err != nil {
		return err
	}
	if artifact.Bytes != actual.Bytes || artifact.SHA256 == "" || artifact.SHA256 != actual.SHA256 {
		return fmt.Errorf("artifact %s failed integrity verification", artifact.Path)
	}
	return nil
}

func safeRelativeArtifactPath(root, relativePath string) (string, error) {
	if relativePath == "" || filepath.IsAbs(relativePath) {
		return "", fmt.Errorf("artifact path %q is not relative", relativePath)
	}
	clean := filepath.Clean(filepath.FromSlash(relativePath))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("artifact path %q escapes the output directory", relativePath)
	}
	path := filepath.Join(root, clean)
	rel, err := filepath.Rel(root, path)
	if err != nil || rel != clean {
		return "", fmt.Errorf("artifact path %q escapes the output directory", relativePath)
	}
	if err := rejectSymlinkComponents(path); err != nil {
		return "", err
	}
	return path, nil
}

// ResolveArtifactPath contains an untrusted fleet artifact path beneath root
// and rejects symlinked path components.
func ResolveArtifactPath(root, relativePath string) (string, error) {
	return safeRelativeArtifactPath(root, relativePath)
}

func rejectSymlinkComponents(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	volume := filepath.VolumeName(abs)
	current := volume + string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(abs, current), string(filepath.Separator)) {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s contains symlink component %s", path, current)
		}
	}
	return nil
}

func ensureDirectoryNoSymlink(path string, mode os.FileMode) error {
	if err := rejectSymlinkComponents(filepath.Dir(path)); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("%s exists and is not a plain directory", path)
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	return rejectSymlinkComponents(path)
}

func reusableTarget(rawRoot, htmlRoot string, result TargetResult, currentFingerprint string, formats []string, renderHTML bool) error {
	if !result.Complete {
		return fmt.Errorf("result is incomplete")
	}
	if result.SourceFingerprint == "" || result.SourceFingerprint != currentFingerprint {
		return fmt.Errorf("source identity changed")
	}
	switch result.Status {
	case StatusNotGoModule:
		if !result.Inventory.Complete {
			return fmt.Errorf("repository inventory is incomplete")
		}
		if len(result.Modules) != 0 || len(result.Artifacts) != 0 {
			return fmt.Errorf("not-go-module result unexpectedly contains module artifacts")
		}
		return nil
	case StatusOK:
		if err := validateReusableArtifactSet(result, formats, renderHTML); err != nil {
			return err
		}
	default:
		return fmt.Errorf("status %q is not reusable", result.Status)
	}
	for _, artifact := range result.Artifacts {
		if err := verifyArtifact(rawRoot, htmlRoot, artifact); err != nil {
			return err
		}
	}
	return nil
}

func validateReusableArtifactSet(result TargetResult, formats []string, renderHTML bool) error {
	if len(result.Modules) == 0 {
		return fmt.Errorf("result has no module inventory")
	}
	wantAll := make(map[string]Artifact)
	seenModules := make(map[string]bool, len(result.Modules))
	multiModule := len(result.Modules) > 1
	for _, module := range result.Modules {
		if err := ValidModuleID(module.ID); err != nil {
			return err
		}
		if seenModules[module.ID] {
			return fmt.Errorf("duplicate module id %q", module.ID)
		}
		seenModules[module.ID] = true
		if module.Status != StatusOK || !module.Complete {
			return fmt.Errorf("module %q is not complete", module.ID)
		}

		base := filepath.Join("targets", result.Name)
		if multiModule {
			base = filepath.Join(base, "modules", module.ID)
		}
		wantReport := filepath.ToSlash(filepath.Join(base, "routes.json"))
		if cleanArtifactPath(module.Report) != wantReport {
			return fmt.Errorf("module %q has non-canonical report path %q", module.ID, module.Report)
		}
		wantModule := make(map[string]bool)
		for _, name := range expectedRawArtifacts(formatsWithJSON(formats)) {
			key := artifactKey("", filepath.Join(base, name))
			wantModule[key] = true
		}
		if renderHTML && containsFormat(formats, "openapi") {
			wantHTML := filepath.ToSlash(filepath.Join(base, "api.html"))
			if cleanArtifactPath(module.APIHTML) != wantHTML {
				return fmt.Errorf("module %q has non-canonical HTML path %q", module.ID, module.APIHTML)
			}
			wantModule[artifactKey("html", wantHTML)] = true
		} else if module.APIHTML != "" {
			return fmt.Errorf("module %q has unexpected HTML path %q", module.ID, module.APIHTML)
		}

		actualModule, err := artifactMap(module.Artifacts)
		if err != nil {
			return fmt.Errorf("module %q: %w", module.ID, err)
		}
		if len(actualModule) != len(wantModule) {
			return fmt.Errorf("module %q artifact set is incomplete", module.ID)
		}
		for key := range wantModule {
			artifact, ok := actualModule[key]
			if !ok {
				return fmt.Errorf("module %q is missing artifact %q", module.ID, key)
			}
			wantAll[key] = artifact
		}
	}

	actualAll, err := artifactMap(result.Artifacts)
	if err != nil {
		return err
	}
	if len(actualAll) != len(wantAll) {
		return fmt.Errorf("target artifact set does not match its modules")
	}
	for key, want := range wantAll {
		got, ok := actualAll[key]
		if !ok || got != want {
			return fmt.Errorf("target artifact %q does not match its module record", key)
		}
	}
	return nil
}

func artifactMap(artifacts []Artifact) (map[string]Artifact, error) {
	result := make(map[string]Artifact, len(artifacts))
	for _, artifact := range artifacts {
		if err := validateArtifactRecord(artifact); err != nil {
			return nil, err
		}
		key := artifactKey(artifact.Tree, artifact.Path)
		if _, exists := result[key]; exists {
			return nil, fmt.Errorf("duplicate artifact %q", key)
		}
		result[key] = artifact
	}
	return result, nil
}

func artifactKey(tree, path string) string {
	return tree + "\x00" + cleanArtifactPath(path)
}

func cleanArtifactPath(path string) string {
	if path == "" {
		return ""
	}
	return filepath.ToSlash(filepath.Clean(filepath.FromSlash(path)))
}

func containsFormat(formats []string, want string) bool {
	for _, format := range formats {
		if format == want {
			return true
		}
	}
	return false
}

// ValidateReusableTarget verifies identity, completeness, and every recorded
// artifact before update/resume may skip a target.
func ValidateReusableTarget(rawRoot, htmlRoot string, result TargetResult, target Target, formats []string, renderHTML bool) error {
	if result.Name != target.Name {
		return fmt.Errorf("saved result name %q does not match target %q", result.Name, target.Name)
	}
	return reusableTarget(rawRoot, htmlRoot, result, targetFingerprint(target), formats, renderHTML)
}

func sourceCommit(ctx context.Context, root string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", "-C", root, "rev-parse", "--verify", "HEAD")
	cmd.Env = []string{
		"GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0",
		"HOME=" + os.TempDir(), "PATH=" + os.Getenv("PATH"),
	}
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	commit := strings.TrimSpace(string(output))
	if len(commit) != 40 && len(commit) != 64 {
		return "", fmt.Errorf("git returned invalid commit %q", commit)
	}
	if _, err := hex.DecodeString(commit); err != nil {
		return "", fmt.Errorf("git returned invalid commit %q", commit)
	}
	return commit, nil
}

// WriteFileAtomic writes a durable artifact without following an existing
// destination symlink. The randomized same-directory temporary file makes
// rename atomic and avoids predictable checkpoint temp names.
func WriteFileAtomic(path string, data []byte, mode os.FileMode) error {
	if err := rejectSymlinkComponents(filepath.Dir(path)); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("%s exists and is not a regular file", path)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".gin-recon-write-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	defer cleanup()
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil && !errors.Is(err, syscall.EINVAL) {
		return err
	}
	return nil
}

type directoryPublication struct {
	staged         string
	destination    string
	backup         string
	hadDestination bool
	published      bool
}

// publishDirectories publishes all of a target's output trees as one
// rollback unit. This matters when raw and HTML output live in sibling roots:
// publishing raw first and then failing to publish HTML must restore both old
// trees instead of leaving the last committed fleet.json pointing at a mix of
// scans. Filesystem crashes are detected later by artifact verification; this
// transaction additionally guarantees rollback for ordinary runtime errors.
func publishDirectories(publications ...directoryPublication) error {
	return publishDirectoriesWithRename(os.Rename, publications...)
}

type renameFunc func(oldPath, newPath string) error

func publishDirectoriesWithRename(rename renameFunc, publications ...directoryPublication) error {
	if len(publications) == 0 {
		return nil
	}
	seenStaged := make(map[string]bool, len(publications))
	seenDestinations := make(map[string]bool, len(publications))
	for i := range publications {
		publication := &publications[i]
		publication.staged = filepath.Clean(publication.staged)
		publication.destination = filepath.Clean(publication.destination)
		if seenStaged[publication.staged] || seenDestinations[publication.destination] {
			return fmt.Errorf("duplicate staged or destination directory in publication transaction")
		}
		seenStaged[publication.staged] = true
		seenDestinations[publication.destination] = true
		if filepath.Dir(publication.staged) != filepath.Dir(publication.destination) {
			return fmt.Errorf("staged output %s is not a sibling of destination %s", publication.staged, publication.destination)
		}
		if err := rejectSymlinkComponents(filepath.Dir(publication.destination)); err != nil {
			return err
		}
		stagedInfo, err := os.Lstat(publication.staged)
		if err != nil {
			return err
		}
		if stagedInfo.Mode()&os.ModeSymlink != 0 || !stagedInfo.IsDir() {
			return fmt.Errorf("staged output %s is not a plain directory", publication.staged)
		}
		info, err := os.Lstat(publication.destination)
		switch {
		case os.IsNotExist(err):
		case err != nil:
			return err
		case info.Mode()&os.ModeSymlink != 0 || !info.IsDir():
			return fmt.Errorf("%s exists and is not a plain directory", publication.destination)
		default:
			publication.hadDestination = true
		}
	}

	rollback := func(cause error) error {
		var rollbackErrors []error
		for i := len(publications) - 1; i >= 0; i-- {
			publication := &publications[i]
			if publication.published {
				if err := os.RemoveAll(publication.destination); err != nil {
					rollbackErrors = append(rollbackErrors, fmt.Errorf("removing newly published %s: %w", publication.destination, err))
				}
			}
			if publication.backup != "" {
				if err := rename(publication.backup, publication.destination); err != nil {
					rollbackErrors = append(rollbackErrors, fmt.Errorf("restoring %s: %w", publication.destination, err))
				}
			}
		}
		if len(rollbackErrors) == 0 {
			return cause
		}
		return errors.Join(append([]error{cause}, rollbackErrors...)...)
	}

	// Keep all backups until every new tree is in place and its parent has
	// been synced. That makes any failure before the commit point reversible.
	for i := range publications {
		publication := &publications[i]
		if !publication.hadDestination {
			continue
		}
		backup, err := os.MkdirTemp(filepath.Dir(publication.destination), ".gin-recon-backup-*")
		if err != nil {
			return rollback(err)
		}
		if err := os.Remove(backup); err != nil {
			_ = os.RemoveAll(backup)
			return rollback(err)
		}
		if err := rename(publication.destination, backup); err != nil {
			return rollback(err)
		}
		publication.backup = backup
	}
	for i := range publications {
		publication := &publications[i]
		if err := rename(publication.staged, publication.destination); err != nil {
			return rollback(err)
		}
		publication.published = true
	}
	seenParents := map[string]bool{}
	for i := range publications {
		parent := filepath.Dir(publications[i].destination)
		if seenParents[parent] {
			continue
		}
		seenParents[parent] = true
		if err := syncDirectory(parent); err != nil {
			return rollback(err)
		}
	}

	// Publication is committed. Backup cleanup cannot safely be made part of
	// the rollback decision once one old tree has already been removed, so it
	// is deliberately best-effort; a leftover hidden backup is stale storage,
	// never evidence referenced by the aggregate.
	for i := range publications {
		if publications[i].backup != "" {
			_ = os.RemoveAll(publications[i].backup)
		}
	}
	return nil
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil && !errors.Is(err, syscall.EINVAL) {
		return err
	}
	return nil
}

// keep sha256 imported here as an explicit assertion that Artifact.SHA256's
// algorithm cannot silently drift with hashBytes without this file changing.
var _ = sha256.Size
