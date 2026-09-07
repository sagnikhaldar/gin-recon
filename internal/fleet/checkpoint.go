package fleet

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

// CheckpointFilename is the fixed name of a fleet run's resume state,
// written under --out. It is removed once a run's coverage is complete —
// docs/adr/0018-fleet-scanning.md: "resume state, not history."
const CheckpointFilename = "checkpoint.json"

// identity is the scope a checkpoint is valid for. --resume refuses to reuse
// a checkpoint whose identity doesn't match the current invocation, the same
// "refuse rather than guess" posture internal/compare.Compatible already
// applies to --baseline.
type identity struct {
	ManifestHash     string   `json:"manifestHash"`
	ConfigHash       string   `json:"configHash"`
	Formats          []string `json:"formats"`
	ToolVersion      string   `json:"toolVersion"`
	TargetConfigHash string   `json:"targetConfigHash,omitempty"`
	AllowDownloads   bool     `json:"allowDownloads"`
	UseTargetConfig  bool     `json:"useTargetConfig"`
	RenderHTML       bool     `json:"renderHtml"`
	RepoAttempts     int      `json:"repoAttempts"`
	RepoTimeout      string   `json:"repoTimeout"`
}

// checkpoint is the on-disk resume state: the scope it was produced under,
// plus every target that has already completed successfully. A target that
// failed is deliberately never recorded here — docs/adr/0018-fleet-scanning.md
// treats a failure as retryable, not terminal, so --resume tries it again
// rather than freezing a transient failure in place forever.
type checkpoint struct {
	Version  int                     `json:"version"`
	Identity identity                `json:"identity"`
	Complete map[string]TargetResult `json:"completed"`
}

func hashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func hashFile(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	data, err := ReadBoundedFile(path)
	if err != nil {
		return "", fmt.Errorf("fleet: reading --config for checkpoint identity: %w", err)
	}
	return hashBytes(data), nil
}

func hashConfigDirectory(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	var names []string
	err := filepath.WalkDir(path, func(current string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("fleet: --target-config-dir: %s is a symlink", current)
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("fleet: --target-config-dir: %s is not a regular file", current)
		}
		rel, err := filepath.Rel(path, current)
		if err != nil {
			return err
		}
		names = append(names, rel)
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Strings(names)
	var material bytes.Buffer
	for _, name := range names {
		data, err := ReadBoundedFile(filepath.Join(path, name))
		if err != nil {
			return "", err
		}
		material.WriteString(filepath.ToSlash(name))
		material.WriteByte(0)
		material.WriteString(hashBytes(data))
		material.WriteByte('\n')
	}
	return hashBytes(material.Bytes()), nil
}

// HashTargetConfigDirectory returns the deterministic content identity used
// by both checkpoint resume and cross-run update validation.
func HashTargetConfigDirectory(path string) (string, error) {
	return hashConfigDirectory(path)
}

// HashConfigFile is hashFile, exported so cmd/gin-recon can compute a
// --config path's identity hash the identical way Run itself does — needed
// by --update (docs/adr/0039-fleet-org-update.md) to compare this run's own
// --config against Aggregate.ConfigHash from the previous complete run,
// before Run itself has even been called (the preseed decision is made
// beforehand, in cmd/gin-recon).
func HashConfigFile(path string) (string, error) {
	return hashFile(path)
}

// loadCheckpoint reads an existing checkpoint for --resume. It returns a
// fresh, empty checkpoint (not an error) when none exists yet, so the first
// run of a --resume invocation behaves like an ordinary run.
func loadCheckpoint(outDir string, want identity) (*checkpoint, error) {
	path := filepath.Join(outDir, CheckpointFilename)
	data, err := ReadBoundedFile(path)
	if os.IsNotExist(err) {
		return &checkpoint{Version: 2, Identity: want, Complete: map[string]TargetResult{}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("fleet: reading checkpoint: %w", err)
	}
	var cp checkpoint
	if err := json.Unmarshal(data, &cp); err != nil {
		return nil, fmt.Errorf("fleet: invalid checkpoint %s: %w", path, err)
	}
	if cp.Version != 2 {
		return nil, fmt.Errorf("fleet: --resume: checkpoint version %d is not compatible with version 2; start a fresh run", cp.Version)
	}
	if cp.Identity.ToolVersion != want.ToolVersion {
		return nil, fmt.Errorf("fleet: --resume: gin-recon version has changed since this checkpoint was written; refusing to reuse mismatched state")
	}
	if cp.Identity.ManifestHash != want.ManifestHash {
		return nil, fmt.Errorf("fleet: --resume: the targets file has changed since this checkpoint was written; refusing to reuse mismatched state")
	}
	if cp.Identity.ConfigHash != want.ConfigHash {
		return nil, fmt.Errorf("fleet: --resume: --config has changed since this checkpoint was written; refusing to reuse mismatched state")
	}
	if !stringsEqual(cp.Identity.Formats, want.Formats) {
		return nil, fmt.Errorf("fleet: --resume: --format has changed since this checkpoint was written; refusing to reuse mismatched state")
	}
	if cp.Identity.TargetConfigHash != want.TargetConfigHash || cp.Identity.UseTargetConfig != want.UseTargetConfig {
		return nil, fmt.Errorf("fleet: --resume: target configuration has changed since this checkpoint was written; refusing to reuse mismatched state")
	}
	if cp.Identity.AllowDownloads != want.AllowDownloads || cp.Identity.RenderHTML != want.RenderHTML {
		return nil, fmt.Errorf("fleet: --resume: scan options have changed since this checkpoint was written; refusing to reuse mismatched state")
	}
	if cp.Identity.RepoAttempts != want.RepoAttempts || cp.Identity.RepoTimeout != want.RepoTimeout {
		return nil, fmt.Errorf("fleet: --resume: repository retry/timeout options have changed since this checkpoint was written; refusing to reuse mismatched state")
	}
	if cp.Complete == nil {
		cp.Complete = map[string]TargetResult{}
	}
	return &cp, nil
}

// saveCheckpoint writes atomically (temp file + rename) so a crash mid-run
// never leaves a partially-written, corrupt checkpoint behind.
func saveCheckpoint(outDir string, cp *checkpoint) error {
	path := filepath.Join(outDir, CheckpointFilename)
	data, err := json.MarshalIndent(cp, "", "  ")
	if err != nil {
		return fmt.Errorf("fleet: encoding checkpoint: %w", err)
	}
	if err := WriteFileAtomic(path, data, 0o600); err != nil {
		return fmt.Errorf("fleet: writing checkpoint: %w", err)
	}
	return nil
}

func removeCheckpoint(outDir string) error {
	err := os.Remove(filepath.Join(outDir, CheckpointFilename))
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("fleet: removing checkpoint: %w", err)
	}
	return nil
}

// RemoveCheckpoint is called by the CLI only after fleet.json and any delta
// have been atomically and durably committed. Run intentionally leaves the
// resume journal in place until that outer transaction finishes.
func RemoveCheckpoint(outDir string) error {
	return removeCheckpoint(outDir)
}

func stringsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
