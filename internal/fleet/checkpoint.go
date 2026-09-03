package fleet

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
	ManifestHash string   `json:"manifestHash"`
	ConfigHash   string   `json:"configHash"`
	Formats      []string `json:"formats"`
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
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("fleet: reading --config for checkpoint identity: %w", err)
	}
	return hashBytes(data), nil
}

// loadCheckpoint reads an existing checkpoint for --resume. It returns a
// fresh, empty checkpoint (not an error) when none exists yet, so the first
// run of a --resume invocation behaves like an ordinary run.
func loadCheckpoint(outDir string, want identity) (*checkpoint, error) {
	path := filepath.Join(outDir, CheckpointFilename)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &checkpoint{Version: 1, Identity: want, Complete: map[string]TargetResult{}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("fleet: reading checkpoint: %w", err)
	}
	var cp checkpoint
	if err := json.Unmarshal(data, &cp); err != nil {
		return nil, fmt.Errorf("fleet: invalid checkpoint %s: %w", path, err)
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
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("fleet: writing checkpoint: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
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
