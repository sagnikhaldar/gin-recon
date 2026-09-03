// Package fleet implements gin-recon's fleet command
// (docs/adr/0018-fleet-scanning.md): orchestrating one audit subprocess per
// target named in a manifest, aggregating the results, and supporting
// checkpointed resume. It never calls internal/analyzer directly — every
// target's own report comes from re-invoking the same gin-recon binary
// every other caller already uses, so a fleet run's per-target results stay
// byte-identical to running audit on that target directly.
package fleet

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
)

// validTargetName matches docs/adr/0018-fleet-scanning.md's target name
// rule: it becomes a per-target output subdirectory name, so it is
// validated up front and rejected outright on a bad character rather than
// silently sanitized into something the manifest author didn't write.
var validTargetName = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// Target is one entry in a targets manifest.
type Target struct {
	Name string `json:"name"`
	Src  string `json:"src"`
}

// Manifest is the strict, data-only shape of a --targets file.
type Manifest struct {
	Version int      `json:"version"`
	Targets []Target `json:"targets"`
}

// LoadManifest reads and strictly validates a targets file, returning both
// the decoded Manifest and its raw bytes — the raw bytes are hashed into the
// checkpoint identity (see checkpoint.go) so a resumed run can detect a
// manifest that changed since the checkpoint was written.
func LoadManifest(path string) (*Manifest, []byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("fleet: reading --targets file: %w", err)
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, nil, fmt.Errorf("fleet: invalid targets file: %w", err)
	}
	if dec.More() {
		return nil, nil, fmt.Errorf("fleet: invalid targets file: trailing content after the top-level object")
	}
	if m.Version != 1 {
		return nil, nil, fmt.Errorf("fleet: targets file version must be 1, got %d", m.Version)
	}
	if len(m.Targets) == 0 {
		return nil, nil, fmt.Errorf("fleet: targets file has no targets")
	}

	seen := make(map[string]bool, len(m.Targets))
	for _, t := range m.Targets {
		if t.Name == "" || t.Name == "." || t.Name == ".." || !validTargetName.MatchString(t.Name) {
			return nil, nil, fmt.Errorf("fleet: target name %q must match %s", t.Name, validTargetName.String())
		}
		if seen[t.Name] {
			return nil, nil, fmt.Errorf("fleet: duplicate target name %q", t.Name)
		}
		seen[t.Name] = true
		if t.Src == "" {
			return nil, nil, fmt.Errorf("fleet: target %q: src is required", t.Name)
		}
	}
	return &m, data, nil
}
