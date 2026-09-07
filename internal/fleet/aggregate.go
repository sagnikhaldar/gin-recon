package fleet

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

// ParseAggregate strictly decodes fleet.json. Current aggregates must carry
// the fleet 1.0 envelope; allowLegacy is reserved for offline render and
// baseline inspection of pre-versioned artifacts, never update reuse.
func ParseAggregate(data []byte, allowLegacy bool) (*Aggregate, error) {
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return nil, fmt.Errorf("invalid fleet aggregate: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var aggregate Aggregate
	if err := decoder.Decode(&aggregate); err != nil {
		return nil, fmt.Errorf("invalid fleet aggregate: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("invalid fleet aggregate: trailing content")
	}
	current := aggregate.SchemaVersion != "" || aggregate.Kind != ""
	if current {
		if aggregate.SchemaVersion != "1.0" || aggregate.Kind != "fleet" || aggregate.Tool != "gin-recon" || aggregate.ToolVersion == "" {
			return nil, fmt.Errorf("invalid fleet aggregate envelope")
		}
	} else if !allowLegacy {
		return nil, fmt.Errorf("unversioned fleet aggregate is not reusable")
	}
	if aggregate.Targets == nil {
		return nil, fmt.Errorf("invalid fleet aggregate: targets must be an array")
	}
	seen := make(map[string]bool, len(aggregate.Targets))
	for _, target := range aggregate.Targets {
		if err := ValidTargetName(target.Name); err != nil {
			return nil, err
		}
		if seen[target.Name] {
			return nil, fmt.Errorf("invalid fleet aggregate: duplicate target name %q", target.Name)
		}
		seen[target.Name] = true
		if err := validStatus(target.Status); err != nil {
			return nil, fmt.Errorf("target %q: %w", target.Name, err)
		}
		if current && target.Repository != nil {
			if !validGitRef(target.Repository.Ref) {
				return nil, fmt.Errorf("target %q: invalid repository ref %q", target.Name, target.Repository.Ref)
			}
			commit := target.Repository.ScannedCommit
			if commit != "" {
				if (len(commit) != 40 && len(commit) != 64) || strings.ToLower(commit) != commit {
					return nil, fmt.Errorf("target %q: invalid scanned commit %q", target.Name, commit)
				}
				if _, err := hex.DecodeString(commit); err != nil {
					return nil, fmt.Errorf("target %q: invalid scanned commit %q", target.Name, commit)
				}
			}
		}
		seenModules := make(map[string]bool, len(target.Modules))
		for _, module := range target.Modules {
			if err := ValidModuleID(module.ID); err != nil {
				return nil, fmt.Errorf("target %q: %w", target.Name, err)
			}
			if seenModules[module.ID] {
				return nil, fmt.Errorf("target %q: duplicate module id %q", target.Name, module.ID)
			}
			seenModules[module.ID] = true
			if err := validStatus(module.Status); err != nil {
				return nil, fmt.Errorf("target %q module %q: %w", target.Name, module.ID, err)
			}
			if current && module.Kind != ModuleGo && module.Kind != ModuleGinNoRoutes && module.Kind != ModuleGinApplication {
				return nil, fmt.Errorf("target %q module %q: invalid module kind %q", target.Name, module.ID, module.Kind)
			}
			for _, artifact := range module.Artifacts {
				if err := validateArtifactRecord(artifact); err != nil {
					return nil, fmt.Errorf("target %q module %q: %w", target.Name, module.ID, err)
				}
			}
		}
		for _, artifact := range target.Artifacts {
			if err := validateArtifactRecord(artifact); err != nil {
				return nil, fmt.Errorf("target %q: %w", target.Name, err)
			}
		}
	}
	return &aggregate, nil
}

func validStatus(status Status) error {
	switch status {
	case StatusOK, StatusNotGoModule, StatusInconclusive, StatusFailed:
		return nil
	default:
		return fmt.Errorf("invalid status %q", status)
	}
}

func validateArtifactRecord(artifact Artifact) error {
	if artifact.Tree != "" && artifact.Tree != "html" {
		return fmt.Errorf("artifact %q has invalid tree %q", artifact.Path, artifact.Tree)
	}
	if artifact.Path == "" || filepath.IsAbs(filepath.FromSlash(artifact.Path)) {
		return fmt.Errorf("artifact has invalid path %q", artifact.Path)
	}
	clean := filepath.Clean(filepath.FromSlash(artifact.Path))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return fmt.Errorf("artifact has invalid path %q", artifact.Path)
	}
	if strings.Contains(artifact.Path, `\`) || filepath.ToSlash(clean) != artifact.Path {
		return fmt.Errorf("artifact has non-canonical path %q", artifact.Path)
	}
	if artifact.Bytes < 0 || len(artifact.SHA256) != 64 {
		return fmt.Errorf("artifact %q has invalid integrity metadata", artifact.Path)
	}
	if _, err := hex.DecodeString(artifact.SHA256); err != nil {
		return fmt.Errorf("artifact %q has invalid SHA-256", artifact.Path)
	}
	return nil
}
