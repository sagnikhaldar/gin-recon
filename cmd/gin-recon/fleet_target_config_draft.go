// Fleet target-config drafts are machine-generated review queues. They live
// outside target-configs-snapshot and are never accepted as configuration.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sagnikhaldar/gin-recon/internal/analyzer"
	"github.com/sagnikhaldar/gin-recon/internal/fleet"
)

const targetConfigDraftDirName = "target-configs-draft"

type targetConfigDraftEntry struct {
	RouteCount   int      `json:"routeCount"`
	SampleRoutes []string `json:"sampleRoutes,omitempty"`
}

type targetConfigDraft struct {
	SchemaVersion         string                            `json:"schemaVersion"`
	Kind                  string                            `json:"kind"`
	Warning               string                            `json:"_warning"`
	Target                string                            `json:"target"`
	ReviewState           string                            `json:"reviewState"`
	ReviewedConfigApplied bool                              `json:"reviewedConfigApplied,omitempty"`
	Reuse                 string                            `json:"reuse,omitempty"`
	Issues                []string                          `json:"issues,omitempty"`
	Candidates            map[string]targetConfigDraftEntry `json:"candidates"`
}

const (
	targetConfigDraftKind          = "gin-recon-target-config-draft"
	targetConfigDraftWarning       = "UNREVIEWED — structural name-pattern hints only. Verify every symbol's implementation against source before copying confirmed entries into a reviewed --target-config-dir file."
	legacyTargetConfigDraftWarning = "UNREVIEWED — these are structural name-pattern hints, not confirmed authMiddleware. Check each symbol's actual implementation against real source before adding it to a real --target-config-dir file. See docs/reference.md#fleet-options (\"--target-config-dir\")."
)

type targetConfigDraftWriter struct{ outDir string }

// newTargetConfigDraftWriter creates the review directory before scanning.
// Existing files are retained; Write replaces only recognizable generated
// drafts, refusing to overwrite an unrelated or manually repurposed file.
func newTargetConfigDraftWriter(outDir string) (*targetConfigDraftWriter, error) {
	dir := filepath.Join(outDir, targetConfigDraftDirName)
	if err := fleet.WriteFileAtomic(filepath.Join(dir, ".gin-recon-generated"), []byte("target-config-drafts-v1\n"), 0o644); err != nil {
		return nil, fmt.Errorf("initializing %s: %w", targetConfigDraftDirName, err)
	}
	return &targetConfigDraftWriter{outDir: outDir}, nil
}

func (w *targetConfigDraftWriter) Write(_ fleet.Target, result fleet.TargetResult, reuse string) error {
	if err := fleet.ValidTargetName(result.Name); err != nil {
		return err
	}
	draft := targetConfigDraft{
		SchemaVersion: "1.0", Kind: targetConfigDraftKind,
		Warning: targetConfigDraftWarning, Target: result.Name, Reuse: reuse,
		Candidates: map[string]targetConfigDraftEntry{},
	}
	draft.ReviewedConfigApplied = result.TargetConfig || result.TargetConfigDir
	switch {
	case result.Status == fleet.StatusNotGoModule:
		draft.ReviewState = "not-applicable"
	case result.Status != fleet.StatusOK:
		draft.ReviewState = "scan-failed"
		if result.Error != "" {
			draft.Issues = append(draft.Issues, result.Error)
		}
	case !result.Complete:
		w.collectCandidates(&draft, result)
		draft.ReviewState = "scan-incomplete"
		draft.Issues = append(draft.Issues, "scan coverage is incomplete")
	case result.TargetConfig || result.TargetConfigDir:
		draft.ReviewState = "reviewed-config-applied"
	default:
		w.collectCandidates(&draft, result)
		if len(draft.Issues) > 0 {
			draft.ReviewState = "enrichment-failed"
		} else if len(draft.Candidates) == 0 {
			draft.ReviewState = "no-candidates"
		} else {
			draft.ReviewState = "candidates-to-review"
		}
	}

	data, err := json.MarshalIndent(draft, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding target config draft for %q: %w", result.Name, err)
	}
	dest := filepath.Join(w.outDir, targetConfigDraftDirName, result.Name+".json")
	if existing, err := fleet.ReadBoundedFile(dest); err == nil {
		var prior targetConfigDraft
		if json.Unmarshal(existing, &prior) != nil || (prior.Kind != targetConfigDraftKind && prior.Warning != targetConfigDraftWarning && prior.Warning != legacyTargetConfigDraftWarning) {
			return fmt.Errorf("refusing to overwrite unrecognized existing draft %s", dest)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("reading prior target config draft for %q: %w", result.Name, err)
	}
	if err := fleet.WriteFileAtomic(dest, data, 0o644); err != nil {
		return fmt.Errorf("writing target config draft for %q: %w", result.Name, err)
	}
	return nil
}

func (w *targetConfigDraftWriter) collectCandidates(draft *targetConfigDraft, result fleet.TargetResult) {
	for _, module := range result.Modules {
		if module.Status != fleet.StatusOK {
			draft.Issues = append(draft.Issues, fmt.Sprintf("module %s did not scan successfully", module.Path))
			continue
		}
		if module.SuggestionArtifact == nil {
			issue := module.SuggestionError
			if issue == "" {
				issue = "suggestion enrichment is unavailable"
			}
			draft.Issues = append(draft.Issues, fmt.Sprintf("module %s: %s", module.Path, issue))
			continue
		}
		data, err := fleet.ReadBoundedFile(filepath.Join(w.outDir, filepath.FromSlash(module.SuggestionArtifact.Path)))
		if err != nil {
			draft.Issues = append(draft.Issues, fmt.Sprintf("module %s: reading suggestion enrichment: %v", module.Path, err))
			continue
		}
		actual, err := fleet.RecordArtifact("", w.outDir, module.SuggestionArtifact.Path)
		if err != nil || actual.Bytes != module.SuggestionArtifact.Bytes || actual.SHA256 != module.SuggestionArtifact.SHA256 {
			draft.Issues = append(draft.Issues, fmt.Sprintf("module %s: suggestion enrichment failed integrity verification", module.Path))
			continue
		}
		var suggestions analyzer.SuggestAuthResult
		if err := json.Unmarshal(data, &suggestions); err != nil {
			draft.Issues = append(draft.Issues, fmt.Sprintf("module %s: decoding suggestion enrichment: %v", module.Path, err))
			continue
		}
		for _, candidate := range suggestions.Candidates {
			if !candidate.NameHint || candidate.KnownNonAuth {
				continue
			}
			entry := draft.Candidates[candidate.CanonicalSymbol]
			entry.RouteCount += candidate.RouteCount
			for _, sample := range candidate.SampleRoutes {
				if len(entry.SampleRoutes) >= fleetAuthSampleCap {
					break
				}
				entry.SampleRoutes = append(entry.SampleRoutes, sample)
			}
			draft.Candidates[candidate.CanonicalSymbol] = entry
		}
	}
}
