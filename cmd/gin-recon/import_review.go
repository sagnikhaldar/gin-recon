// import_review.go implements `import-review`: reads a suggest-auth JSON
// bundle and either a reviewer's own assessment file or, when --assessment
// is omitted, gin-recon's own analyzer.DraftAssessment
// (docs/adr/0042-static-analysis-drafts-assessments.md) — then validates
// the assessment against the bundle's exact fingerprints and writes
// analyzer.ImportReview's advisory suggestions document. When --out is
// given, it also writes a second, standalone, directly --config-usable
// file (reviewed-config.json) — the purely mechanical "make this a real
// config file" step, never merged into any existing --config this command
// has no evidence about. It never runs analysis of its own — see
// analyzer.ImportReview's own doc comment for the full ADR-0005 reasoning
// behind what stays a human/AI decision even when a draft covers the rest.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/sagnikhaldar/gin-recon/internal/analyzer"
	"github.com/sagnikhaldar/gin-recon/internal/cli"
	"github.com/sagnikhaldar/gin-recon/internal/config"
	"github.com/sagnikhaldar/gin-recon/internal/fleet"
	"github.com/sagnikhaldar/gin-recon/internal/report"
)

// reviewedConfigFilename is the standalone, directly --config-usable file
// import-review writes alongside its own advisory suggestions document.
const reviewedConfigFilename = "reviewed-config.json"

func runImportReview(opts *cli.Options, stdout, stderr io.Writer) int {
	bundleData, err := fleet.ReadBoundedFile(opts.BundlePath)
	if err != nil {
		fmt.Fprintf(stderr, "gin-recon: --bundle: %v\n", err)
		return cli.ExitOperationalError
	}
	var bundle analyzer.SuggestAuthResult
	if err := json.Unmarshal(bundleData, &bundle); err != nil {
		fmt.Fprintf(stderr, "gin-recon: --bundle: decoding: %v\n", err)
		return cli.ExitOperationalError
	}

	var assessment *analyzer.ReviewAssessment
	if opts.AssessmentPath == "" {
		// docs/adr/0042-static-analysis-drafts-assessments.md: no human/AI
		// assessment was given, so gin-recon drafts one itself from the
		// bundle's own combined static-analysis signals — a human or AI can
		// still review, extend, or override this by passing --assessment.
		assessment = analyzer.DraftAssessment(&bundle)
	} else {
		assessmentData, err := fleet.ReadBoundedFile(opts.AssessmentPath)
		if err != nil {
			fmt.Fprintf(stderr, "gin-recon: --assessment: %v\n", err)
			return cli.ExitOperationalError
		}
		assessment = &analyzer.ReviewAssessment{}
		if err := json.Unmarshal(assessmentData, assessment); err != nil {
			fmt.Fprintf(stderr, "gin-recon: --assessment: decoding: %v\n", err)
			return cli.ExitOperationalError
		}
	}

	result, err := analyzer.ImportReview(&bundle, assessment)
	if err != nil {
		fmt.Fprintf(stderr, "gin-recon: %v\n", err)
		return cli.ExitOperationalError
	}
	result.Tool = "gin-recon"
	result.ToolVersion = report.ToolVersion

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "gin-recon: %v\n", err)
		return cli.ExitOperationalError
	}
	data = append(data, '\n')

	if opts.OutDir == "" {
		if _, err := stdout.Write(data); err != nil {
			fmt.Fprintf(stderr, "gin-recon: writing report: %v\n", err)
			return cli.ExitOperationalError
		}
		return cli.ExitSuccess
	}

	// A standalone, directly --config-usable file alongside the advisory
	// suggestions document — the same authMiddleware/authWrappers entries,
	// just wrapped as a real, valid gin-recon config on its own (version 1,
	// nothing else). Never merged into any existing --config: a fresh file
	// under this exact, fixed name, gated by --force like anything else
	// import-review writes.
	reviewedConfig := &config.Config{
		Version:        1,
		AuthMiddleware: result.ReviewedConfigSuggestions.AuthMiddleware,
		AuthWrappers:   result.ReviewedConfigSuggestions.AuthWrappers,
	}
	configData, err := json.MarshalIndent(reviewedConfig, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "gin-recon: %v\n", err)
		return cli.ExitOperationalError
	}
	configData = append(configData, '\n')

	suggestionsPath := filepath.Join(opts.OutDir, "review-suggestions.json")
	configPath := filepath.Join(opts.OutDir, reviewedConfigFilename)
	if !opts.Force {
		for _, p := range []string{suggestionsPath, configPath} {
			if _, err := os.Stat(p); err == nil {
				fmt.Fprintf(stderr, "gin-recon: %s already exists; pass --force to overwrite\n", p)
				return cli.ExitOperationalError
			}
		}
	}
	if err := os.MkdirAll(opts.OutDir, 0o755); err != nil {
		fmt.Fprintf(stderr, "gin-recon: %v\n", err)
		return cli.ExitOperationalError
	}
	if err := os.WriteFile(suggestionsPath, data, 0o644); err != nil {
		fmt.Fprintf(stderr, "gin-recon: %v\n", err)
		return cli.ExitOperationalError
	}
	if err := os.WriteFile(configPath, configData, 0o644); err != nil {
		fmt.Fprintf(stderr, "gin-recon: %v\n", err)
		return cli.ExitOperationalError
	}
	return cli.ExitSuccess
}
