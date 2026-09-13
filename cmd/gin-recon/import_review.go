// import_review.go implements `import-review`: reads a suggest-auth JSON
// bundle and a reviewer's own assessment file, validates the assessment
// against the bundle's exact fingerprints, and writes analyzer.ImportReview's
// advisory suggestions document. It never runs analysis of its own and never
// writes to a real --config file — see analyzer.ImportReview's own doc
// comment for the full ADR-0005 reasoning.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/sagnikhaldar/gin-recon/internal/analyzer"
	"github.com/sagnikhaldar/gin-recon/internal/cli"
	"github.com/sagnikhaldar/gin-recon/internal/fleet"
	"github.com/sagnikhaldar/gin-recon/internal/report"
)

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

	assessmentData, err := fleet.ReadBoundedFile(opts.AssessmentPath)
	if err != nil {
		fmt.Fprintf(stderr, "gin-recon: --assessment: %v\n", err)
		return cli.ExitOperationalError
	}
	var assessment analyzer.ReviewAssessment
	if err := json.Unmarshal(assessmentData, &assessment); err != nil {
		fmt.Fprintf(stderr, "gin-recon: --assessment: decoding: %v\n", err)
		return cli.ExitOperationalError
	}

	result, err := analyzer.ImportReview(&bundle, &assessment)
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

	outPath := filepath.Join(opts.OutDir, "review-suggestions.json")
	if !opts.Force {
		if _, err := os.Stat(outPath); err == nil {
			fmt.Fprintf(stderr, "gin-recon: %s already exists; pass --force to overwrite\n", outPath)
			return cli.ExitOperationalError
		}
	}
	if err := os.MkdirAll(opts.OutDir, 0o755); err != nil {
		fmt.Fprintf(stderr, "gin-recon: %v\n", err)
		return cli.ExitOperationalError
	}
	if err := os.WriteFile(outPath, data, 0o644); err != nil {
		fmt.Fprintf(stderr, "gin-recon: %v\n", err)
		return cli.ExitOperationalError
	}
	return cli.ExitSuccess
}
