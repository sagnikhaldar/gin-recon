package cli

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/sagnikhaldar/gin-recon/internal/model"
)

var failOnPolicyPattern = regexp.MustCompile(`^policy:.+$`)

var validFailOnSelectors = map[string]bool{
	"public":              true,
	"unknown":             true,
	"attested-unresolved": true,
	"policy":              true,
	"new":                 true,
	"regression":          true,
	"incomplete":          true,
}

// Validate checks cross-field rules and resolves/contains filesystem paths.
// It is a separate pass from Parse because path resolution requires the
// filesystem (via filepath, not flag syntax) and is easiest to unit test
// against a temporary directory rather than mocked I/O inside the parser.
func Validate(opts *Options) error {
	// render has no --src/--profile/etc. of its own (see parseRender) — it
	// never runs analysis, so none of the scan-oriented checks below apply.
	// Its --format/--out rules are the same shape as inventory/audit's own,
	// except FormatSARIF's audit-only restriction: render's loaded document,
	// not the CLI command itself, decides whether "audit" applies, and that
	// document is not read until runRender, so that one check is deferred
	// there instead of here.
	if opts.Command == CommandRender {
		if opts.ReportPath == "" {
			return fmt.Errorf("--report is required")
		}
		for _, f := range opts.Formats {
			switch f {
			case FormatPretty, FormatJSON, FormatMD, FormatOpenAPI, FormatSARIF:
			default:
				return fmt.Errorf("--format: unsupported format %q", f)
			}
		}
		if len(opts.Formats) > 1 && opts.OutDir == "" {
			return fmt.Errorf("--out is required when more than one --format is selected")
		}
		return nil
	}

	switch opts.Profile {
	case model.ProfileSyntaxOnly, model.ProfileTyped:
	default:
		return fmt.Errorf("--profile: must be \"syntax-only\" or \"typed\", got %q", opts.Profile)
	}

	switch opts.ModuleMode {
	case "", model.ModuleReadonly, model.ModuleVendor:
	default:
		return fmt.Errorf("--module-mode: must be \"readonly\" or \"vendor\", got %q", opts.ModuleMode)
	}

	// --allow-downloads only has meaning for the typed profile: syntax-only
	// never invokes go/packages or the Go toolchain at all (see
	// docs/threat-model.md's "does not... resolve remote modules"), so there
	// is nothing for it to download. Accepting the flag silently would imply
	// a trust-boundary widening that never actually happens.
	if opts.Profile == model.ProfileSyntaxOnly && opts.AllowDownloads {
		return fmt.Errorf("--allow-downloads is not meaningful with --profile syntax-only, which never invokes the Go toolchain")
	}

	if opts.Timeout <= 0 {
		return fmt.Errorf("--timeout: must be positive, got %s", opts.Timeout)
	}

	srcAbs, err := filepath.Abs(opts.Src)
	if err != nil {
		return fmt.Errorf("--src: %w", err)
	}
	// EvalSymlinks resolves --src to a real path, per
	// docs/threat-model.md#trust-profiles ("explicitly resolved root").
	// Requiring --src to already exist here is deliberate: a scan root that
	// doesn't exist should fail immediately and clearly, not surface as a
	// confusing failure deep inside package loading.
	srcReal, err := filepath.EvalSymlinks(srcAbs)
	if err != nil {
		return fmt.Errorf("--src: %q could not be resolved: %w", opts.Src, err)
	}
	opts.Src = srcReal

	if opts.IgnoreFile != "none" {
		if err := requireUnderSrc(opts.Src, opts.IgnoreFile, "--ignore-file"); err != nil {
			return err
		}
	}

	if opts.Workspace != "off" {
		if err := requireUnderSrc(opts.Src, opts.Workspace, "--workspace"); err != nil {
			return err
		}
	}

	for _, f := range opts.Formats {
		switch f {
		case FormatPretty, FormatJSON, FormatMD, FormatOpenAPI, FormatSARIF:
		default:
			return fmt.Errorf("--format: unsupported format %q", f)
		}
		if f == FormatSARIF && opts.Command != CommandAudit {
			return fmt.Errorf("--format sarif is audit-only")
		}
	}
	if len(opts.Formats) > 1 && opts.OutDir == "" {
		return fmt.Errorf("--out is required when more than one --format is selected")
	}

	if opts.Baseline != "" && opts.Command != CommandAudit {
		return fmt.Errorf("--baseline is audit-only")
	}

	for _, selector := range opts.FailOn {
		if selector == "new" || selector == "regression" {
			if opts.Baseline == "" {
				return fmt.Errorf("--fail-on %s requires --baseline", selector)
			}
		}
		if validFailOnSelectors[selector] || failOnPolicyPattern.MatchString(selector) {
			continue
		}
		return fmt.Errorf("--fail-on: unsupported selector %q", selector)
	}

	switch opts.Command {
	case CommandSchema:
		switch opts.SchemaKind {
		case SchemaKindReport, SchemaKindConfig:
		default:
			return fmt.Errorf("schema --kind: must be \"report\" or \"config\", got %q", opts.SchemaKind)
		}
	}

	return nil
}

// requireUnderSrc enforces docs/cli-contract.md's "the path must remain under
// --src" rule for a single path field. src must already be absolute (Validate
// resolves opts.Src before calling this).
func requireUnderSrc(src, path, field string) error {
	abs := path
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(src, abs)
	}
	abs = filepath.Clean(abs)
	rel, err := filepath.Rel(src, abs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%s: %q must resolve beneath --src", field, path)
	}
	return nil
}
