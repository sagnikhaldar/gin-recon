package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/sagnikhaldar/gin-recon/internal/fleet"
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

	// fleet has no --src/--profile/etc. of its own (see parseFleet) — each
	// target supplies its own --src via the manifest, resolved later by
	// internal/fleet, not here. Its --format/--out rules mirror audit's own;
	// --fail-on is restricted to the one selector meaningful at fleet scope
	// today (docs/adr/0018-fleet-scanning.md).
	if opts.Command == CommandFleet {
		selected := 0
		for _, s := range []string{opts.TargetsPath, opts.Org, opts.Repo} {
			if s != "" {
				selected++
			}
		}
		if selected != 1 {
			return fmt.Errorf("exactly one of --targets, --org, or --repo is required")
		}
		if (opts.Org != "" || opts.Repo != "") && !opts.AllowRemoteTargets {
			return fmt.Errorf("--org/--repo require --allow-remote-targets: fetching a remote repository is itself a network call")
		}
		if opts.Org == "" {
			if opts.MaxRepos != 0 {
				return fmt.Errorf("--max-repos is --org only")
			}
			if opts.IncludeArchived || opts.IncludeForks {
				return fmt.Errorf("--include-archived/--include-forks are --org only")
			}
			if len(opts.RepoInclude) > 0 || len(opts.RepoExclude) > 0 {
				return fmt.Errorf("--repo-include/--repo-exclude are --org only")
			}
			if opts.Update {
				return fmt.Errorf("--update is --org only")
			}
		} else if opts.MaxRepos != 0 && (opts.MaxRepos < 1 || opts.MaxRepos > fleet.MaxMaxRepos) {
			return fmt.Errorf("--max-repos: must be between 1 and %d, got %d", fleet.MaxMaxRepos, opts.MaxRepos)
		}
		// --update, --resume, and --force name three different, mutually
		// exclusive answers to "output already exists here" — reusing
		// unchanged targets since the last complete run, continuing an
		// incomplete one from its checkpoint, and starting over — not
		// something meaningful to combine (docs/adr/0039-fleet-org-update.md,
		// matching a sibling tool's own identical rule for its own
		// --resume/--update/--overwrite trio, checked directly against its
		// source rather than assumed).
		if opts.Update && opts.Resume {
			return fmt.Errorf("--update and --resume cannot be used together: --resume continues an incomplete run from its checkpoint, --update starts a fresh run reusing what hasn't changed since the last complete one")
		}
		if opts.Update && opts.Force {
			return fmt.Errorf("--update and --force cannot be used together: --update already means \"proceed, reusing what hasn't changed\"")
		}
		if opts.Repo == "" && opts.Ref != "" {
			return fmt.Errorf("--ref is --repo only")
		}
		if opts.OutDir == "" {
			dir, err := defaultFleetOutDir(opts)
			if err != nil {
				return err
			}
			opts.OutDir = dir
		}
		if opts.Concurrency < 1 || opts.Concurrency > 8 {
			return fmt.Errorf("--concurrency: must be between 1 and 8, got %d", opts.Concurrency)
		}
		if opts.TargetConfigDir != "" {
			fi, err := os.Stat(opts.TargetConfigDir)
			if err != nil || !fi.IsDir() {
				return fmt.Errorf("--target-config-dir: %q must be an existing directory", opts.TargetConfigDir)
			}
		}
		// --format means for fleet what it already means for audit: which
		// formats each target's own audit subprocess produces
		// (docs/adr/0023-fleet-raw-rendered-split.md). fleet.json itself is
		// always JSON regardless of this list — there is no separate
		// concept of "the aggregate's own format" to select here.
		for _, f := range opts.Formats {
			switch f {
			case FormatJSON, FormatMD, FormatOpenAPI, FormatSARIF:
			default:
				return fmt.Errorf("--format: unsupported format %q", f)
			}
		}
		for _, selector := range opts.FailOn {
			switch selector {
			case "incomplete":
			case "new", "regression":
				if opts.Baseline == "" {
					return fmt.Errorf("--fail-on %s requires --baseline", selector)
				}
			default:
				return fmt.Errorf("--fail-on: fleet supports \"incomplete\", \"new\", and \"regression\", got %q", selector)
			}
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

// ParseFleetRepo splits --repo's value (docs/adr/0038-fleet-repo-shorthand.md)
// into the git clone URL a manifest's own "git.url" would use and a target
// name valid under fleet's existing `^[A-Za-z0-9._-]+$` name rule. Accepts
// either "owner/name" (expanded against github.com, the same default --org
// already assumes) or a full "https://" URL, used exactly as given.
func ParseFleetRepo(repo string) (url, name string) {
	if strings.HasPrefix(repo, "https://") {
		return repo, fleetRepoTargetName(strings.TrimSuffix(repo, ".git"))
	}
	return "https://github.com/" + repo + ".git", fleetRepoTargetName(repo)
}

// fleetRepoTargetName extracts the last path segment of a "owner/name"
// shorthand or a (`.git`-suffix-trimmed) URL — a GitHub repository name
// already satisfies fleet's own target-name rule, so no further sanitizing
// is needed here.
func fleetRepoTargetName(repo string) string {
	repo = strings.TrimSuffix(repo, "/")
	if i := strings.LastIndex(repo, "/"); i >= 0 {
		return repo[i+1:]
	}
	return repo
}

// defaultFleetOutDir computes fleet's --out when the caller didn't pass one,
// so `fleet --org <name> --allow-remote-targets` or `fleet --targets <path>`
// works with no --out at all — docs/adr/0028-gin-recon-default-output-directory.md,
// gin-recon's own directory name for a sibling tool's own
// `.express-recon/<org>` convention. --org gets `.gin-recon/<org>`
// (lowercased, matching the sibling convention and GitHub's own
// case-insensitive org names); --targets gets `.gin-recon/<manifest base
// name>`, the closest available scope identity for a hand-written manifest
// that has no organization name of its own. Passing --out explicitly always
// overrides this and is unaffected by anything here.
func defaultFleetOutDir(opts *Options) (string, error) {
	if fi, err := os.Lstat(".gin-recon"); err == nil && (fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir()) {
		return "", fmt.Errorf("--out: refusing to default into \".gin-recon\": it exists and is not a plain directory; pass --out explicitly")
	}
	if opts.Org != "" {
		return filepath.Join(".gin-recon", strings.ToLower(opts.Org)), nil
	}
	if opts.Repo != "" {
		return filepath.Join(".gin-recon", strings.ToLower(fleetRepoTargetName(opts.Repo))), nil
	}
	name := strings.TrimSuffix(filepath.Base(opts.TargetsPath), filepath.Ext(opts.TargetsPath))
	if name == "" {
		name = "targets"
	}
	return filepath.Join(".gin-recon", name), nil
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
