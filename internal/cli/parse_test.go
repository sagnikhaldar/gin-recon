package cli

import (
	"strings"
	"testing"
)

func mustParse(t *testing.T, args ...string) *Options {
	t.Helper()
	opts, err := Parse(args)
	if err != nil {
		t.Fatalf("Parse(%v) unexpected error: %v", args, err)
	}
	return opts
}

func expectParseError(t *testing.T, wantSubstring string, args ...string) {
	t.Helper()
	_, err := Parse(args)
	if err == nil {
		t.Fatalf("Parse(%v) succeeded, want error containing %q", args, wantSubstring)
	}
	if !strings.Contains(err.Error(), wantSubstring) {
		t.Fatalf("Parse(%v) error = %q, want it to contain %q", args, err.Error(), wantSubstring)
	}
}

func TestParseRejectsEmptyArgs(t *testing.T) {
	expectParseError(t, "missing command")
}

func TestParseRejectsUnknownCommand(t *testing.T) {
	expectParseError(t, "unknown command", "bogus")
}

func TestParseDefaultsForInventory(t *testing.T) {
	opts := mustParse(t, "inventory")
	if opts.Command != CommandInventory {
		t.Errorf("Command = %v, want inventory", opts.Command)
	}
	if len(opts.Formats) != 1 || opts.Formats[0] != FormatPretty {
		t.Errorf("Formats = %v, want [pretty]", opts.Formats)
	}
	if opts.IgnoreFile != DefaultIgnoreFile {
		t.Errorf("IgnoreFile = %q, want %q", opts.IgnoreFile, DefaultIgnoreFile)
	}
	if opts.Timeout != DefaultTimeout {
		t.Errorf("Timeout = %v, want %v", opts.Timeout, DefaultTimeout)
	}
}

// TestParseTracksExplicitlySetFlags is the regression for the precedence
// rule docs/configuration-contract.md requires ("Scalar CLI values override
// configuration"): a caller merging config file values on top of parsed
// Options needs to distinguish "the user actually passed --goos" from "GOOS
// just holds its runtime.GOOS default," which the resolved value alone
// cannot express.
func TestParseTracksExplicitlySetFlags(t *testing.T) {
	opts := mustParse(t, "inventory", "--goos=linux")
	if !opts.ExplicitFlags["goos"] {
		t.Error(`ExplicitFlags["goos"] = false, want true (user passed --goos)`)
	}
	if opts.ExplicitFlags["goarch"] {
		t.Error(`ExplicitFlags["goarch"] = true, want false (user did not pass --goarch)`)
	}
	if opts.ExplicitFlags["profile"] {
		t.Error(`ExplicitFlags["profile"] = true, want false (user did not pass --profile)`)
	}
}

func TestParseRejectsDuplicateScalarOption(t *testing.T) {
	expectParseError(t, "more than once", "inventory", "--src=a", "--src=b")
	expectParseError(t, "more than once", "audit", "--force", "--force")
}

func TestParseAccumulatesRepeatableInclude(t *testing.T) {
	opts := mustParse(t, "inventory", "--include=a/**", "--include=b/**,c/**")
	want := []string{"a/**", "b/**", "c/**"}
	if len(opts.Include) != len(want) {
		t.Fatalf("Include = %v, want %v", opts.Include, want)
	}
	for i := range want {
		if opts.Include[i] != want[i] {
			t.Errorf("Include[%d] = %q, want %q", i, opts.Include[i], want[i])
		}
	}
}

func TestParseFormatAcceptsRepeatedAndCommaSeparated(t *testing.T) {
	opts := mustParse(t, "audit", "--format=json,md", "--format=sarif", "--out=/tmp/out")
	want := []OutputFormat{FormatJSON, FormatMD, FormatSARIF}
	if len(opts.Formats) != len(want) {
		t.Fatalf("Formats = %v, want %v", opts.Formats, want)
	}
}

func TestParseRejectsInapplicableOptionForCommand(t *testing.T) {
	// --baseline and --fail-on are audit-only.
	expectParseError(t, "not defined", "inventory", "--baseline=x.json")
	expectParseError(t, "not defined", "suggest-auth", "--fail-on=public")
	// --format is inventory/audit-only — suggest-auth's output has no format
	// choice to make (always JSON). --out/--force are NOT in this category;
	// see TestParseSuggestAuthAcceptsOutAndForce.
	expectParseError(t, "not defined", "suggest-auth", "--format=json")
	expectParseError(t, "not defined", "schema", "--src=.")
	expectParseError(t, "not defined", "schema", "--out=/tmp/x")
}

// TestParseSuggestAuthAcceptsOutAndForce is the regression for a real
// contract/implementation mismatch: docs/cli-contract.md states "suggest-auth
// writes JSON to stdout unless --out is supplied", but parseScanCommand only
// ever registered --out/--force for inventory and audit, so --out silently
// failed with "flag provided but not defined" for suggest-auth despite the
// documented contract promising it works.
func TestParseSuggestAuthAcceptsOutAndForce(t *testing.T) {
	opts := mustParse(t, "suggest-auth", "--out=/tmp/out", "--force")
	if opts.OutDir != "/tmp/out" {
		t.Errorf("OutDir = %q, want /tmp/out", opts.OutDir)
	}
	if !opts.Force {
		t.Error("Force = false, want true")
	}
}

func TestParseRejectsInvalidTimeoutDuration(t *testing.T) {
	expectParseError(t, "invalid duration", "inventory", "--timeout=not-a-duration")
}

func TestParseRejectsUnexpectedPositionalArgument(t *testing.T) {
	expectParseError(t, "unexpected positional argument", "inventory", "extra-arg")
}

func TestParseSchemaDefaultsToReport(t *testing.T) {
	opts := mustParse(t, "schema")
	if opts.SchemaKind != SchemaKindReport {
		t.Errorf("SchemaKind = %q, want %q", opts.SchemaKind, SchemaKindReport)
	}
}

func TestParseSchemaAcceptsKindConfig(t *testing.T) {
	opts := mustParse(t, "schema", "--kind=config")
	if opts.SchemaKind != SchemaKindConfig {
		t.Errorf("SchemaKind = %q, want %q", opts.SchemaKind, SchemaKindConfig)
	}
}

// TestParseRenderAcceptsReportFormatOutConfig confirms render registers
// exactly the flags docs/adr/0016-render-command-decouples-formatting-from-analysis.md
// specifies (--report, --format, --out, --config, plus --force per the same
// output-option rules inventory/audit already follow) and none of
// inventory/audit's scan/analysis flags.
func TestParseRenderAcceptsReportFormatOutConfig(t *testing.T) {
	opts := mustParse(t, "render", "--report=/tmp/routes.json", "--format=json,openapi", "--out=/tmp/out", "--config=/tmp/gin-recon.json", "--force")
	if opts.Command != CommandRender {
		t.Errorf("Command = %v, want render", opts.Command)
	}
	if opts.ReportPath != "/tmp/routes.json" {
		t.Errorf("ReportPath = %q, want /tmp/routes.json", opts.ReportPath)
	}
	if opts.OutDir != "/tmp/out" {
		t.Errorf("OutDir = %q, want /tmp/out", opts.OutDir)
	}
	if opts.ConfigPath != "/tmp/gin-recon.json" {
		t.Errorf("ConfigPath = %q, want /tmp/gin-recon.json", opts.ConfigPath)
	}
	if !opts.Force {
		t.Error("Force = false, want true")
	}
	want := []OutputFormat{FormatJSON, FormatOpenAPI}
	if len(opts.Formats) != len(want) || opts.Formats[0] != want[0] || opts.Formats[1] != want[1] {
		t.Errorf("Formats = %v, want %v", opts.Formats, want)
	}
}

// TestParseRenderDefaultsToPrettyFormat mirrors TestParseDefaultsForInventory:
// render shares inventory/audit's "no --format means pretty" default.
func TestParseRenderDefaultsToPrettyFormat(t *testing.T) {
	opts := mustParse(t, "render", "--report=/tmp/routes.json")
	if len(opts.Formats) != 1 || opts.Formats[0] != FormatPretty {
		t.Errorf("Formats = %v, want [pretty]", opts.Formats)
	}
}

// TestParseRenderRejectsScanOnlyOption confirms render has no --src (or any
// other scan/analysis flag) — the ADR's "no source tree, no --src... of any
// kind" is enforced by construction: the flag is simply never registered.
func TestParseRenderRejectsScanOnlyOption(t *testing.T) {
	expectParseError(t, "flag provided but not defined", "render", "--report=/tmp/routes.json", "--src=/tmp")
}

func TestParseTagsSplitsOnComma(t *testing.T) {
	opts := mustParse(t, "inventory", "--tags=integration,slow")
	want := []string{"integration", "slow"}
	if len(opts.Tags) != len(want) || opts.Tags[0] != want[0] || opts.Tags[1] != want[1] {
		t.Errorf("Tags = %v, want %v", opts.Tags, want)
	}
}
