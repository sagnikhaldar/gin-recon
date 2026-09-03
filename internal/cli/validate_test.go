package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

func mustParseAndValidate(t *testing.T, args ...string) *Options {
	t.Helper()
	opts := mustParse(t, args...)
	if err := Validate(opts); err != nil {
		t.Fatalf("Validate(%v) unexpected error: %v", args, err)
	}
	return opts
}

func expectValidateError(t *testing.T, wantSubstring string, args ...string) {
	t.Helper()
	opts := mustParse(t, args...)
	err := Validate(opts)
	if err == nil {
		t.Fatalf("Validate(%v) succeeded, want error containing %q", args, wantSubstring)
	}
	if !strings.Contains(err.Error(), wantSubstring) {
		t.Fatalf("Validate(%v) error = %q, want it to contain %q", args, err.Error(), wantSubstring)
	}
}

func TestValidateResolvesSrcToAbsoluteRealPath(t *testing.T) {
	dir := t.TempDir()
	opts := mustParseAndValidate(t, "inventory", "--src="+dir)
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	if opts.Src != resolved {
		t.Errorf("Src = %q, want %q", opts.Src, resolved)
	}
}

func TestValidateRejectsNonexistentSrc(t *testing.T) {
	expectValidateError(t, "could not be resolved", "inventory", "--src=/definitely/does/not/exist/xyz")
}

func TestValidateRejectsIgnoreFileEscapingSrc(t *testing.T) {
	dir := t.TempDir()
	expectValidateError(t, "must resolve beneath --src", "inventory", "--src="+dir, "--ignore-file=../../etc/passwd")
}

func TestValidateAllowsIgnoreFileNone(t *testing.T) {
	dir := t.TempDir()
	mustParseAndValidate(t, "inventory", "--src="+dir, "--ignore-file=none")
}

func TestValidateRejectsInvalidProfile(t *testing.T) {
	dir := t.TempDir()
	expectValidateError(t, "--profile", "inventory", "--src="+dir, "--profile=bogus")
}

func TestValidateRejectsMultipleFormatsWithoutOut(t *testing.T) {
	dir := t.TempDir()
	expectValidateError(t, "--out is required", "audit", "--src="+dir, "--format=json,md")
}

func TestValidateAcceptsMultipleFormatsWithOut(t *testing.T) {
	dir := t.TempDir()
	mustParseAndValidate(t, "audit", "--src="+dir, "--format=json,md", "--out=/tmp/out")
}

func TestValidateRejectsSARIFOnInventory(t *testing.T) {
	dir := t.TempDir()
	expectValidateError(t, "audit-only", "inventory", "--src="+dir, "--format=sarif")
}

// TestValidateRenderRequiresReport and the tests below confirm render's
// early branch in Validate — see its doc comment: render skips every
// scan-oriented check (--src, --profile, ...) entirely, applying only the
// --report/--format/--out rules the ADR actually specifies. Notably, unlike
// TestValidateRejectsSARIFOnInventory above, --format=sarif alone must NOT
// be rejected here — render's SARIF/audit-only check depends on the loaded
// --report document's own command, which Validate never reads.
func TestValidateRenderRequiresReport(t *testing.T) {
	expectValidateError(t, "--report is required", "render")
}

func TestValidateRenderAcceptsSARIFPendingLoadedReportCommand(t *testing.T) {
	mustParseAndValidate(t, "render", "--report=/tmp/routes.json", "--format=sarif")
}

func TestValidateRenderRejectsMultipleFormatsWithoutOut(t *testing.T) {
	expectValidateError(t, "--out is required", "render", "--report=/tmp/routes.json", "--format=json,md")
}

func TestValidateRenderRejectsUnsupportedFormat(t *testing.T) {
	expectValidateError(t, "unsupported format", "render", "--report=/tmp/routes.json", "--format=html")
}

// TestValidateRenderDoesNotRequireSrcToExist confirms render never resolves
// --src at all (it has none) — a nonexistent path anywhere on the system is
// irrelevant to it, unlike every other command (TestValidateRejectsNonexistentSrc).
func TestValidateRenderDoesNotRequireSrcToExist(t *testing.T) {
	mustParseAndValidate(t, "render", "--report=/tmp/routes.json")
}

func TestValidateRejectsNewOrRegressionWithoutBaseline(t *testing.T) {
	dir := t.TempDir()
	expectValidateError(t, "requires --baseline", "audit", "--src="+dir, "--fail-on=new")
	expectValidateError(t, "requires --baseline", "audit", "--src="+dir, "--fail-on=regression")
}

func TestValidateAcceptsNewWithBaseline(t *testing.T) {
	dir := t.TempDir()
	mustParseAndValidate(t, "audit", "--src="+dir, "--baseline=base.json", "--fail-on=new")
}

func TestValidateAcceptsPolicyFailOnSelector(t *testing.T) {
	dir := t.TempDir()
	mustParseAndValidate(t, "audit", "--src="+dir, "--fail-on=policy:admin-routes-need-role")
}

func TestValidateRejectsUnknownFailOnSelector(t *testing.T) {
	dir := t.TempDir()
	expectValidateError(t, "unsupported selector", "audit", "--src="+dir, "--fail-on=totally-bogus")
}

func TestValidateRejectsAllowDownloadsWithSyntaxOnly(t *testing.T) {
	dir := t.TempDir()
	expectValidateError(t, "not meaningful", "audit", "--src="+dir, "--profile=syntax-only", "--allow-downloads")
}

func TestValidateAcceptsAllowDownloadsWithTypedProfile(t *testing.T) {
	dir := t.TempDir()
	mustParseAndValidate(t, "audit", "--src="+dir, "--profile=typed", "--allow-downloads")
}

func TestValidateRejectsZeroTimeout(t *testing.T) {
	dir := t.TempDir()
	expectValidateError(t, "must be positive", "inventory", "--src="+dir, "--timeout=0s")
}

func TestValidateFleetRequiresTargetsOrOrg(t *testing.T) {
	dir := t.TempDir()
	expectValidateError(t, "exactly one of --targets or --org", "fleet", "--out="+dir)
}

func TestValidateFleetRejectsBothTargetsAndOrg(t *testing.T) {
	dir := t.TempDir()
	expectValidateError(t, "exactly one of --targets or --org", "fleet", "--out="+dir, "--targets=/tmp/targets.json", "--org=myorg", "--allow-remote-targets")
}

func TestValidateFleetRequiresOut(t *testing.T) {
	expectValidateError(t, "--out is required", "fleet", "--targets=/tmp/targets.json")
}

func TestValidateFleetOrgRequiresAllowRemoteTargets(t *testing.T) {
	dir := t.TempDir()
	expectValidateError(t, "--org requires --allow-remote-targets", "fleet", "--out="+dir, "--org=myorg")
}

func TestValidateFleetOrgAcceptsAllowRemoteTargets(t *testing.T) {
	dir := t.TempDir()
	mustParseAndValidate(t, "fleet", "--out="+dir, "--org=myorg", "--allow-remote-targets")
}

func TestValidateFleetRejectsMaxReposWithoutOrg(t *testing.T) {
	dir := t.TempDir()
	expectValidateError(t, "--max-repos is --org only", "fleet", "--out="+dir, "--targets=/tmp/targets.json", "--max-repos=50")
}

func TestValidateFleetRejectsIncludeArchivedWithoutOrg(t *testing.T) {
	dir := t.TempDir()
	expectValidateError(t, "--org only", "fleet", "--out="+dir, "--targets=/tmp/targets.json", "--include-archived")
}

func TestValidateFleetRejectsMaxReposOutOfRange(t *testing.T) {
	dir := t.TempDir()
	expectValidateError(t, "must be between 1 and", "fleet", "--out="+dir, "--org=myorg", "--allow-remote-targets", "--max-repos=100000")
}

func TestValidateFleetRejectsOutOfRangeConcurrency(t *testing.T) {
	dir := t.TempDir()
	expectValidateError(t, "must be between 1 and 8", "fleet", "--targets=/tmp/targets.json", "--out="+dir, "--concurrency=9")
}

func TestValidateFleetRejectsNonJSONFormat(t *testing.T) {
	dir := t.TempDir()
	expectValidateError(t, "only supports \"json\"", "fleet", "--targets=/tmp/targets.json", "--out="+dir, "--format=md")
}

func TestValidateFleetRejectsUnsupportedFailOnSelector(t *testing.T) {
	dir := t.TempDir()
	expectValidateError(t, "fleet supports", "fleet", "--targets=/tmp/targets.json", "--out="+dir, "--fail-on=public")
}

func TestValidateFleetAcceptsIncompleteFailOn(t *testing.T) {
	dir := t.TempDir()
	mustParseAndValidate(t, "fleet", "--targets=/tmp/targets.json", "--out="+dir, "--fail-on=incomplete")
}

func TestValidateFleetFailOnNewRequiresBaseline(t *testing.T) {
	dir := t.TempDir()
	expectValidateError(t, "--fail-on new requires --baseline", "fleet", "--targets=/tmp/targets.json", "--out="+dir, "--fail-on=new")
}

func TestValidateFleetFailOnRegressionRequiresBaseline(t *testing.T) {
	dir := t.TempDir()
	expectValidateError(t, "--fail-on regression requires --baseline", "fleet", "--targets=/tmp/targets.json", "--out="+dir, "--fail-on=regression")
}

func TestValidateFleetAcceptsNewAndRegressionWithBaseline(t *testing.T) {
	dir := t.TempDir()
	mustParseAndValidate(t, "fleet", "--targets=/tmp/targets.json", "--out="+dir, "--baseline=/tmp/prior/fleet.json", "--fail-on=new,regression")
}
