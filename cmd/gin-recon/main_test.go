package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/sagnikhaldar/gin-recon/internal/cli"
	"github.com/sagnikhaldar/gin-recon/internal/fleet"
	"github.com/sagnikhaldar/gin-recon/internal/model"
	"github.com/sagnikhaldar/gin-recon/internal/report"
)

// TestMain forces isInteractiveTerminalForTests false for the entire test
// binary, regardless of how `go test` was actually invoked — running it
// directly in an interactive shell (not just CI) leaves the real os.Stdin
// check genuinely true, and any fleet test hitting the already-exists
// conflict path without --force/--resume would otherwise block forever on
// a prompt nothing will ever answer
// (docs/adr/0034-fleet-interactive-conflict-prompt.md). A test that
// specifically wants the interactive path overrides this back to a
// true-returning func, paired with fleetStdinForTests, only for its own
// duration.
func TestMain(m *testing.M) {
	isInteractiveTerminalForTests = func() bool { return false }
	os.Exit(m.Run())
}

func TestRunSchemaReportSucceeds(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"schema"}, &stdout, &stderr)
	if code != cli.ExitSuccess {
		t.Fatalf("exit code = %d, want %d; stderr: %s", code, cli.ExitSuccess, stderr.String())
	}
	var doc map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
	}
	if doc["title"] != "Gin Recon Report" {
		t.Errorf("title = %v, want %q", doc["title"], "Gin Recon Report")
	}
}

func TestRunSchemaConfigSucceeds(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"schema", "--kind", "config"}, &stdout, &stderr)
	if code != cli.ExitSuccess {
		t.Fatalf("exit code = %d, want %d; stderr: %s", code, cli.ExitSuccess, stderr.String())
	}
	var doc map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("stdout is not valid JSON: %v", err)
	}
	if doc["title"] != "Gin Recon Configuration" {
		t.Errorf("title = %v, want %q", doc["title"], "Gin Recon Configuration")
	}
}

func TestRunFleetSchemasSucceed(t *testing.T) {
	for _, kind := range []string{"fleet", "fleet-delta"} {
		var stdout, stderr bytes.Buffer
		code := run([]string{"schema", "--kind", kind}, &stdout, &stderr)
		if code != cli.ExitSuccess {
			t.Fatalf("schema %s exit code = %d; stderr: %s", kind, code, stderr.String())
		}
		var doc map[string]any
		if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
			t.Fatalf("schema %s is not valid JSON: %v", kind, err)
		}
		if doc["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
			t.Errorf("schema %s has unexpected dialect %v", kind, doc["$schema"])
		}
	}
}

func TestRunSuggestAuthSucceedsAndRanksCandidates(t *testing.T) {
	dir := fixtureDir(t, "middleware-order")

	var stdout, stderr bytes.Buffer
	code := run([]string{"suggest-auth", "--src", dir, "--allow-downloads"}, &stdout, &stderr)
	if code != cli.ExitSuccess {
		t.Fatalf("exit code = %d, want %d; stderr: %s", code, cli.ExitSuccess, stderr.String())
	}
	var result map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
	}
	candidates, ok := result["candidates"].([]any)
	if !ok || len(candidates) < 2 {
		t.Fatalf("expected at least 2 candidates, got %v", result["candidates"])
	}
	// RequireAuth and RequireAdmin (both name-hinted) must rank ahead of
	// RequestID (no auth-related name hint) — see rankLess's doc comment for
	// why RequireAdmin (applied to 1 route) sorts ahead of RequireAuth
	// (applied to 2): more selective coverage ranks as more interesting.
	first := candidates[0].(map[string]any)
	second := candidates[1].(map[string]any)
	for _, c := range []map[string]any{first, second} {
		symbol := c["canonicalSymbol"].(string)
		if !strings.Contains(symbol, "RequireAuth") && !strings.Contains(symbol, "RequireAdmin") {
			t.Errorf("top-2 candidates = [%v, %v], want RequireAuth/RequireAdmin ranked ahead of everything else", first, second)
		}
	}
}

// TestRunSuggestAuthWritesToOutDir is the regression for a real
// contract/implementation mismatch found while wiring this command up:
// docs/reference.md says "suggest-auth writes JSON to stdout unless --out
// is supplied", but --out was never registered on suggest-auth's FlagSet at
// all (see internal/cli/parse_test.go's TestParseSuggestAuthAcceptsOutAndForce
// for the parser-level regression).
func TestRunSuggestAuthWritesToOutDir(t *testing.T) {
	dir := fixtureDir(t, "middleware-order")
	outDir := t.TempDir()

	var stdout, stderr bytes.Buffer
	code := run([]string{"suggest-auth", "--src", dir, "--out", outDir, "--allow-downloads"}, &stdout, &stderr)
	if code != cli.ExitSuccess {
		t.Fatalf("exit code = %d, want %d; stderr: %s", code, cli.ExitSuccess, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty when --out is supplied", stdout.String())
	}
	data, err := os.ReadFile(filepath.Join(outDir, "suggestions.json"))
	if err != nil {
		t.Fatalf("suggestions.json was not written: %v", err)
	}
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("suggestions.json is not valid JSON: %v", err)
	}
}

// fixtureDir resolves a testdata/fixtures/<name> directory regardless of the
// test binary's working directory, mirroring internal/analyzer's own
// fixtureDir helper (unexported to that package, so duplicated here rather
// than shared across a package boundary for one helper).
func fixtureDir(t *testing.T, name string) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not determine repo-relative fixture path")
	}
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")
	return filepath.Join(repoRoot, "testdata", "fixtures", name)
}

// TestRunInventoryAndAuditFailFatallyOnAnEmptyDirectory is the regression
// test for a real gap: golang.org/x/tools/go/packages frequently reports "no
// go.mod here" not through packages.Load's own error return but as a single
// synthetic package whose Errors describe the failure. Before this was
// fixed, that meant --src pointed at a directory with no Go module at all
// silently produced an empty, exit-0 "successful" report instead of the
// exit 1 docs/reference.md requires for "Fatal inability to load the
// requested root."
func TestRunInventoryAndAuditFailFatallyOnAnEmptyDirectory(t *testing.T) {
	dir := t.TempDir() // no go.mod, no Go files
	for _, cmd := range []string{"inventory", "audit", "suggest-auth"} {
		var stdout, stderr bytes.Buffer
		code := run([]string{cmd, "--src", dir, "--allow-downloads"}, &stdout, &stderr)
		if code != cli.ExitOperationalError {
			t.Errorf("%s: exit code = %d, want %d", cmd, code, cli.ExitOperationalError)
		}
		if stdout.Len() != 0 {
			t.Errorf("%s: stdout = %q, want empty — a fatal load failure must never emit a report", cmd, stdout.String())
		}
		if stderr.Len() == 0 {
			t.Errorf("%s: stderr is empty, want an explanation of the load failure", cmd)
		}
	}
}

func TestRunUnknownCommandFails(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"bogus"}, &stdout, &stderr)
	if code != cli.ExitOperationalError {
		t.Errorf("exit code = %d, want %d", code, cli.ExitOperationalError)
	}
}

func TestRunHelpSucceeds(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"--help"}, &stdout, &stderr)
	if code != cli.ExitSuccess {
		t.Errorf("exit code = %d, want %d", code, cli.ExitSuccess)
	}
	if !strings.Contains(stdout.String(), "gin-recon") {
		t.Errorf("stdout = %q, want usage text", stdout.String())
	}
}

func TestRunSchemaIgnoresScanOnlyOptions(t *testing.T) {
	// schema does not register --src at all (docs/reference.md: "accepts
	// no scan/config/output options"), so passing one must fail the same way
	// any unknown flag would, not be silently ignored.
	var stdout, stderr bytes.Buffer
	code := run([]string{"schema", "--src", "."}, &stdout, &stderr)
	if code != cli.ExitOperationalError {
		t.Errorf("exit code = %d, want %d", code, cli.ExitOperationalError)
	}
}

// TestRunInventorySyntaxOnlyProfileNeverInvokesToolchain proves --profile
// syntax-only end-to-end through the CLI: no --allow-downloads is passed at
// all (LoadSyntax never invokes go/packages or the Go toolchain, so there is
// nothing for it to download), yet the fixture's routes and middleware order
// are still recovered.
func TestRunInventorySyntaxOnlyProfileNeverInvokesToolchain(t *testing.T) {
	dir := fixtureDir(t, "middleware-order")

	var stdout, stderr bytes.Buffer
	code := run([]string{"inventory", "--src", dir, "--format", "json", "--profile", "syntax-only"}, &stdout, &stderr)
	if code != cli.ExitSuccess {
		t.Fatalf("exit code = %d, want %d; stderr: %s", code, cli.ExitSuccess, stderr.String())
	}
	var doc map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
	}
	if doc["analysisProfile"] != "syntax-only" {
		t.Errorf("analysisProfile = %v, want syntax-only", doc["analysisProfile"])
	}
	foundAdminUsers := false
	for _, r := range doc["routes"].([]any) {
		route := r.(map[string]any)
		if route["normalizedPath"] == "/admin/users" && route["method"] == "GET" {
			foundAdminUsers = true
			mw := route["middleware"].([]any)
			if len(mw) != 2 {
				t.Errorf("middleware = %v, want 2 entries", mw)
			}
		}
	}
	if !foundAdminUsers {
		t.Errorf("expected GET /admin/users among routes: %v", doc["routes"])
	}
}

// TestRunAuditSyntaxOnlyNeverClassifiesProven proves the security invariant
// behind syntax-only's documented "cannot emit proven": even with the exact
// same authMiddleware config that makes typed mode classify a route proven
// (the auth-wrappers fixture's RequireAuth), syntax-only can never resolve a
// canonical symbol at all, so classification must fall back to public
// rather than silently degrading to a false proven or a false unknown.
func TestRunAuditSyntaxOnlyNeverClassifiesProven(t *testing.T) {
	dir := fixtureDir(t, "auth-wrappers")
	cfgPath := filepath.Join(t.TempDir(), "gin-recon.json")
	if err := os.WriteFile(cfgPath, []byte(authWrappersConfigured), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"audit", "--src", dir, "--format", "json", "--config", cfgPath, "--profile", "syntax-only"}, &stdout, &stderr)
	if code != cli.ExitSuccess {
		t.Fatalf("exit code = %d, want %d; stderr: %s", code, cli.ExitSuccess, stderr.String())
	}
	var doc map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
	}
	summary := doc["summary"].(map[string]any)
	if summary["provenByConfirmedShape"] != float64(0) || summary["provenByAttestedUnresolved"] != float64(0) {
		t.Errorf("summary = %v, want zero proven routes under syntax-only even with a matching authMiddleware config", summary)
	}
	if summary["totalRoutes"] == float64(0) {
		t.Errorf("summary.totalRoutes = 0, want the fixture's routes to still be discovered")
	}

	// Regression: every syntax-only route has a nil canonical symbol, so
	// without explicit suppression every authMiddleware entry above would
	// spuriously report stale-auth-config even though RequireAuth etc. are
	// genuinely present and used in the fixture — see
	// internal/classify.TestStaleAuthConfigFindingSuppressedForSyntaxOnly.
	for _, f := range doc["findings"].([]any) {
		if f.(map[string]any)["ruleId"] == "stale-auth-config" {
			t.Errorf("unexpected stale-auth-config finding under syntax-only: %v", f)
		}
	}
	foundUnverifiableDiagnostic := false
	for _, d := range doc["diagnostics"].([]any) {
		if d.(map[string]any)["code"] == "gin-syntax-auth-config-unverifiable" {
			foundUnverifiableDiagnostic = true
		}
	}
	if !foundUnverifiableDiagnostic {
		t.Errorf("expected a gin-syntax-auth-config-unverifiable diagnostic explaining why stale-auth-config was skipped, got: %v", doc["diagnostics"])
	}
}

// TestRunAuditSyntaxOnlyRejectsAllowDownloads confirms syntax-only does not
// silently accept an option that only makes sense for typed loading —
// cli.Validate already enforces this; this is the CLI-level regression that
// keeps it enforced.
func TestRunAuditSyntaxOnlyRejectsAllowDownloads(t *testing.T) {
	dir := fixtureDir(t, "middleware-order")
	var stdout, stderr bytes.Buffer
	code := run([]string{"audit", "--src", dir, "--profile", "syntax-only", "--allow-downloads"}, &stdout, &stderr)
	if code != cli.ExitOperationalError {
		t.Fatalf("exit code = %d, want %d; stderr: %s", code, cli.ExitOperationalError, stderr.String())
	}
}

func TestRunInventoryPrettyFormatSucceeds(t *testing.T) {
	dir := t.TempDir() // no Gin usage — a valid, empty target
	writeMinimalGoModule(t, dir)

	var stdout, stderr bytes.Buffer
	code := run([]string{"inventory", "--src", dir, "--format", "pretty", "--allow-downloads"}, &stdout, &stderr)
	if code != cli.ExitSuccess {
		t.Fatalf("exit code = %d, want %d; stderr: %s", code, cli.ExitSuccess, stderr.String())
	}
	if !strings.Contains(stdout.String(), "gin-recon inventory") {
		t.Errorf("stdout = %q, want pretty-formatted output", stdout.String())
	}
	// Pretty output is not JSON; confirm it genuinely isn't.
	var probe map[string]any
	if json.Unmarshal(stdout.Bytes(), &probe) == nil {
		t.Error("pretty output parsed as JSON — --format pretty is not actually producing pretty text")
	}
}

func TestRunInventoryOpenAPIFormatSucceeds(t *testing.T) {
	dir := t.TempDir() // no Gin usage — a valid, empty target
	writeMinimalGoModule(t, dir)

	var stdout, stderr bytes.Buffer
	code := run([]string{"inventory", "--src", dir, "--format", "openapi", "--allow-downloads"}, &stdout, &stderr)
	if code != cli.ExitSuccess {
		t.Fatalf("exit code = %d, want %d; stderr: %s", code, cli.ExitSuccess, stderr.String())
	}
	var doc map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
	}
	if doc["openapi"] != "3.1.0" {
		t.Errorf("openapi = %v, want 3.1.0", doc["openapi"])
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty — an empty route set produces no format diagnostics", stderr.String())
	}
}

func TestRunInventoryMarkdownFormatSucceeds(t *testing.T) {
	dir := t.TempDir() // no Gin usage — a valid, empty target
	writeMinimalGoModule(t, dir)

	var stdout, stderr bytes.Buffer
	code := run([]string{"inventory", "--src", dir, "--format", "md", "--allow-downloads"}, &stdout, &stderr)
	if code != cli.ExitSuccess {
		t.Fatalf("exit code = %d, want %d; stderr: %s", code, cli.ExitSuccess, stderr.String())
	}
	if !strings.Contains(stdout.String(), "# gin-recon inventory") {
		t.Errorf("stdout = %q, want Markdown-formatted output", stdout.String())
	}
	var probe map[string]any
	if json.Unmarshal(stdout.Bytes(), &probe) == nil {
		t.Error("markdown output parsed as JSON — --format md is not actually producing markdown")
	}
}

func TestRunAuditSARIFFormatSucceeds(t *testing.T) {
	dir := t.TempDir() // no Gin usage — a valid, empty target
	writeMinimalGoModule(t, dir)

	var stdout, stderr bytes.Buffer
	code := run([]string{"audit", "--src", dir, "--format", "sarif", "--allow-downloads"}, &stdout, &stderr)
	if code != cli.ExitSuccess {
		t.Fatalf("exit code = %d, want %d; stderr: %s", code, cli.ExitSuccess, stderr.String())
	}
	var doc map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
	}
	if doc["version"] != "2.1.0" {
		t.Errorf("version = %v, want 2.1.0", doc["version"])
	}
}

// TestRunInventorySARIFFormatIsRejected is the regression for
// docs/reference.md's "SARIF is audit-only" — cli.Validate must still
// reject it for inventory now that format.SARIF actually exists, so
// implementing the formatter did not accidentally widen its command scope.
func TestRunInventorySARIFFormatIsRejected(t *testing.T) {
	dir := t.TempDir()
	writeMinimalGoModule(t, dir)

	var stdout, stderr bytes.Buffer
	code := run([]string{"inventory", "--src", dir, "--format", "sarif", "--allow-downloads"}, &stdout, &stderr)
	if code != cli.ExitOperationalError {
		t.Errorf("exit code = %d, want %d", code, cli.ExitOperationalError)
	}
	if !strings.Contains(stderr.String(), "audit-only") {
		t.Errorf("stderr = %q, want it to explain SARIF is audit-only", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty", stdout.String())
	}
}

// TestRunHTMLIsNotASelectableFormat is the regression for "html shouldn't
// be a separate --format value — it should be made automatically when
// openapi is used": html is api.html, openapi's fixed companion file, not
// an independent report representation a user can request or omit on its
// own, so --format html must fail exactly like any other unknown format
// value rather than being accepted as a standalone choice.
func TestRunHTMLIsNotASelectableFormat(t *testing.T) {
	dir := t.TempDir()
	writeMinimalGoModule(t, dir)

	var stdout, stderr bytes.Buffer
	code := run([]string{"inventory", "--src", dir, "--format", "html", "--allow-downloads"}, &stdout, &stderr)
	if code != cli.ExitOperationalError {
		t.Errorf("exit code = %d, want %d", code, cli.ExitOperationalError)
	}
	if !strings.Contains(stderr.String(), "unsupported format") {
		t.Errorf("stderr = %q, want it to reject html as an unsupported format value", stderr.String())
	}
}

// TestRunOpenAPIFormatAlsoWritesHTMLCompanion is the regression for the same
// directive: requesting --format openapi with --out must produce api.html
// alongside openapi.json with no separate opt-in, and the two must describe
// the same routes since api.html is rendered from the identical document.
func TestRunOpenAPIFormatAlsoWritesHTMLCompanion(t *testing.T) {
	dir := t.TempDir() // no Gin usage — a valid, empty target
	writeMinimalGoModule(t, dir)
	outDir := t.TempDir()

	var stdout, stderr bytes.Buffer
	code := run([]string{"inventory", "--src", dir, "--format", "openapi", "--out", outDir, "--allow-downloads"}, &stdout, &stderr)
	if code != cli.ExitSuccess {
		t.Fatalf("exit code = %d, want %d; stderr: %s", code, cli.ExitSuccess, stderr.String())
	}

	openapiPath := filepath.Join(outDir, "openapi.json")
	htmlPath := filepath.Join(outDir, "api.html")
	if _, err := os.Stat(openapiPath); err != nil {
		t.Errorf("openapi.json was not written: %v", err)
	}
	htmlData, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatalf("api.html was not written alongside openapi.json: %v", err)
	}
	if !strings.Contains(string(htmlData), "<!doctype html>") {
		t.Errorf("api.html = %q, want an HTML document", htmlData)
	}
	if !strings.Contains(string(htmlData), `"openapi": "3.1.0"`) {
		t.Errorf("api.html does not embed the OpenAPI spec: %s", htmlData)
	}

	// Requesting a format other than openapi must not produce api.html.
	outDir2 := t.TempDir()
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"inventory", "--src", dir, "--format", "json", "--out", outDir2, "--allow-downloads"}, &stdout, &stderr)
	if code != cli.ExitSuccess {
		t.Fatalf("exit code = %d, want %d; stderr: %s", code, cli.ExitSuccess, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(outDir2, "api.html")); err == nil {
		t.Error("api.html was written even though openapi was not a requested format")
	}
}

// TestRunExcludeFlagScopesTheScan and the two tests following it are the
// regression for a real gap: --include/--exclude/--ignore-file were parsed
// and schema-validated but analyzer.LoadOptions had no corresponding fields
// at all, so every one of these flags (and their config-file equivalents)
// was silently a no-op — the scan always covered the whole target
// regardless of what was asked for.
func TestRunExcludeFlagScopesTheScan(t *testing.T) {
	dir := fixtureDir(t, "registrar-functions")
	var stdout, stderr bytes.Buffer
	code := run([]string{"inventory", "--src", dir, "--format", "json", "--exclude", "routes/**", "--allow-downloads"}, &stdout, &stderr)
	if code != cli.ExitSuccess {
		t.Fatalf("exit code = %d, want %d; stderr: %s", code, cli.ExitSuccess, stderr.String())
	}
	var doc map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
	}
	for _, r := range doc["routes"].([]any) {
		if r.(map[string]any)["normalizedPath"] == "/api/users" {
			t.Errorf("--exclude routes/** did not remove /api/users: %v", doc["routes"])
		}
	}
}

func TestRunIgnoreFileScopesTheScan(t *testing.T) {
	src := fixtureDir(t, "registrar-functions")
	// --ignore-file must resolve beneath --src (cli.Validate), so copy the
	// fixture into a writable temp dir rather than writing into testdata.
	dir := t.TempDir()
	copyDir(t, src, dir)
	if err := os.WriteFile(filepath.Join(dir, ".gin-reconignore"), []byte("# ignore the cross-package routes file\nroutes/**\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"inventory", "--src", dir, "--format", "json", "--allow-downloads"}, &stdout, &stderr)
	if code != cli.ExitSuccess {
		t.Fatalf("exit code = %d, want %d; stderr: %s", code, cli.ExitSuccess, stderr.String())
	}
	var doc map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
	}
	for _, r := range doc["routes"].([]any) {
		if r.(map[string]any)["normalizedPath"] == "/api/users" {
			t.Errorf(".gin-reconignore did not remove /api/users: %v", doc["routes"])
		}
	}
}

func TestRunConfigScanExcludeScopesTheScanWithoutAnyCLIFlag(t *testing.T) {
	src := fixtureDir(t, "registrar-functions")
	dir := t.TempDir()
	copyDir(t, src, dir)
	cfgPath := filepath.Join(dir, "gin-recon.json")
	if err := os.WriteFile(cfgPath, []byte(`{"version":1,"scan":{"exclude":["routes/**"]}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"inventory", "--src", dir, "--format", "json", "--config", cfgPath, "--allow-downloads"}, &stdout, &stderr)
	if code != cli.ExitSuccess {
		t.Fatalf("exit code = %d, want %d; stderr: %s", code, cli.ExitSuccess, stderr.String())
	}
	var doc map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
	}
	for _, r := range doc["routes"].([]any) {
		if r.(map[string]any)["normalizedPath"] == "/api/users" {
			t.Errorf("config scan.exclude did not remove /api/users with no CLI --exclude at all: %v", doc["routes"])
		}
	}
}

// TestRunCLIGOOSOverridesConfigAnalysisGOOS is the regression for the other
// half of the same contract rule: "Scalar CLI values override
// configuration." A config-supplied analysis.goos must not silently win
// over an explicitly-passed --goos.
func TestRunCLIGOOSOverridesConfigAnalysisGOOS(t *testing.T) {
	dir := t.TempDir()
	writeMinimalGoModule(t, dir)
	cfgPath := filepath.Join(dir, "gin-recon.json")
	if err := os.WriteFile(cfgPath, []byte(`{"version":1,"analysis":{"goos":"windows"}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"inventory", "--src", dir, "--format", "json", "--config", cfgPath, "--goos", runtime.GOOS, "--allow-downloads"}, &stdout, &stderr)
	if code != cli.ExitSuccess {
		t.Fatalf("exit code = %d, want %d; stderr: %s", code, cli.ExitSuccess, stderr.String())
	}
	var doc map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
	}
	goos := doc["scanCoverage"].(map[string]any)["buildContext"].(map[string]any)["goos"]
	if goos != runtime.GOOS {
		t.Errorf("scanCoverage.buildContext.goos = %v, want %q (explicit --goos must override config analysis.goos=windows)", goos, runtime.GOOS)
	}
}

// copyDir recursively copies src into dst — used to give a fixture module a
// writable location so a test can add an ignore file or config alongside it
// without mutating testdata.
func copyDir(t *testing.T, src, dst string) {
	t.Helper()
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		s := filepath.Join(src, e.Name())
		d := filepath.Join(dst, e.Name())
		if e.IsDir() {
			if err := os.MkdirAll(d, 0o755); err != nil {
				t.Fatal(err)
			}
			copyDir(t, s, d)
			continue
		}
		data, err := os.ReadFile(s)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(d, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func writeMinimalGoModule(t *testing.T, dir string) {
	t.Helper()
	if err := os.WriteFile(dir+"/go.mod", []byte("module example.com/empty\n\ngo 1.25\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"/main.go", []byte("package main\n\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// authWrappersConfigured is the full auth-wrappers fixture config (see
// testdata/fixtures/auth-wrappers/manifest.json), which classifies
// /wrapped/positive, /wrapped/nested, and /wrapped/factory as proven and
// produces a matched-but-unenforced finding on /wrapped/contradicted.
const authWrappersConfigured = `{
  "version": 1,
  "authMiddleware": {
    "gin-recon-fixtures/auth-wrappers.RequireAuth": { "assurance": "analyze" },
    "gin-recon-fixtures/auth-wrappers.RequireAuthContradicted": { "assurance": "analyze" },
    "gin-recon-fixtures/auth-wrappers.RequireRoleFactory": { "assurance": "analyze" }
  },
  "authWrappers": [
    "gin-recon-fixtures/auth-wrappers.LoggedAuth"
  ]
}`

const authWrappersEmpty = `{"version": 1}`

// runAuditJSON runs "audit" against dir with the given config content
// (written to a fresh temp file) and returns the decoded JSON report.
func runAuditJSON(t *testing.T, dir, configJSON string) ([]byte, map[string]any) {
	t.Helper()
	cfgPath := filepath.Join(t.TempDir(), "gin-recon.json")
	if err := os.WriteFile(cfgPath, []byte(configJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"audit", "--src", dir, "--format", "json", "--config", cfgPath, "--allow-downloads"}, &stdout, &stderr)
	if code != cli.ExitSuccess {
		t.Fatalf("exit code = %d, want %d; stderr: %s", code, cli.ExitSuccess, stderr.String())
	}
	var doc map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
	}
	return stdout.Bytes(), doc
}

func writeBaseline(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestRunInventoryRejectsOutputExceedingMaxOutputBytes is a regression test
// for a real gap: limits.maxOutputBytes was validated as a config *value*
// (internal/config/validate.go) but never actually enforced anywhere in the
// output-writing path — any rendered artifact, however large, was written
// unconditionally. A config with an unrealistically tiny maxOutputBytes
// against a real fixture's report must now be refused rather than written.
func TestRunInventoryRejectsOutputExceedingMaxOutputBytes(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "gin-recon.json")
	tinyLimitConfig := `{"version":1,"limits":{"maxOutputBytes":10}}`
	if err := os.WriteFile(cfgPath, []byte(tinyLimitConfig), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"inventory", "--src", fixtureDir(t, "route-kinds"), "--format", "json",
		"--config", cfgPath, "--allow-downloads",
	}, &stdout, &stderr)
	if code != cli.ExitOperationalError {
		t.Fatalf("exit code = %d, want %d; stdout: %s stderr: %s", code, cli.ExitOperationalError, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "maxOutputBytes") {
		t.Errorf("stderr = %q, want it to explain the maxOutputBytes limit", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty — an over-limit report must never be written", stdout.String())
	}
}

// TestRunInventoryIncludeTestsFlagWorksEndToEnd is the CLI-level regression
// test for a real gap: --include-tests was parsed and schema-validated but
// never actually threaded through to the analyzer, so it silently did
// nothing regardless of how it was set (internal/analyzer/scope_test.go has
// the lower-level Load/LoadSyntax regression tests for the same fix).
func TestRunInventoryIncludeTestsFlagWorksEndToEnd(t *testing.T) {
	dir := fixtureDir(t, "include-tests")

	var stdout, stderr bytes.Buffer
	if code := run([]string{"inventory", "--src", dir, "--format", "json", "--allow-downloads"}, &stdout, &stderr); code != cli.ExitSuccess {
		t.Fatalf("exit code = %d; stderr: %s", code, stderr.String())
	}
	if strings.Contains(stdout.String(), "/test-only-route") {
		t.Errorf("expected /test-only-route to be invisible without --include-tests: %s", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"inventory", "--src", dir, "--format", "json", "--allow-downloads", "--include-tests"}, &stdout, &stderr); code != cli.ExitSuccess {
		t.Fatalf("exit code = %d; stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "/test-only-route") {
		t.Errorf("expected /test-only-route to be discovered with --include-tests: %s", stdout.String())
	}
}

// TestRunAuditBaselineRejectsInvalidAuthStatus is a regression test for real
// artifact-validation gap: --baseline is an external, untrusted file, and
// before this fix its routes' own authStatus values were never checked
// against model.AuthProven/Public/Unknown — a crafted or corrupted baseline
// claiming some bogus status would either silently fail to match
// --fail-on's gate logic, or feed a nonsense value into the delta, rather
// than being rejected as the malformed input it is.
func TestRunAuditBaselineRejectsInvalidAuthStatus(t *testing.T) {
	maliciousBaseline := `{"schemaVersion":"1.0","command":"audit","routes":[
		{"method":"GET","normalizedPath":"/x","auth":{"authStatus":"totally-bogus"}}
	]}`
	baselinePath := writeBaseline(t, []byte(maliciousBaseline))

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"audit", "--src", fixtureDir(t, "auth-wrappers"), "--format", "json",
		"--baseline", baselinePath, "--allow-downloads",
	}, &stdout, &stderr)
	if code != cli.ExitOperationalError {
		t.Fatalf("exit code = %d, want %d; stderr: %s", code, cli.ExitOperationalError, stderr.String())
	}
	if !strings.Contains(stderr.String(), "invalid authStatus") {
		t.Errorf("stderr = %q, want it to reject the invalid authStatus", stderr.String())
	}
}

// TestRunFleetRenderRejectsInvalidAuthStatus mirrors the --baseline case
// above for render's own external --report validation.
func TestRunFleetRenderRejectsInvalidAuthStatus(t *testing.T) {
	root := t.TempDir()
	outDir := filepath.Join(root, "out")
	if err := os.MkdirAll(filepath.Join(outDir, "targets", "repo-a"), 0o755); err != nil {
		t.Fatal(err)
	}
	maliciousRoutes := `{"schemaVersion":"1.0","command":"audit","routes":[
		{"method":"GET","normalizedPath":"/x","auth":{"authStatus":"totally-bogus"}}
	]}`
	if err := os.WriteFile(filepath.Join(outDir, "targets", "repo-a", "routes.json"), []byte(maliciousRoutes), 0o644); err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(outDir, "fleet.json")
	fleetJSON := `{"targets":[{"name":"repo-a","status":"ok"}]}`
	if err := os.WriteFile(reportPath, []byte(fleetJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"render", "--report", reportPath, "--format", "json", "--force"}, &stdout, &stderr)
	if code != cli.ExitOperationalError {
		t.Fatalf("exit code = %d, want %d; stderr: %s", code, cli.ExitOperationalError, stderr.String())
	}
	if !strings.Contains(stderr.String(), "invalid authStatus") {
		t.Errorf("stderr = %q, want it to reject the invalid authStatus", stderr.String())
	}
}

// TestRunAuditBaselineDetectsAuthRegressions is the CLI-level integration
// test for --baseline: comparing a baseline captured with the auth-wrappers
// fixture's full config against a current run with an empty config (so
// every previously-proven wrapped route drops to public) must surface those
// drops as delta.authRegressions and the contradicted route's
// matched-but-unenforced finding as a resolved finding.
func TestRunAuditBaselineDetectsAuthRegressions(t *testing.T) {
	dir := fixtureDir(t, "auth-wrappers")
	baselineData, _ := runAuditJSON(t, dir, authWrappersConfigured)
	baselinePath := writeBaseline(t, baselineData)

	cfgPath := filepath.Join(t.TempDir(), "gin-recon.json")
	if err := os.WriteFile(cfgPath, []byte(authWrappersEmpty), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"audit", "--src", dir, "--format", "json", "--config", cfgPath,
		"--baseline", baselinePath, "--fail-on", "regression", "--allow-downloads",
	}, &stdout, &stderr)
	if code != cli.ExitGate {
		t.Fatalf("exit code = %d, want %d (ExitGate); stderr: %s", code, cli.ExitGate, stderr.String())
	}
	var doc map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
	}
	delta, ok := doc["delta"].(map[string]any)
	if !ok {
		t.Fatalf("delta missing from report: %s", stdout.String())
	}
	regressions, ok := delta["authRegressions"].([]any)
	if !ok || len(regressions) == 0 {
		t.Fatalf("authRegressions = %v, want at least one regression", delta["authRegressions"])
	}
	found := false
	for _, r := range regressions {
		change := r.(map[string]any)
		if change["path"] == "/wrapped/positive" && change["from"] == "proven" && change["to"] == "public" {
			found = true
		}
	}
	if !found {
		t.Errorf("authRegressions = %v, want /wrapped/positive proven -> public", regressions)
	}
	resolved, ok := delta["resolvedFindings"].([]any)
	if !ok || len(resolved) == 0 {
		t.Errorf("resolvedFindings = %v, want the contradicted route's matched-but-unenforced finding to resolve", delta["resolvedFindings"])
	}
}

// TestRunAuditBaselineFailOnNewDetectsNewFindings mirrors the previous test
// with baseline/current reversed: moving from the empty config to the fully
// configured one introduces a new matched-but-unenforced finding on
// /wrapped/contradicted, which --fail-on new must catch even though no
// route was added or removed.
func TestRunAuditBaselineFailOnNewDetectsNewFindings(t *testing.T) {
	dir := fixtureDir(t, "auth-wrappers")
	baselineData, _ := runAuditJSON(t, dir, authWrappersEmpty)
	baselinePath := writeBaseline(t, baselineData)

	cfgPath := filepath.Join(t.TempDir(), "gin-recon.json")
	if err := os.WriteFile(cfgPath, []byte(authWrappersConfigured), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"audit", "--src", dir, "--format", "json", "--config", cfgPath,
		"--baseline", baselinePath, "--fail-on", "new", "--allow-downloads",
	}, &stdout, &stderr)
	if code != cli.ExitGate {
		t.Fatalf("exit code = %d, want %d (ExitGate); stderr: %s", code, cli.ExitGate, stderr.String())
	}
	var doc map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
	}
	delta := doc["delta"].(map[string]any)
	newFindings, ok := delta["newFindings"].([]any)
	if !ok || len(newFindings) == 0 {
		t.Errorf("newFindings = %v, want the new matched-but-unenforced finding", delta["newFindings"])
	}
	improvements, ok := delta["authImprovements"].([]any)
	if !ok || len(improvements) == 0 {
		t.Errorf("authImprovements = %v, want the now-proven wrapped routes", delta["authImprovements"])
	}
}

// TestRunAuditBaselineWithoutFailOnStillSucceeds confirms --baseline alone
// (no --fail-on new/regression) still produces the delta but exits 0 — the
// delta is informational unless a gate selector asks for it.
func TestRunAuditBaselineWithoutFailOnStillSucceeds(t *testing.T) {
	dir := fixtureDir(t, "auth-wrappers")
	baselineData, _ := runAuditJSON(t, dir, authWrappersConfigured)
	baselinePath := writeBaseline(t, baselineData)

	cfgPath := filepath.Join(t.TempDir(), "gin-recon.json")
	if err := os.WriteFile(cfgPath, []byte(authWrappersConfigured), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"audit", "--src", dir, "--format", "json", "--config", cfgPath,
		"--baseline", baselinePath, "--allow-downloads",
	}, &stdout, &stderr)
	if code != cli.ExitSuccess {
		t.Fatalf("exit code = %d, want %d (no --fail-on gate); stderr: %s", code, cli.ExitSuccess, stderr.String())
	}
	var doc map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
	}
	if _, ok := doc["delta"]; !ok {
		t.Errorf("delta missing even though --baseline was supplied: %s", stdout.String())
	}
}

// TestRunAuditBaselineRejectsIncompatibleAnalysisProfile confirms a
// baseline/current mismatch is rejected with an operational error rather
// than silently producing a misleading comparison, per
// docs/reference.md's baseline compatibility requirement.
func TestRunAuditBaselineRejectsIncompatibleAnalysisProfile(t *testing.T) {
	dir := fixtureDir(t, "auth-wrappers")
	_, doc := runAuditJSON(t, dir, authWrappersEmpty)
	doc["analysisProfile"] = "syntax-only" // tamper: simulate an incompatible baseline
	tampered, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	baselinePath := writeBaseline(t, tampered)

	cfgPath := filepath.Join(t.TempDir(), "gin-recon.json")
	if err := os.WriteFile(cfgPath, []byte(authWrappersEmpty), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"audit", "--src", dir, "--format", "json", "--config", cfgPath,
		"--baseline", baselinePath, "--allow-downloads",
	}, &stdout, &stderr)
	if code != cli.ExitOperationalError {
		t.Fatalf("exit code = %d, want %d; stderr: %s", code, cli.ExitOperationalError, stderr.String())
	}
	if !strings.Contains(stderr.String(), "analysis profile") {
		t.Errorf("stderr = %q, want it to explain the analysis profile mismatch", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty on a rejected baseline", stdout.String())
	}
}

func TestRunNonexistentSrcFailsBeforeDispatch(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"inventory", "--src", "/definitely/does/not/exist"}, &stdout, &stderr)
	if code != cli.ExitOperationalError {
		t.Errorf("exit code = %d, want %d", code, cli.ExitOperationalError)
	}
	if !strings.Contains(stderr.String(), "could not be resolved") {
		t.Errorf("stderr = %q, want a path-resolution error", stderr.String())
	}
}

// TestRunRenderReproducesAuditOutputFromSavedReport is the CLI-level
// integration test for docs/adr/0016-render-command-decouples-formatting-from-analysis.md's
// central claim: render, over a routes.json a prior audit run already
// produced, reproduces byte-for-byte what that same audit run's own
// --format json,openapi --out would have written — routes.json, openapi.json,
// and its api.html companion — without ever rescanning dir. report.Report
// carries no timestamp field (grepped: no generatedAt/time.Now output), so
// there is nothing non-deterministic to account for.
func TestRunRenderReproducesAuditOutputFromSavedReport(t *testing.T) {
	dir := fixtureDir(t, "auth-wrappers")
	outDir := t.TempDir()

	var stdout, stderr bytes.Buffer
	code := run([]string{"audit", "--src", dir, "--format", "json,openapi", "--out", outDir, "--allow-downloads"}, &stdout, &stderr)
	if code != cli.ExitSuccess {
		t.Fatalf("audit exit code = %d, want %d; stderr: %s", code, cli.ExitSuccess, stderr.String())
	}

	renderOutDir := t.TempDir()
	reportPath := filepath.Join(outDir, "routes.json")
	var rstdout, rstderr bytes.Buffer
	code = run([]string{"render", "--report", reportPath, "--format", "json,openapi", "--out", renderOutDir}, &rstdout, &rstderr)
	if code != cli.ExitSuccess {
		t.Fatalf("render exit code = %d, want %d; stderr: %s", code, cli.ExitSuccess, rstderr.String())
	}

	for _, name := range []string{"routes.json", "openapi.json", "api.html"} {
		want, err := os.ReadFile(filepath.Join(outDir, name))
		if err != nil {
			t.Fatalf("reading original audit run's %s: %v", name, err)
		}
		got, err := os.ReadFile(filepath.Join(renderOutDir, name))
		if err != nil {
			t.Fatalf("render did not produce %s: %v", name, err)
		}
		if !bytes.Equal(want, got) {
			t.Errorf("%s differs between the direct audit run and render over its saved routes.json", name)
		}
	}
}

// TestRunRenderSARIFAgainstInventoryReportIsRejected confirms render applies
// SARIF's audit-only restriction the same way inventory/audit's own
// cli.Validate does (see TestRunInventorySARIFFormatIsRejected) — except
// render can only make that decision after loading --report, since its own
// CLI command is always "render", never "inventory"/"audit".
func TestRunRenderSARIFAgainstInventoryReportIsRejected(t *testing.T) {
	dir := t.TempDir()
	writeMinimalGoModule(t, dir)
	outDir := t.TempDir()

	var stdout, stderr bytes.Buffer
	code := run([]string{"inventory", "--src", dir, "--format", "json", "--out", outDir, "--allow-downloads"}, &stdout, &stderr)
	if code != cli.ExitSuccess {
		t.Fatalf("inventory exit code = %d, want %d; stderr: %s", code, cli.ExitSuccess, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = run([]string{"render", "--report", filepath.Join(outDir, "routes.json"), "--format", "sarif"}, &stdout, &stderr)
	if code != cli.ExitOperationalError {
		t.Errorf("exit code = %d, want %d", code, cli.ExitOperationalError)
	}
	if !strings.Contains(stderr.String(), "audit-only") {
		t.Errorf("stderr = %q, want it to explain SARIF is audit-only", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty", stdout.String())
	}
}

// TestRunRenderMissingReportFileFails and TestRunRenderMalformedReportFileFails
// cover docs/adr/0016's "a malformed or schema-incompatible input is a
// render-specific validation failure (exit 1), not a silent best-effort
// attempt."
func TestRunRenderMissingReportFileFails(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"render", "--report", filepath.Join(t.TempDir(), "does-not-exist.json")}, &stdout, &stderr)
	if code != cli.ExitOperationalError {
		t.Errorf("exit code = %d, want %d", code, cli.ExitOperationalError)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty", stdout.String())
	}
	if stderr.Len() == 0 {
		t.Error("stderr is empty, want an explanation of the missing --report file")
	}
}

func TestRunRenderMalformedReportFileFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "routes.json")
	if err := os.WriteFile(path, []byte("{ not valid json"), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"render", "--report", path}, &stdout, &stderr)
	if code != cli.ExitOperationalError {
		t.Errorf("exit code = %d, want %d", code, cli.ExitOperationalError)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "--report") {
		t.Errorf("stderr = %q, want it to name --report as the source of the failure", stderr.String())
	}
}

// TestRunRenderNeverTouchesASourceTree is the cheap proof render has no
// hidden analysis dependency: it points --report at a real routes.json while
// there is no source tree reachable at all — no --src, no fake Go module set
// up, not even a go.mod on disk anywhere near the report file's own temp
// dir — and confirms render still succeeds. A hidden call into
// internal/analyzer or go/packages would necessarily fail here, since there
// is nothing for either to load.
func TestRunRenderNeverTouchesASourceTree(t *testing.T) {
	scanDir := t.TempDir()
	writeMinimalGoModule(t, scanDir)
	captureDir := t.TempDir()

	var stdout, stderr bytes.Buffer
	code := run([]string{"inventory", "--src", scanDir, "--format", "json", "--out", captureDir, "--allow-downloads"}, &stdout, &stderr)
	if code != cli.ExitSuccess {
		t.Fatalf("inventory exit code = %d, want %d; stderr: %s", code, cli.ExitSuccess, stderr.String())
	}

	// Move the captured report far away from any Go module or source tree,
	// into a directory containing nothing but that one file, before render
	// ever sees it.
	isolatedDir := t.TempDir()
	reportData, err := os.ReadFile(filepath.Join(captureDir, "routes.json"))
	if err != nil {
		t.Fatal(err)
	}
	isolatedReportPath := filepath.Join(isolatedDir, "routes.json")
	if err := os.WriteFile(isolatedReportPath, reportData, 0o644); err != nil {
		t.Fatal(err)
	}

	stdout.Reset()
	stderr.Reset()
	code = run([]string{"render", "--report", isolatedReportPath, "--format", "pretty"}, &stdout, &stderr)
	if code != cli.ExitSuccess {
		t.Fatalf("render exit code = %d, want %d; stderr: %s", code, cli.ExitSuccess, stderr.String())
	}
	if !strings.Contains(stdout.String(), "gin-recon inventory") {
		t.Errorf("stdout = %q, want pretty-formatted output over the loaded report", stdout.String())
	}
}

// buildRealGinReconBinary compiles this checkout's actual main package to a
// temp binary, for tests that need fleet to re-exec a real "audit"
// subcommand rather than the go-test binary os.Executable() would otherwise
// resolve to under `go test`.
func buildRealGinReconBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "gin-recon-under-test")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building gin-recon for test: %v\n%s", err, out)
	}
	return bin
}

// TestRunFleetOrgMaxReposIncompleteTriggersFailOn is a regression test for a
// real bug caught by hand: --max-repos capping a --org discovery (fewer
// repositories fetched than the organization actually has) must count as
// "incomplete" for --fail-on incomplete, the same way a target's own
// scanCoverage.complete: false already does. It didn't — discoveryIncomplete
// was reported to stderr but never folded into the aggregate's
// Coverage.Complete, so the gate silently never fired even though every
// discovered (capped) target finished cleanly.
func TestRunFleetOrgMaxReposIncompleteTriggersFailOn(t *testing.T) {
	fleetBinaryPathForTests = buildRealGinReconBinary(t)
	defer func() { fleetBinaryPathForTests = "" }()

	// A host deliberately absent from the allowlist below: the clone
	// attempt fails fast at the authorization check, with no real network
	// access and no dependency on clone success — this test only needs to
	// isolate the discovery-incompleteness bug, not exercise cloning.
	const repoURL = "https://repo-host-not-in-any-allowlist.test/x.git"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := json.Marshal([]map[string]any{
			{"name": "repo-a", "clone_url": repoURL, "default_branch": "main", "size": 1},
			{"name": "repo-b", "clone_url": repoURL, "default_branch": "main", "size": 1},
			{"name": "repo-c", "clone_url": repoURL, "default_branch": "main", "size": 1},
		})
		w.Write(body)
	}))
	defer srv.Close()
	fleetGitHubAPIBaseForTests = srv.URL
	defer func() { fleetGitHubAPIBaseForTests = "" }()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "cfg.json")
	if err := os.WriteFile(cfgPath, []byte(`{"version":1,"fleet":{"allowedRemoteHosts":[{"host":"api.github.com"},{"host":"github.com"}]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(dir, "out")

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"fleet", "--org", "myorg", "--config", cfgPath, "--out", outDir,
		"--allow-remote-targets", "--max-repos", "2", "--fail-on", "incomplete",
	}, &stdout, &stderr)

	if code != cli.ExitGate {
		t.Fatalf("exit code = %d, want %d (ExitGate); stderr: %s", code, cli.ExitGate, stderr.String())
	}
	aggData, err := os.ReadFile(filepath.Join(outDir, "fleet.json"))
	if err != nil {
		t.Fatal(err)
	}
	var agg struct {
		Targets  []map[string]any `json:"targets"`
		Coverage struct {
			Complete bool `json:"complete"`
		} `json:"coverage"`
	}
	if err := json.Unmarshal(aggData, &agg); err != nil {
		t.Fatal(err)
	}
	if agg.Coverage.Complete {
		t.Error("fleet.json coverage.complete = true, want false: --max-repos capped a larger discovery")
	}
	if len(agg.Targets) != 2 {
		t.Fatalf("Targets = %+v, want exactly 2 (the --max-repos cap)", agg.Targets)
	}
}

func TestRunFleetOrgAutomaticallyPublishesDraftsDuringScan(t *testing.T) {
	fleetBinaryPathForTests = buildRealGinReconBinary(t)
	defer func() { fleetBinaryPathForTests = "" }()
	const testToken = "local-org-scan-test-token"
	t.Setenv("GH_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", testToken)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			t.Errorf("default config did not authenticate org discovery")
		}
		body, _ := json.Marshal([]map[string]any{
			{"name": "repo-a", "clone_url": "https://github.com/myorg/repo-a.git", "default_branch": "main", "size": 1},
			{"name": "repo-b", "clone_url": "https://github.com/myorg/repo-b.git", "default_branch": "main", "size": 1},
		})
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	fleetGitHubAPIBaseForTests = srv.URL
	defer func() { fleetGitHubAPIBaseForTests = "" }()

	root := t.TempDir()
	outDir := filepath.Join(root, "out")
	cloneCount := 0
	fleetCloneForTests = func(_ context.Context, _, _ string, destination, token string) error {
		if token != testToken {
			return fmt.Errorf("default config did not authenticate cloning")
		}
		cloneCount++
		if info, err := os.Stat(filepath.Join(outDir, targetConfigDraftDirName)); err != nil || !info.IsDir() {
			return fmt.Errorf("draft directory did not exist before clone %d: %v", cloneCount, err)
		}
		if cloneCount == 2 {
			if _, err := os.Stat(filepath.Join(outDir, targetConfigDraftDirName, "repo-a.json")); err != nil {
				return fmt.Errorf("repo-a draft was not visible before repo-b started: %v", err)
			}
		}
		return os.CopyFS(destination, os.DirFS(fixtureDir(t, "auth-wrappers")))
	}
	defer func() { fleetCloneForTests = nil }()

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"fleet", "--org", "myorg", "--out", outDir,
		"--allow-remote-targets", "--allow-downloads", "--concurrency", "1",
	}, &stdout, &stderr)
	if code != cli.ExitSuccess {
		t.Fatalf("exit code = %d; stderr: %s", code, stderr.String())
	}
	for _, filename := range []string{fleetDefaultConfigFilename, "config-snapshot.json"} {
		data, err := os.ReadFile(filepath.Join(outDir, filename))
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != fleetDefaultConfig || bytes.Contains(data, []byte(testToken)) {
			t.Errorf("%s must contain the default config without credential values", filename)
		}
	}
	for _, name := range []string{"repo-a", "repo-b"} {
		data, err := os.ReadFile(filepath.Join(outDir, targetConfigDraftDirName, name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		var draft targetConfigDraft
		if err := json.Unmarshal(data, &draft); err != nil {
			t.Fatal(err)
		}
		if draft.ReviewState != "candidates-to-review" || len(draft.Candidates) == 0 {
			t.Fatalf("%s draft = %+v", name, draft)
		}
	}
}

// TestRunFleetOrgResumeToleratesPushedAtDrift is a regression test for a
// real bug found live against a real organization
// (docs/adr/0026-fleet-org-resume-ignores-provenance-drift.md): --resume
// refused every real re-run because the discovered manifest's GitHubMeta
// (pushedAt in particular, which changes on every commit anywhere in the
// org) was part of what got hashed for checkpoint identity. Two --org
// invocations against a fake GitHub API that returns the identical
// TestRunFleetOrgUpdateBypassesConflictPrompt is a regression test for
// docs/adr/0039-fleet-org-update.md's interactive-prompt decision:
// --update is, on its own, a complete answer to "output already exists
// here" — it must proceed straight through even non-interactively
// (matching --force/--resume's own existing behavior), never hitting the
// hard error/prompt docs/adr/0034 added for the plain no-flag case.
func TestRunFleetOrgUpdateBypassesConflictPrompt(t *testing.T) {
	fleetBinaryPathForTests = buildRealGinReconBinary(t)
	defer func() { fleetBinaryPathForTests = "" }()

	const repoURL = "https://repo-host-not-in-any-allowlist.test/x.git"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := json.Marshal([]map[string]any{
			{"name": "repo-a", "clone_url": repoURL, "default_branch": "main", "size": 1, "pushed_at": "2026-01-01T00:00:00Z"},
		})
		w.Write(body)
	}))
	defer srv.Close()
	fleetGitHubAPIBaseForTests = srv.URL
	defer func() { fleetGitHubAPIBaseForTests = "" }()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "cfg.json")
	if err := os.WriteFile(cfgPath, []byte(`{"version":1,"fleet":{"allowedRemoteHosts":[{"host":"api.github.com"},{"host":"github.com"}]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(dir, "out")
	args := []string{"fleet", "--org", "myorg", "--config", cfgPath, "--out", outDir, "--allow-remote-targets"}

	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != cli.ExitSuccess {
		t.Fatalf("first run: exit code = %d, want %d; stderr: %s", code, cli.ExitSuccess, stderr.String())
	}

	// fleet.json now exists at outDir. A second run with neither --force
	// nor --resume would normally hard-error (or prompt, interactively);
	// --update alone must sail through instead.
	stdout.Reset()
	stderr.Reset()
	code := run(append(append([]string{}, args...), "--update"), &stdout, &stderr)
	if code != cli.ExitSuccess {
		t.Fatalf("--update run: exit code = %d, want %d; stderr: %s", code, cli.ExitSuccess, stderr.String())
	}
	if strings.Contains(stderr.String(), "already exists") {
		t.Errorf("--update should bypass the conflict check entirely, got: %s", stderr.String())
	}
}

// target set but a different pushed_at each time must both succeed, with
// the second one actually resuming (not re-scanning) the completed target.
func TestRunFleetOrgResumeToleratesPushedAtDrift(t *testing.T) {
	fleetBinaryPathForTests = buildRealGinReconBinary(t)
	defer func() { fleetBinaryPathForTests = "" }()

	const repoURL = "https://repo-host-not-in-any-allowlist.test/x.git"
	pushedAt := "2026-01-01T00:00:00Z"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := json.Marshal([]map[string]any{
			{"name": "repo-a", "clone_url": repoURL, "default_branch": "main", "size": 1, "pushed_at": pushedAt},
		})
		w.Write(body)
	}))
	defer srv.Close()
	fleetGitHubAPIBaseForTests = srv.URL
	defer func() { fleetGitHubAPIBaseForTests = "" }()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "cfg.json")
	if err := os.WriteFile(cfgPath, []byte(`{"version":1,"fleet":{"allowedRemoteHosts":[{"host":"api.github.com"},{"host":"github.com"}]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(dir, "out")

	args := []string{"fleet", "--org", "myorg", "--config", cfgPath, "--out", outDir, "--allow-remote-targets"}

	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != cli.ExitSuccess {
		t.Fatalf("first run: exit code = %d, want %d; stderr: %s", code, cli.ExitSuccess, stderr.String())
	}

	// The repository received a "commit" between the two runs: same name,
	// same clone URL, only pushed_at differs — exactly the drift that must
	// not invalidate the checkpoint.
	pushedAt = "2026-06-15T12:00:00Z"

	stdout.Reset()
	stderr.Reset()
	code := run(append(append([]string{}, args...), "--resume"), &stdout, &stderr)
	if code != cli.ExitSuccess {
		t.Fatalf("resumed run: exit code = %d, want %d; stderr: %s", code, cli.ExitSuccess, stderr.String())
	}
	if strings.Contains(stderr.String(), "the targets file has changed") {
		t.Fatalf("resume refused despite only pushed_at drifting: %s", stderr.String())
	}
}

// TestRunFleetOrgWritesConfigSnapshot is the CLI-level integration test for
// docs/adr/0025-fleet-org-config-snapshot.md: an --org run copies its
// resolved --config verbatim into --out, alongside discovered-targets.json,
// so revisiting the run later doesn't depend on the original --config path
// still existing or being unchanged.
func TestRunFleetOrgWritesConfigSnapshot(t *testing.T) {
	fleetBinaryPathForTests = buildRealGinReconBinary(t)
	defer func() { fleetBinaryPathForTests = "" }()

	// A host deliberately absent from the allowlist below: the clone attempt
	// fails fast at the authorization check, with no real network access —
	// this test only needs a discovered repo to exist, not a successful clone.
	const repoURL = "https://repo-host-not-in-any-allowlist.test/x.git"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := json.Marshal([]map[string]any{
			{"name": "repo-a", "clone_url": repoURL, "default_branch": "main", "size": 1},
		})
		w.Write(body)
	}))
	defer srv.Close()
	fleetGitHubAPIBaseForTests = srv.URL
	defer func() { fleetGitHubAPIBaseForTests = "" }()

	dir := t.TempDir()
	const cfgContent = `{"version":1,"fleet":{"allowedRemoteHosts":[{"host":"api.github.com"},{"host":"github.com"}]}}`
	cfgPath := filepath.Join(dir, "cfg.json")
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0o644); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(dir, "out")

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"fleet", "--org", "myorg", "--config", cfgPath, "--out", outDir,
		"--allow-remote-targets",
	}, &stdout, &stderr)
	if code != cli.ExitSuccess {
		t.Fatalf("exit code = %d, want %d; stderr: %s", code, cli.ExitSuccess, stderr.String())
	}

	got, err := os.ReadFile(filepath.Join(outDir, "config-snapshot.json"))
	if err != nil {
		t.Fatalf("config-snapshot.json: %v", err)
	}
	if string(got) != cfgContent {
		t.Errorf("config-snapshot.json = %q, want %q", got, cfgContent)
	}
}

// TestRunFleetTargetsDoesNotWriteConfigSnapshot confirms the snapshot is
// --org-only (docs/adr/0025-fleet-org-config-snapshot.md): a plain
// TestRunFleetPrintsProgress is the CLI-level check that fleet's stderr
// actually carries live per-target progress lines, not just the
// end-of-run error summary — a real complaint: a long fleet run produced
// no visible output at all until it finished.
func TestRunFleetPrintsProgress(t *testing.T) {
	fleetBinaryPathForTests = buildRealGinReconBinary(t)
	defer func() { fleetBinaryPathForTests = "" }()

	root := t.TempDir()
	src := filepath.Join(root, "repo-a")
	if err := os.CopyFS(src, os.DirFS(fixtureDir(t, "auth-wrappers"))); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(root, "targets.json")
	manifest := fmt.Sprintf(`{"version":1,"targets":[{"name":"repo-a","src":%q}]}`, src)
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"fleet", "--targets", manifestPath, "--out", filepath.Join(root, "out"), "--allow-downloads"}, &stdout, &stderr)
	if code != cli.ExitSuccess {
		t.Fatalf("fleet exit code = %d, want %d; stderr: %s", code, cli.ExitSuccess, stderr.String())
	}
	if !strings.Contains(stderr.String(), "[1/1] repo-a: ok") {
		t.Errorf("stderr should carry a progress line for repo-a, got: %q", stderr.String())
	}
}

// TestRunFleetDoesNotRenderHTMLByDefault is a regression test for
// docs/adr/0037-fleet-html-opt-in.md: fleet.html was previously an
// unconditional companion to fleet.json — asked directly not to do that,
// since rendering should be something the user opts into, not something
// fleet decides for them. A bare fleet run with no --render-html must
// write the raw fleet.json and nothing under any <out>-html sibling at
// all — not even the directory.
func TestRunFleetDoesNotRenderHTMLByDefault(t *testing.T) {
	fleetBinaryPathForTests = buildRealGinReconBinary(t)
	defer func() { fleetBinaryPathForTests = "" }()

	root := t.TempDir()
	src := filepath.Join(root, "repo-a")
	if err := os.CopyFS(src, os.DirFS(fixtureDir(t, "auth-wrappers"))); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(root, "targets.json")
	manifest := fmt.Sprintf(`{"version":1,"targets":[{"name":"repo-a","src":%q}]}`, src)
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(root, "out")

	var stdout, stderr bytes.Buffer
	code := run([]string{"fleet", "--targets", manifestPath, "--out", outDir, "--allow-downloads"}, &stdout, &stderr)
	if code != cli.ExitSuccess {
		t.Fatalf("fleet exit code = %d, want %d; stderr: %s", code, cli.ExitSuccess, stderr.String())
	}

	if _, err := os.Stat(filepath.Join(outDir, "fleet.json")); err != nil {
		t.Errorf("expected fleet.json to still be written: %v", err)
	}
	if _, err := os.Stat(outDir + "-html"); !os.IsNotExist(err) {
		t.Errorf("no <out>-html sibling should exist without --render-html, stat err = %v", err)
	}
}

// fleetConflictFixture runs a fresh fleet scan to completion and returns
// the args a second, conflicting invocation against the same --out would
// use — shared setup for every interactive-conflict-prompt test below
// (docs/adr/0034-fleet-interactive-conflict-prompt.md).
func fleetConflictFixture(t *testing.T) (args []string, outDir string) {
	t.Helper()
	fleetBinaryPathForTests = buildRealGinReconBinary(t)
	t.Cleanup(func() { fleetBinaryPathForTests = "" })

	root := t.TempDir()
	src := filepath.Join(root, "repo-a")
	if err := os.CopyFS(src, os.DirFS(fixtureDir(t, "auth-wrappers"))); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(root, "targets.json")
	manifest := fmt.Sprintf(`{"version":1,"targets":[{"name":"repo-a","src":%q}]}`, src)
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	outDir = filepath.Join(root, "out")
	args = []string{"fleet", "--targets", manifestPath, "--out", outDir, "--allow-downloads"}

	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != cli.ExitSuccess {
		t.Fatalf("initial fleet run exit code = %d, want %d; stderr: %s", code, cli.ExitSuccess, stderr.String())
	}
	return args, outDir
}

// TestRunFleetConflictNonInteractiveStillHardErrors is a regression test
// pinning down existing behavior: without a real terminal (the default for
// every test, tests, CI, and scripts), fleet must keep failing with the
// same clear, deterministic error it always has — no prompt, no change.
func TestRunFleetConflictNonInteractiveStillHardErrors(t *testing.T) {
	args, _ := fleetConflictFixture(t)

	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	if code != cli.ExitOperationalError {
		t.Fatalf("exit code = %d, want %d", code, cli.ExitOperationalError)
	}
	if !strings.Contains(stderr.String(), "already exists; pass --force to overwrite or --resume to continue") {
		t.Errorf("stderr = %q, want the original hard-error message", stderr.String())
	}
}

// TestRunFleetConflictInteractivePromptResume covers the "r" answer: it
// must behave exactly as if --resume had been passed.
func TestRunFleetConflictInteractivePromptResume(t *testing.T) {
	args, _ := fleetConflictFixture(t)
	isInteractiveTerminalForTests = func() bool { return true }
	fleetStdinForTests = strings.NewReader("r\n")
	defer func() { isInteractiveTerminalForTests = func() bool { return false }; fleetStdinForTests = nil }()

	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	if code != cli.ExitSuccess {
		t.Fatalf("exit code = %d, want %d; stderr: %s", code, cli.ExitSuccess, stderr.String())
	}
	if !strings.Contains(stdout.String(), "already exists") || !strings.Contains(stdout.String(), "[R]esume") {
		t.Errorf("stdout should show the conflict prompt, got: %q", stdout.String())
	}
}

// TestRunFleetConflictInteractivePromptOverwrite covers the "o" answer: it
// must behave exactly as if --force had been passed.
func TestRunFleetConflictInteractivePromptOverwrite(t *testing.T) {
	args, _ := fleetConflictFixture(t)
	isInteractiveTerminalForTests = func() bool { return true }
	fleetStdinForTests = strings.NewReader("overwrite\n")
	defer func() { isInteractiveTerminalForTests = func() bool { return false }; fleetStdinForTests = nil }()

	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	if code != cli.ExitSuccess {
		t.Fatalf("exit code = %d, want %d; stderr: %s", code, cli.ExitSuccess, stderr.String())
	}
}

// TestRunFleetConflictInteractivePromptCancel covers an unrecognized
// answer (and, by the same code path, a blank one or a closed stdin):
// cancel is the only safe default — never silently resuming or
// overwriting real output on an ambiguous response.
func TestRunFleetConflictInteractivePromptCancel(t *testing.T) {
	args, _ := fleetConflictFixture(t)
	isInteractiveTerminalForTests = func() bool { return true }
	fleetStdinForTests = strings.NewReader("banana\n")
	defer func() { isInteractiveTerminalForTests = func() bool { return false }; fleetStdinForTests = nil }()

	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	if code != cli.ExitOperationalError {
		t.Fatalf("exit code = %d, want %d", code, cli.ExitOperationalError)
	}
	if !strings.Contains(stderr.String(), "cancelled") {
		t.Errorf("stderr = %q, want a cancellation message", stderr.String())
	}
}

// TestRunFleetConflictInteractivePromptEOFCancels confirms a closed/empty
// stdin (e.g. redirected from /dev/null despite a TTY-like stdin.Stat)
// cancels rather than blocking or defaulting to something destructive.
func TestRunFleetConflictInteractivePromptEOFCancels(t *testing.T) {
	args, _ := fleetConflictFixture(t)
	isInteractiveTerminalForTests = func() bool { return true }
	fleetStdinForTests = strings.NewReader("")
	defer func() { isInteractiveTerminalForTests = func() bool { return false }; fleetStdinForTests = nil }()

	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	if code != cli.ExitOperationalError {
		t.Fatalf("exit code = %d, want %d", code, cli.ExitOperationalError)
	}
}

// TestLoadFleetUpdateState is a unit test for
// docs/adr/0039-fleet-org-update.md's "read the previous complete run's own
// state" half, without any real clone or network: writes the same
// discovered-targets.json/fleet.json shape a real --org run would have
// left at --out, and checks both maps come from the committed aggregate.
// The discovery file intentionally carries different timestamps: it may
// belong to an interrupted newer run and must never authorize reuse.
func TestLoadFleetUpdateState(t *testing.T) {
	outDir := t.TempDir()
	discovered := `{"version":1,"targets":[
		{"name":"repo-a","git":{"url":"https://github.com/acme/repo-a.git"},"github":{"pushedAt":"1999-01-01T00:00:00Z"}},
		{"name":"repo-b","git":{"url":"https://github.com/acme/repo-b.git"},"github":{"pushedAt":"1999-02-02T00:00:00Z"}}
	]}`
	if err := os.WriteFile(filepath.Join(outDir, discoveredTargetsFilename), []byte(discovered), 0o644); err != nil {
		t.Fatal(err)
	}
	agg := fmt.Sprintf(`{"schemaVersion":"1.0","kind":"fleet","tool":"gin-recon","toolVersion":%q,"targets":[
		{"name":"repo-a","src":"","status":"ok","complete":true,"routes":5,"repository":{"pushedAt":"2026-01-01T00:00:00Z"}},
		{"name":"repo-b","src":"","status":"not-go-module","complete":true,"repository":{"pushedAt":"2026-02-02T00:00:00Z"}}
	],"repoAttempts":2,"repoTimeout":"10m0s","coverage":{"complete":true},"resume":{"requested":false,"reused":0,"checkpoint":false},"update":{"requested":false,"reused":0},"totals":{"routes":0,"proven":0,"public":0,"unknown":0},"authConfig":{"middlewareCount":0,"wrappersCount":0}}`, report.ToolVersion)
	if err := os.WriteFile(filepath.Join(outDir, fleetAggregateFilename), []byte(agg), 0o644); err != nil {
		t.Fatal(err)
	}

	var stderr bytes.Buffer
	pushedAt, results := loadFleetUpdateState(&cli.Options{OutDir: outDir, Update: true, RepoAttempts: 2, RepoTimeout: 10 * time.Minute}, &stderr)
	if pushedAt["repo-a"] != "2026-01-01T00:00:00Z" {
		t.Errorf("pushedAt[repo-a] = %q", pushedAt["repo-a"])
	}
	if pushedAt["repo-b"] != "2026-02-02T00:00:00Z" {
		t.Errorf("pushedAt[repo-b] = %q", pushedAt["repo-b"])
	}
	if results["repo-a"].Status != fleet.StatusOK || results["repo-a"].Routes != 5 {
		t.Errorf("results[repo-a] = %+v", results["repo-a"])
	}
	if results["repo-b"].Status != fleet.StatusNotGoModule {
		t.Errorf("results[repo-b] = %+v", results["repo-b"])
	}
}

// TestLoadFleetUpdateStateEmptyWithoutUpdate confirms the read is skipped
// entirely (not just empty by coincidence) when --update wasn't passed —
// matching Aggregate.Update.Requested's own "did the caller even ask"
// signal downstream.
func TestLoadFleetUpdateStateEmptyWithoutUpdate(t *testing.T) {
	outDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(outDir, discoveredTargetsFilename), []byte(`{"version":1,"targets":[{"name":"repo-a","github":{"pushedAt":"2026-01-01T00:00:00Z"}}]}`), 0o644); err != nil {
		t.Fatal(err)
	}

	var stderr bytes.Buffer
	pushedAt, results := loadFleetUpdateState(&cli.Options{OutDir: outDir, Update: false}, &stderr)
	if len(pushedAt) != 0 || len(results) != 0 {
		t.Errorf("pushedAt=%v results=%v, want both empty when --update wasn't passed", pushedAt, results)
	}
}

// TestLoadFleetUpdateStateRefusesReuseAcrossToolVersions is a regression
// test for docs/adr/0039-fleet-org-update.md's toolVersion safety check
// (matching a sibling tool's own real check, confirmed against its
// source): a previous run classified under a different toolVersion must
// never be silently reused — the classification rules that produced it
// may no longer be current.
func TestLoadFleetUpdateStateRefusesReuseAcrossToolVersions(t *testing.T) {
	outDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(outDir, discoveredTargetsFilename), []byte(`{"version":1,"targets":[{"name":"repo-a","github":{"pushedAt":"2026-01-01T00:00:00Z"}}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	agg := `{"tool":"gin-recon","toolVersion":"0.0.1-old","targets":[
		{"name":"repo-a","src":"","status":"ok","complete":true,"routes":5}
	],"coverage":{"complete":false},"resume":{"requested":false,"reused":0,"checkpoint":false},"update":{"requested":false,"reused":0},"totals":{"routes":0,"proven":0,"public":0,"unknown":0},"authConfig":{"middlewareCount":0,"wrappersCount":0}}`
	if err := os.WriteFile(filepath.Join(outDir, fleetAggregateFilename), []byte(agg), 0o644); err != nil {
		t.Fatal(err)
	}

	var stderr bytes.Buffer
	pushedAt, results := loadFleetUpdateState(&cli.Options{OutDir: outDir, Update: true}, &stderr)
	if len(pushedAt) != 0 || len(results) != 0 {
		t.Errorf("pushedAt=%v results=%v, want both empty across a toolVersion mismatch", pushedAt, results)
	}
	if !strings.Contains(stderr.String(), "toolVersion") {
		t.Errorf("stderr = %q, want a toolVersion-mismatch explanation", stderr.String())
	}
}

// TestLoadFleetUpdateStateRefusesReuseAcrossConfigChange is a regression
// test for a real gap: --update only ever checked toolVersion, never
// whether --config itself changed between the previous run and this one —
// a route's proven/public/unknown classification could silently stay
// stale under what's now an outdated auth config. Aggregate gained
// ConfigHash for exactly this comparison.
func TestLoadFleetUpdateStateRefusesReuseAcrossConfigChange(t *testing.T) {
	outDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(outDir, discoveredTargetsFilename), []byte(`{"version":1,"targets":[{"name":"repo-a","github":{"pushedAt":"2026-01-01T00:00:00Z"}}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	agg := fmt.Sprintf(`{"tool":"gin-recon","toolVersion":%q,"configHash":"old-hash","targets":[
		{"name":"repo-a","src":"","status":"ok","complete":true,"routes":5}
	],"coverage":{"complete":false},"resume":{"requested":false,"reused":0,"checkpoint":false},"update":{"requested":false,"reused":0},"totals":{"routes":0,"proven":0,"public":0,"unknown":0},"authConfig":{"middlewareCount":0,"wrappersCount":0}}`, report.ToolVersion)
	if err := os.WriteFile(filepath.Join(outDir, fleetAggregateFilename), []byte(agg), 0o644); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(outDir, "gin-recon.json")
	if err := os.WriteFile(cfgPath, []byte(`{"version":1}`), 0o644); err != nil {
		t.Fatal(err)
	}

	var stderr bytes.Buffer
	pushedAt, results := loadFleetUpdateState(&cli.Options{OutDir: outDir, Update: true, ConfigPath: cfgPath}, &stderr)
	if len(pushedAt) != 0 || len(results) != 0 {
		t.Errorf("pushedAt=%v results=%v, want both empty across a --config change", pushedAt, results)
	}
	if !strings.Contains(stderr.String(), "--config has changed") {
		t.Errorf("stderr = %q, want a --config-changed explanation", stderr.String())
	}
}

// TestLoadFleetUpdateStateRefusesReuseAcrossFormatChange mirrors the config
// test above for --format: the previous run's own artifacts may not cover
// a newly requested format (e.g. openapi added), so reuse must be refused,
// not silently missing what this run was actually asked to produce.
func TestLoadFleetUpdateStateRefusesReuseAcrossFormatChange(t *testing.T) {
	outDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(outDir, discoveredTargetsFilename), []byte(`{"version":1,"targets":[{"name":"repo-a","github":{"pushedAt":"2026-01-01T00:00:00Z"}}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	agg := fmt.Sprintf(`{"tool":"gin-recon","toolVersion":%q,"formats":["json"],"targets":[
		{"name":"repo-a","src":"","status":"ok","complete":true,"routes":5}
	],"coverage":{"complete":false},"resume":{"requested":false,"reused":0,"checkpoint":false},"update":{"requested":false,"reused":0},"totals":{"routes":0,"proven":0,"public":0,"unknown":0},"authConfig":{"middlewareCount":0,"wrappersCount":0}}`, report.ToolVersion)
	if err := os.WriteFile(filepath.Join(outDir, fleetAggregateFilename), []byte(agg), 0o644); err != nil {
		t.Fatal(err)
	}

	var stderr bytes.Buffer
	pushedAt, results := loadFleetUpdateState(&cli.Options{OutDir: outDir, Update: true, Formats: []cli.OutputFormat{cli.FormatJSON, cli.FormatOpenAPI}}, &stderr)
	if len(pushedAt) != 0 || len(results) != 0 {
		t.Errorf("pushedAt=%v results=%v, want both empty across a --format change", pushedAt, results)
	}
	if !strings.Contains(stderr.String(), "--format has changed") {
		t.Errorf("stderr = %q, want a --format-changed explanation", stderr.String())
	}
}

// TestShouldPreseedTargetRefusesWhenArtifactIsMissing is a regression test
// for a real gap: the previous-result-reuse decision trusted a StatusOK
// target's recorded Report path unchecked — someone deleting or moving
// --out's targets/<name> tree between runs (a partial cleanup, a moved
// artifact) must cause a rescan, not a "complete" result pointing at a
// routes.json that no longer exists.
func TestShouldPreseedTargetRefusesWhenArtifactIsMissing(t *testing.T) {
	outDir := t.TempDir()
	target := fleet.Target{Name: "repo-a", GitHub: &fleet.GitHubMeta{PushedAt: "2026-01-01T00:00:00Z"}}
	oldPushedAt := map[string]string{"repo-a": "2026-01-01T00:00:00Z"}
	reportRel := filepath.Join("targets", "repo-a", "routes.json")
	reportSum := sha256.Sum256([]byte(`{}`))
	oldResults := map[string]fleet.TargetResult{
		"repo-a": {
			Name: "repo-a", Status: fleet.StatusOK, Complete: true, Report: reportRel,
			SourceFingerprint: fleet.TargetFingerprint(target),
			Artifacts:         []fleet.Artifact{{Path: filepath.ToSlash(reportRel), Bytes: 2, SHA256: hex.EncodeToString(reportSum[:])}},
			Modules: []fleet.ModuleResult{{
				ID: "root", Path: ".", Kind: fleet.ModuleGo, Status: fleet.StatusOK, Complete: true,
				Report:    filepath.ToSlash(reportRel),
				Artifacts: []fleet.Artifact{{Path: filepath.ToSlash(reportRel), Bytes: 2, SHA256: hex.EncodeToString(reportSum[:])}},
			}},
		},
	}

	// The report file genuinely does not exist under outDir at all yet.
	if _, ok := shouldPreseedTarget(outDir, "", []string{"json"}, false, target, oldPushedAt, oldResults); ok {
		t.Fatal("shouldPreseedTarget = true with a missing routes.json, want false")
	}

	// Once the file is actually there, the identical inputs must reuse it.
	reportPath := filepath.Join(outDir, "targets", "repo-a", "routes.json")
	if err := os.MkdirAll(filepath.Dir(reportPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(reportPath, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := shouldPreseedTarget(outDir, "", []string{"json"}, false, target, oldPushedAt, oldResults); !ok {
		t.Error("shouldPreseedTarget = false with the routes.json present, want true")
	}
}

// TestShouldPreseedTargetRefusesWhenPushedAtChanged confirms the existing
// pushedAt-comparison behavior survives the shouldPreseedTarget refactor.
func TestShouldPreseedTargetRefusesWhenPushedAtChanged(t *testing.T) {
	target := fleet.Target{Name: "repo-a", GitHub: &fleet.GitHubMeta{PushedAt: "2026-02-02T00:00:00Z"}}
	oldPushedAt := map[string]string{"repo-a": "2026-01-01T00:00:00Z"}
	oldResults := map[string]fleet.TargetResult{
		"repo-a": {Name: "repo-a", Status: fleet.StatusOK, Report: filepath.Join("targets", "repo-a", "routes.json")},
	}
	if _, ok := shouldPreseedTarget(t.TempDir(), "", []string{"json"}, false, target, oldPushedAt, oldResults); ok {
		t.Error("shouldPreseedTarget = true despite pushedAt having changed, want false")
	}
}

// TestResolveFleetRepoManifestOwnerName is a unit test for
// docs/adr/0038-fleet-repo-shorthand.md's manifest construction, without a
// real network clone: an "owner/name" --repo value must produce a
// one-target manifest expanded against github.com, with --ref carried
// through as that target's git.ref.
func TestResolveFleetRepoManifestOwnerName(t *testing.T) {
	opts := &cli.Options{OutDir: "out", Repo: "smallcase/las-be-flow", Ref: "main"}
	var stderr bytes.Buffer

	manifestPath, manifest, manifestData, discoveryIncomplete, exitCode := resolveFleetRepoManifest(opts, &stderr)
	if exitCode != cli.ExitSuccess {
		t.Fatalf("exitCode = %d, want %d; stderr: %s", exitCode, cli.ExitSuccess, stderr.String())
	}
	if discoveryIncomplete {
		t.Error("discoveryIncomplete = true, want false")
	}
	if manifestPath == "" {
		t.Error("manifestPath is empty")
	}
	if len(manifestData) == 0 {
		t.Error("manifestData is empty")
	}
	if len(manifest.Targets) != 1 {
		t.Fatalf("Targets = %d, want 1", len(manifest.Targets))
	}
	target := manifest.Targets[0]
	if target.Name != "las-be-flow" {
		t.Errorf("Name = %q, want %q", target.Name, "las-be-flow")
	}
	if target.Git == nil || target.Git.URL != "https://github.com/smallcase/las-be-flow.git" {
		t.Errorf("Git = %+v, want URL https://github.com/smallcase/las-be-flow.git", target.Git)
	}
	if target.Git.Ref != "main" {
		t.Errorf("Ref = %q, want %q", target.Git.Ref, "main")
	}
}

// --targets run's own manifest and config are expected to already be
// version-controlled together, so nothing new needs to be written.
func TestRunFleetTargetsDoesNotWriteConfigSnapshot(t *testing.T) {
	fleetBinaryPathForTests = buildRealGinReconBinary(t)
	defer func() { fleetBinaryPathForTests = "" }()

	dir := t.TempDir()
	src := filepath.Join(dir, "repo-a")
	if err := os.CopyFS(src, os.DirFS(fixtureDir(t, "auth-wrappers"))); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "cfg.json")
	if err := os.WriteFile(cfgPath, []byte(`{"version":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(dir, "targets.json")
	manifest := fmt.Sprintf(`{"version":1,"targets":[{"name":"repo-a","src":%q}]}`, src)
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(dir, "out")

	var stdout, stderr bytes.Buffer
	code := run([]string{"fleet", "--targets", manifestPath, "--config", cfgPath, "--out", outDir}, &stdout, &stderr)
	if code != cli.ExitSuccess {
		t.Fatalf("exit code = %d, want %d; stderr: %s", code, cli.ExitSuccess, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(outDir, "config-snapshot.json")); !os.IsNotExist(err) {
		t.Errorf("config-snapshot.json should not exist for a --targets run, stat err = %v", err)
	}
}

// TestRunFleetTargetsWritesTargetConfigSnapshot is the real-world fix for a
// real incident: --target-config-dir's reviewed per-target authMiddleware
// configs — individually checked against source, real review work — lived
// only in an operator-owned directory outside the tool's own knowledge, and
// that directory was later wiped with nothing to recover it from. --out now
// gets its own durable copy, for --targets runs too, not just --org
// (unlike config-snapshot.json, which docs/adr/0025-fleet-org-config-snapshot.md
// deliberately scopes to --org alone).
// TestRunFleetSuggestAuthWritesUnreviewedTargetConfigDraft confirms
// fleet_target_config_draft.go's own actual behavior end to end: a target
// scanned with --suggest-auth and no real reviewed config gets a
// target-configs-draft/<name>.json listing its own nameHint candidates, and
// — the safety property this whole file exists for — that draft has zero
// effect on classification: the routes it names stay exactly as
// unauthenticated as they'd be with no draft at all, because
// --target-config-dir never reads from target-configs-draft/.
func TestRunFleetSuggestAuthWritesUnreviewedTargetConfigDraft(t *testing.T) {
	fleetBinaryPathForTests = buildRealGinReconBinary(t)
	defer func() { fleetBinaryPathForTests = "" }()

	dir := t.TempDir()
	src := filepath.Join(dir, "repo-a")
	if err := os.CopyFS(src, os.DirFS(fixtureDir(t, "auth-wrappers"))); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(dir, "targets.json")
	manifest := fmt.Sprintf(`{"version":1,"targets":[{"name":"repo-a","src":%q}]}`, src)
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(dir, "out")

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"fleet", "--targets", manifestPath, "--suggest-auth", "--out", outDir,
	}, &stdout, &stderr)
	if code != cli.ExitSuccess {
		t.Fatalf("exit code = %d, want %d; stderr: %s", code, cli.ExitSuccess, stderr.String())
	}

	draftData, err := os.ReadFile(filepath.Join(outDir, "target-configs-draft", "repo-a.json"))
	if err != nil {
		t.Fatalf("target-configs-draft/repo-a.json: %v", err)
	}
	var draft targetConfigDraft
	if err := json.Unmarshal(draftData, &draft); err != nil {
		t.Fatalf("decoding draft: %v", err)
	}
	if draft.Warning == "" {
		t.Error("draft._warning is empty, want an explicit unreviewed warning")
	}
	// LoggedAuth is itself a transparent wrapper (always calls through,
	// never a guard on its own) — inventory sees it as the outermost
	// registered symbol at every wrapped call site here, never the guard it
	// wraps, without an authWrappers config telling it to unwrap. That it
	// still surfaces as a nameHint candidate ("Auth" in the name) is exactly
	// the case a draft must be reviewed, not trusted: naming alone can't
	// tell a real guard from a wrapper that needs a different config key
	// entirely (authWrappers, not authMiddleware).
	const wantSymbol = "gin-recon-fixtures/auth-wrappers.LoggedAuth"
	if _, ok := draft.Candidates[wantSymbol]; !ok {
		t.Errorf("draft = %+v, want Candidates entry for %s", draft, wantSymbol)
	}

	// The safety property: the draft must never have been consulted for
	// classification — every route stays exactly as unauthenticated as a
	// run with no --target-config-dir at all would leave it.
	var agg fleet.Aggregate
	aggData, err := os.ReadFile(filepath.Join(outDir, "fleet.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(aggData, &agg); err != nil {
		t.Fatal(err)
	}
	if agg.Targets[0].Proven != 0 {
		t.Errorf("Proven = %d, want 0: an unreviewed draft must never affect classification", agg.Targets[0].Proven)
	}
}

func TestRunFleetTargetsWritesTargetConfigSnapshot(t *testing.T) {
	fleetBinaryPathForTests = buildRealGinReconBinary(t)
	defer func() { fleetBinaryPathForTests = "" }()

	dir := t.TempDir()
	src := filepath.Join(dir, "repo-a")
	if err := os.CopyFS(src, os.DirFS(fixtureDir(t, "auth-wrappers"))); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(dir, "targets.json")
	manifest := fmt.Sprintf(`{"version":1,"targets":[{"name":"repo-a","src":%q}]}`, src)
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	targetConfigDir := filepath.Join(dir, "target-configs")
	if err := os.MkdirAll(targetConfigDir, 0o755); err != nil {
		t.Fatal(err)
	}
	const targetCfgContent = `{"version":1,"authMiddleware":{}}`
	if err := os.WriteFile(filepath.Join(targetConfigDir, "repo-a.json"), []byte(targetCfgContent), 0o644); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(dir, "out")

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"fleet", "--targets", manifestPath, "--target-config-dir", targetConfigDir, "--out", outDir,
	}, &stdout, &stderr)
	if code != cli.ExitSuccess {
		t.Fatalf("exit code = %d, want %d; stderr: %s", code, cli.ExitSuccess, stderr.String())
	}

	got, err := os.ReadFile(filepath.Join(outDir, "target-configs-snapshot", "repo-a.json"))
	if err != nil {
		t.Fatalf("target-configs-snapshot/repo-a.json: %v", err)
	}
	if string(got) != targetCfgContent {
		t.Errorf("target-configs-snapshot/repo-a.json = %q, want %q", got, targetCfgContent)
	}
}

// TestRunFleetReusesPublishedTargetConfigSnapshotWithoutTargetConfigDir is
// the real fix for the actual complaint: --target-config-dir shouldn't need
// to be re-supplied, or ever manually recreated, on every run — once a
// reviewed config has been used and published to this --out's own
// target-configs-snapshot/, a later run at the same --out must keep
// applying it automatically even with --target-config-dir omitted entirely,
// and even after the original directory it came from is gone for good.
func TestRunFleetReusesPublishedTargetConfigSnapshotWithoutTargetConfigDir(t *testing.T) {
	fleetBinaryPathForTests = buildRealGinReconBinary(t)
	defer func() { fleetBinaryPathForTests = "" }()

	dir := t.TempDir()
	src := filepath.Join(dir, "repo-a")
	if err := os.CopyFS(src, os.DirFS(fixtureDir(t, "auth-wrappers"))); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(dir, "targets.json")
	manifest := fmt.Sprintf(`{"version":1,"targets":[{"name":"repo-a","src":%q}]}`, src)
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}

	// The directory this first run's --target-config-dir points at is
	// deliberately transient (its own t.TempDir(), gone once the subtest
	// ends) — proving the second run below cannot possibly still be reading
	// from it.
	targetConfigDir := t.TempDir()
	const targetCfgContent = `{"version":1,"authMiddleware":{"gin-recon-fixtures/auth-wrappers.RequireAuth":{"tags":["authenticated"]}},"authWrappers":["gin-recon-fixtures/auth-wrappers.LoggedAuth"]}`
	if err := os.WriteFile(filepath.Join(targetConfigDir, "repo-a.json"), []byte(targetCfgContent), 0o644); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(dir, "out")

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"fleet", "--targets", manifestPath, "--target-config-dir", targetConfigDir, "--out", outDir, "--force",
	}, &stdout, &stderr)
	if code != cli.ExitSuccess {
		t.Fatalf("first run exit code = %d, want %d; stderr: %s", code, cli.ExitSuccess, stderr.String())
	}
	var firstAgg fleet.Aggregate
	firstData, err := os.ReadFile(filepath.Join(outDir, "fleet.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(firstData, &firstAgg); err != nil {
		t.Fatal(err)
	}
	if !firstAgg.Targets[0].TargetConfigDir || firstAgg.Targets[0].Proven == 0 {
		t.Fatalf("first run target = %+v, want targetConfigDir=true with proven routes", firstAgg.Targets[0])
	}

	// Prove the original directory can genuinely never be read again.
	if err := os.RemoveAll(targetConfigDir); err != nil {
		t.Fatal(err)
	}

	stdout.Reset()
	stderr.Reset()
	code = run([]string{
		"fleet", "--targets", manifestPath, "--out", outDir, "--force",
	}, &stdout, &stderr)
	if code != cli.ExitSuccess {
		t.Fatalf("second run exit code = %d, want %d; stderr: %s", code, cli.ExitSuccess, stderr.String())
	}
	var secondAgg fleet.Aggregate
	secondData, err := os.ReadFile(filepath.Join(outDir, "fleet.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(secondData, &secondAgg); err != nil {
		t.Fatal(err)
	}
	if !secondAgg.Targets[0].TargetConfigDir || secondAgg.Targets[0].Proven == 0 {
		t.Fatalf("second run (no --target-config-dir) target = %+v, want targetConfigDir=true with proven routes carried forward from the published snapshot", secondAgg.Targets[0])
	}
}

// TestRunFleetDefaultsOutUnderGinReconDir is the CLI-level integration test
// for docs/adr/0028-gin-recon-default-output-directory.md: a bare
// `fleet --targets ...` with no --out at all creates .gin-recon/<manifest
// base name> (raw) and, with --render-html (docs/adr/0037-fleet-html-opt-in.md),
// its sibling .gin-recon/<manifest base name>-html/fleet.html (rendered),
// mirroring a sibling tool's own .express-recon/<org>/<org>-html
// convention.
func TestRunFleetDefaultsOutUnderGinReconDir(t *testing.T) {
	fleetBinaryPathForTests = buildRealGinReconBinary(t)
	defer func() { fleetBinaryPathForTests = "" }()

	root := t.TempDir()
	src := filepath.Join(root, "repo-a")
	if err := os.CopyFS(src, os.DirFS(fixtureDir(t, "auth-wrappers"))); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(root, "targets.json")
	manifest := fmt.Sprintf(`{"version":1,"targets":[{"name":"repo-a","src":%q}]}`, src)
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}

	origWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(origWD) }()

	var stdout, stderr bytes.Buffer
	code := run([]string{"fleet", "--targets", "targets.json", "--render-html"}, &stdout, &stderr)
	if code != cli.ExitSuccess {
		t.Fatalf("exit code = %d, want %d; stderr: %s", code, cli.ExitSuccess, stderr.String())
	}

	if _, err := os.Stat(filepath.Join(root, ".gin-recon", "targets", "fleet.json")); err != nil {
		t.Errorf("expected fleet.json under .gin-recon/targets: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, ".gin-recon", "targets-html", "fleet.html")); err != nil {
		t.Errorf("expected fleet.html under .gin-recon/targets-html: %v", err)
	}
}

// TestRunFleetOutDotNestsRenderedOutput is a regression test for a real bug
// found live-testing against a real org: `fleet --out .` (a realistic
// invocation — running from inside the directory meant to hold output) put
// fleet.html in a directory sibling to --out's own parent
// (docs/adr/0027-fleet-out-dot-nests-rendered-output.md) — for
// ~/Tools/fleet-out, that meant ~/Tools/fleet-out-html, escaping the
// directory the caller actually pointed --out at. --out "." should nest its
// rendered output inside itself instead — see fleetHTMLSibling's doc
// comment.
func TestRunFleetOutDotNestsRenderedOutput(t *testing.T) {
	fleetBinaryPathForTests = buildRealGinReconBinary(t)
	defer func() { fleetBinaryPathForTests = "" }()

	root := t.TempDir()
	src := filepath.Join(root, "repo-a")
	if err := os.CopyFS(src, os.DirFS(fixtureDir(t, "auth-wrappers"))); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(root, "fleet-out")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(outDir, "targets.json")
	manifest := fmt.Sprintf(`{"version":1,"targets":[{"name":"repo-a","src":%q}]}`, src)
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}

	origWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(outDir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(origWD) }()

	var stdout, stderr bytes.Buffer
	code := run([]string{"fleet", "--targets", "targets.json", "--out", ".", "--render-html"}, &stdout, &stderr)
	if code != cli.ExitSuccess {
		t.Fatalf("exit code = %d, want %d; stderr: %s", code, cli.ExitSuccess, stderr.String())
	}

	wantHTMLDir := filepath.Join(outDir, "html")
	if _, err := os.Stat(filepath.Join(wantHTMLDir, "fleet.html")); err != nil {
		t.Fatalf("expected fleet.html nested under --out at %s: %v", wantHTMLDir, err)
	}
	if _, err := os.Stat(filepath.Join(root, "fleet-out-html")); !os.IsNotExist(err) {
		t.Errorf("rendered output escaped --out into a sibling of its parent, stat err = %v", err)
	}

	htmlData, err := os.ReadFile(filepath.Join(wantHTMLDir, "fleet.html"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(htmlData), `href="../."`) {
		t.Errorf("fleet.html links back to --out's parent instead of --out itself: %s", htmlData)
	}
	if !strings.Contains(string(htmlData), "../targets/") {
		t.Errorf("fleet.html should link back to --out via ../targets/, got: %s", htmlData)
	}
}

// TestRunFleetRenderAddsFormatWithoutRescanning is the CLI-level
// integration test for docs/adr/0024-fleet-render.md's central claim:
// render, over a fleet.json a prior fleet run already produced,
// retroactively adds a format (openapi) to every target and regenerates
// fleet.html — entirely from already-computed evidence, without ever
// touching the original source tree again. Proven here the same way the
// single-report render test proves it: by moving the source tree away
// before running render at all.
// TestRunFleetPopulatesAuthConfigAndProvenFromRealConfig is a regression
// test for docs/adr/0030-fleet-html-auth-config-visibility.md, built after
// a real --org run against smallcase showed Totals.Proven = 0 across every
// target. That was correct given the --config actually used (no
// authMiddleware entries at all, only fleet.allowedRemoteHosts) — this test
// proves the other half: a real --config naming real authMiddleware/
// authWrappers symbols does populate Aggregate.AuthConfig and does produce
// a non-zero Proven count, using the auth-wrappers fixture's own known
// expected classification (3 of its 6 routes are proven).
func TestRunFleetPopulatesAuthConfigAndProvenFromRealConfig(t *testing.T) {
	fleetBinaryPathForTests = buildRealGinReconBinary(t)
	defer func() { fleetBinaryPathForTests = "" }()

	root := t.TempDir()
	src := filepath.Join(root, "repo-a")
	if err := os.CopyFS(src, os.DirFS(fixtureDir(t, "auth-wrappers"))); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(root, "cfg.json")
	cfg := `{
		"version": 1,
		"analysis": {"followModules": ["gin-recon-fixtures/**"]},
		"authMiddleware": {
			"gin-recon-fixtures/auth-wrappers.RequireAuth": {"assurance": "analyze"},
			"gin-recon-fixtures/auth-wrappers.RequireAuthContradicted": {"assurance": "analyze"},
			"gin-recon-fixtures/auth-wrappers.RequireRoleFactory": {"assurance": "analyze"}
		},
		"authWrappers": ["gin-recon-fixtures/auth-wrappers.LoggedAuth"]
	}`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(root, "targets.json")
	manifest := fmt.Sprintf(`{"version":1,"targets":[{"name":"repo-a","src":%q}]}`, src)
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(root, "out")

	var stdout, stderr bytes.Buffer
	code := run([]string{"fleet", "--targets", manifestPath, "--config", cfgPath, "--out", outDir, "--allow-downloads", "--render-html"}, &stdout, &stderr)
	if code != cli.ExitSuccess {
		t.Fatalf("fleet exit code = %d, want %d; stderr: %s", code, cli.ExitSuccess, stderr.String())
	}

	var agg fleet.Aggregate
	aggData, err := os.ReadFile(filepath.Join(outDir, "fleet.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(aggData, &agg); err != nil {
		t.Fatal(err)
	}
	if agg.AuthConfig.MiddlewareCount != 3 {
		t.Errorf("AuthConfig.MiddlewareCount = %d, want 3", agg.AuthConfig.MiddlewareCount)
	}
	if agg.AuthConfig.WrappersCount != 1 {
		t.Errorf("AuthConfig.WrappersCount = %d, want 1", agg.AuthConfig.WrappersCount)
	}
	if agg.FollowModulesCount != 1 {
		t.Errorf("FollowModulesCount = %d, want 1", agg.FollowModulesCount)
	}
	if agg.Targets[0].Proven == 0 {
		t.Error("Targets[0].Proven = 0, want non-zero: this fixture has proven routes under this exact config")
	}
	if agg.Totals.Proven != agg.Targets[0].Proven {
		t.Errorf("Totals.Proven = %d, want %d", agg.Totals.Proven, agg.Targets[0].Proven)
	}

	htmlData, err := os.ReadFile(filepath.Join(outDir+"-html", "fleet.html"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(htmlData), "No <code>authMiddleware</code> configured") {
		t.Errorf("fleet.html should not warn about missing authMiddleware when 3 were configured:\n%s", htmlData)
	}
}

// TestRunFleetUsesTargetOwnConfigEndToEnd is the CLI-level integration test
// for docs/adr/0031-fleet-per-target-config.md: --use-target-config lets a
// fleet scan pick up a target's own committed config
// (.gin-recon-reconcile-config.json, the real filename already used by
// several repositories in the org this was built for) with no shared
// TestRunFleetUsesTargetConfigDirEndToEnd is the CLI-level integration test
// for docs/adr/0033-fleet-target-config-dir.md: --target-config-dir gets a
// target real proven classification via a config file that lives entirely
// outside the scanned repository — no commit, no push, no PR into the
// target's own repo required, unlike --use-target-config.
func TestRunFleetUsesTargetConfigDirEndToEnd(t *testing.T) {
	fleetBinaryPathForTests = buildRealGinReconBinary(t)
	defer func() { fleetBinaryPathForTests = "" }()

	root := t.TempDir()
	src := filepath.Join(root, "repo-a")
	if err := os.CopyFS(src, os.DirFS(fixtureDir(t, "auth-wrappers"))); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(root, "targets.json")
	manifest := fmt.Sprintf(`{"version":1,"targets":[{"name":"repo-a","src":%q}]}`, src)
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}

	targetConfigDir := filepath.Join(root, "operator-configs")
	if err := os.MkdirAll(targetConfigDir, 0o755); err != nil {
		t.Fatal(err)
	}
	ownConfig := `{
		"version": 1,
		"authMiddleware": {
			"gin-recon-fixtures/auth-wrappers.RequireAuth": {"assurance": "analyze"},
			"gin-recon-fixtures/auth-wrappers.RequireAuthContradicted": {"assurance": "analyze"},
			"gin-recon-fixtures/auth-wrappers.RequireRoleFactory": {"assurance": "analyze"}
		},
		"authWrappers": ["gin-recon-fixtures/auth-wrappers.LoggedAuth"]
	}`
	if err := os.WriteFile(filepath.Join(targetConfigDir, "repo-a.json"), []byte(ownConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(root, "out")

	var stdout, stderr bytes.Buffer
	code := run([]string{"fleet", "--targets", manifestPath, "--out", outDir, "--allow-downloads", "--target-config-dir", targetConfigDir}, &stdout, &stderr)
	if code != cli.ExitSuccess {
		t.Fatalf("fleet exit code = %d, want %d; stderr: %s", code, cli.ExitSuccess, stderr.String())
	}

	var agg fleet.Aggregate
	aggData, err := os.ReadFile(filepath.Join(outDir, "fleet.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(aggData, &agg); err != nil {
		t.Fatal(err)
	}
	if !agg.Targets[0].TargetConfigDir {
		t.Error("Targets[0].TargetConfigDir = false, want true")
	}
	if agg.Targets[0].Proven == 0 {
		t.Error("Targets[0].Proven = 0, want non-zero: classified via --target-config-dir with no --config at all")
	}

	// The whole point: nothing under src (the scanned repository) was ever
	// touched or read for config purposes.
	if _, err := os.Stat(filepath.Join(src, ".gin-recon-reconcile-config.json")); !os.IsNotExist(err) {
		t.Error("no config file should exist inside the scanned repository itself")
	}
}

// --config at all, and get the same real proven classification a direct
// `audit --config <that file>` invocation of that one repository would.
func TestRunFleetUsesTargetOwnConfigEndToEnd(t *testing.T) {
	fleetBinaryPathForTests = buildRealGinReconBinary(t)
	defer func() { fleetBinaryPathForTests = "" }()

	root := t.TempDir()
	src := filepath.Join(root, "repo-a")
	if err := os.CopyFS(src, os.DirFS(fixtureDir(t, "auth-wrappers"))); err != nil {
		t.Fatal(err)
	}
	ownConfig := `{
		"version": 1,
		"authMiddleware": {
			"gin-recon-fixtures/auth-wrappers.RequireAuth": {"assurance": "analyze"},
			"gin-recon-fixtures/auth-wrappers.RequireAuthContradicted": {"assurance": "analyze"},
			"gin-recon-fixtures/auth-wrappers.RequireRoleFactory": {"assurance": "analyze"}
		},
		"authWrappers": ["gin-recon-fixtures/auth-wrappers.LoggedAuth"]
	}`
	if err := os.WriteFile(filepath.Join(src, ".gin-recon-reconcile-config.json"), []byte(ownConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(root, "targets.json")
	manifest := fmt.Sprintf(`{"version":1,"targets":[{"name":"repo-a","src":%q}]}`, src)
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(root, "out")

	var stdout, stderr bytes.Buffer
	code := run([]string{"fleet", "--targets", manifestPath, "--out", outDir, "--allow-downloads", "--use-target-config", "--render-html"}, &stdout, &stderr)
	if code != cli.ExitSuccess {
		t.Fatalf("fleet exit code = %d, want %d; stderr: %s", code, cli.ExitSuccess, stderr.String())
	}

	var agg fleet.Aggregate
	aggData, err := os.ReadFile(filepath.Join(outDir, "fleet.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(aggData, &agg); err != nil {
		t.Fatal(err)
	}
	if !agg.Targets[0].TargetConfig {
		t.Error("Targets[0].TargetConfig = false, want true: repo-a committed its own config")
	}
	if agg.Targets[0].Proven == 0 {
		t.Error("Targets[0].Proven = 0, want non-zero: this fixture is proven under its own committed config, with no shared --config at all")
	}

	htmlData, err := os.ReadFile(filepath.Join(outDir+"-html", "fleet.html"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(htmlData), "own config (repo)</span>") {
		t.Errorf("fleet.html should show the own-config badge for repo-a:\n%s", htmlData)
	}
}

// TestRunFleetRenderRefreshesRouteEvidenceCounts is a regression test for
// docs/adr/0028-gin-recon-default-output-directory.md's fleet.html
// redesign: a fleet.json written before Routes/Proven/Public/Unknown
// existed (simulated here by zeroing them out by hand) gets them
// backfilled — from each target's own already-computed routes.json, no
// rescan — the next time it's rendered.
func TestRunFleetRenderRefreshesRouteEvidenceCounts(t *testing.T) {
	fleetBinaryPathForTests = buildRealGinReconBinary(t)
	defer func() { fleetBinaryPathForTests = "" }()

	root := t.TempDir()
	src := filepath.Join(root, "repo-a")
	if err := os.CopyFS(src, os.DirFS(fixtureDir(t, "auth-wrappers"))); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(root, "targets.json")
	manifest := fmt.Sprintf(`{"version":1,"targets":[{"name":"repo-a","src":%q}]}`, src)
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(root, "out")

	var stdout, stderr bytes.Buffer
	code := run([]string{"fleet", "--targets", manifestPath, "--out", outDir}, &stdout, &stderr)
	if code != cli.ExitSuccess {
		t.Fatalf("fleet exit code = %d, want %d; stderr: %s", code, cli.ExitSuccess, stderr.String())
	}

	fleetJSONPath := filepath.Join(outDir, "fleet.json")
	var agg fleet.Aggregate
	aggData, err := os.ReadFile(fleetJSONPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(aggData, &agg); err != nil {
		t.Fatal(err)
	}
	if agg.Targets[0].Routes == 0 {
		t.Fatal("test setup: fixture reported zero routes, nothing to zero out")
	}

	// Simulate a fleet.json written before this field existed.
	agg.Targets[0].Routes, agg.Targets[0].Proven, agg.Targets[0].Public, agg.Targets[0].Unknown = 0, 0, 0, 0
	agg.Totals.Routes, agg.Totals.Proven, agg.Totals.Public, agg.Totals.Unknown = 0, 0, 0, 0
	agg.RepositoryGroups = nil
	staleData, err := json.MarshalIndent(&agg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fleetJSONPath, staleData, 0o644); err != nil {
		t.Fatal(err)
	}

	stdout.Reset()
	stderr.Reset()
	code = run([]string{"render", "--report", fleetJSONPath, "--force"}, &stdout, &stderr)
	if code != cli.ExitSuccess {
		t.Fatalf("fleet render exit code = %d, want %d; stderr: %s", code, cli.ExitSuccess, stderr.String())
	}

	refreshedData, err := os.ReadFile(fleetJSONPath)
	if err != nil {
		t.Fatal(err)
	}
	var refreshed fleet.Aggregate
	if err := json.Unmarshal(refreshedData, &refreshed); err != nil {
		t.Fatal(err)
	}
	if refreshed.Targets[0].Routes == 0 {
		t.Error("render did not refresh the target's Routes count")
	}
	if refreshed.Totals.Routes != refreshed.Targets[0].Routes {
		t.Errorf("Totals.Routes = %d, want %d (recomputed from the refreshed target)", refreshed.Totals.Routes, refreshed.Targets[0].Routes)
	}
	wantGroups := fleet.GroupRepositories(refreshed.Targets)
	if !reflect.DeepEqual(refreshed.RepositoryGroups, wantGroups) {
		t.Errorf("RepositoryGroups = %#v, want recomputed %#v", refreshed.RepositoryGroups, wantGroups)
	}
}

func TestRunFleetRenderAddsFormatWithoutRescanning(t *testing.T) {
	fleetBinaryPathForTests = buildRealGinReconBinary(t)
	defer func() { fleetBinaryPathForTests = "" }()

	root := t.TempDir()
	src := filepath.Join(root, "repo-a")
	if err := os.CopyFS(src, os.DirFS(fixtureDir(t, "auth-wrappers"))); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(root, "targets.json")
	manifest := fmt.Sprintf(`{"version":1,"targets":[{"name":"repo-a","src":%q}]}`, src)
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(root, "out")

	var stdout, stderr bytes.Buffer
	code := run([]string{"fleet", "--targets", manifestPath, "--out", outDir, "--allow-downloads"}, &stdout, &stderr)
	if code != cli.ExitSuccess {
		t.Fatalf("fleet exit code = %d, want %d; stderr: %s", code, cli.ExitSuccess, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(outDir+"-html", "targets", "repo-a", "api.html")); !os.IsNotExist(err) {
		t.Fatal("api.html should not exist yet: the original fleet run only requested --format json")
	}

	// The whole point: the source tree is gone by the time render runs.
	if err := os.RemoveAll(src); err != nil {
		t.Fatal(err)
	}

	stdout.Reset()
	stderr.Reset()
	code = run([]string{"render", "--report", filepath.Join(outDir, "fleet.json"), "--format", "json,openapi", "--out", outDir, "--force"}, &stdout, &stderr)
	if code != cli.ExitSuccess {
		t.Fatalf("fleet render exit code = %d, want %d; stderr: %s", code, cli.ExitSuccess, stderr.String())
	}

	htmlOutDir := outDir + "-html"
	if _, err := os.Stat(filepath.Join(htmlOutDir, "fleet.html")); err != nil {
		t.Errorf("fleet.html was not (re)written: %v", err)
	}
	apiHTMLPath := filepath.Join(htmlOutDir, "targets", "repo-a", "api.html")
	if _, err := os.Stat(apiHTMLPath); err != nil {
		t.Errorf("api.html was not produced by the render pass: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outDir, "targets", "repo-a", "openapi.json")); err != nil {
		t.Errorf("openapi.json (raw evidence) should exist in --out: %v", err)
	}

	fleetHTML, err := os.ReadFile(filepath.Join(htmlOutDir, "fleet.html"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(fleetHTML), `href="targets/repo-a/api.html"`) {
		t.Errorf("fleet.html does not link to the newly-rendered api.html:\n%s", fleetHTML)
	}

	// fleet.json itself must reflect the new link too, not just fleet.html
	// — see runFleetRender's own comment on why this write exists.
	aggData, err := os.ReadFile(filepath.Join(outDir, "fleet.json"))
	if err != nil {
		t.Fatal(err)
	}
	var agg struct {
		Targets []struct {
			Name    string `json:"name"`
			APIHTML string `json:"apiHtml"`
		} `json:"targets"`
	}
	if err := json.Unmarshal(aggData, &agg); err != nil {
		t.Fatal(err)
	}
	if len(agg.Targets) != 1 || agg.Targets[0].APIHTML != filepath.Join("targets", "repo-a", "api.html") {
		t.Errorf("fleet.json targets = %+v, want repo-a.apiHtml = targets/repo-a/api.html", agg.Targets)
	}
}

func TestRunFleetRenderHandlesEveryModule(t *testing.T) {
	rawDir := t.TempDir()
	moduleIDs := []string{"module-0123456789abcdef", "module-fedcba9876543210"}
	modules := make([]fleet.ModuleResult, 0, len(moduleIDs))
	for index, id := range moduleIDs {
		rel := filepath.Join("targets", "monorepo", "modules", id, "routes.json")
		path := filepath.Join(rawDir, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		rep := report.NewInventoryReport(model.ProfileTyped, report.Target{Module: fmt.Sprintf("example.com/module%d", index)})
		rep.ScanCoverage.Complete = true
		data, err := json.Marshal(rep)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
		modules = append(modules, fleet.ModuleResult{
			ID: id, Path: fmt.Sprintf("services/%d", index), ModulePath: fmt.Sprintf("example.com/module%d", index),
			Kind: fleet.ModuleGo, Status: fleet.StatusOK, Complete: true, Report: filepath.ToSlash(rel),
		})
	}
	agg := fleet.Aggregate{SchemaVersion: "1.0", Kind: "fleet", Tool: "gin-recon", ToolVersion: report.ToolVersion}
	agg.Coverage.Complete = true
	agg.Targets = []fleet.TargetResult{{
		Name: "monorepo", Status: fleet.StatusOK, Complete: true,
		Inventory: fleet.RepositoryInventory{Kind: fleet.RepositoryMultiModule, Complete: true, Modules: 2}, Modules: modules,
	}}
	aggData, err := json.Marshal(&agg)
	if err != nil {
		t.Fatal(err)
	}
	fleetPath := filepath.Join(rawDir, fleetAggregateFilename)
	if err := os.WriteFile(fleetPath, aggData, 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"render", "--report", fleetPath, "--format", "openapi", "--out", rawDir, "--force"}, &stdout, &stderr)
	if code != cli.ExitSuccess {
		t.Fatalf("exit code = %d; stderr: %s", code, stderr.String())
	}

	refreshedData, err := os.ReadFile(fleetPath)
	if err != nil {
		t.Fatal(err)
	}
	var refreshed fleet.Aggregate
	if err := json.Unmarshal(refreshedData, &refreshed); err != nil {
		t.Fatal(err)
	}
	if len(refreshed.Targets[0].Modules) != 2 {
		t.Fatalf("modules = %+v", refreshed.Targets[0].Modules)
	}
	htmlDir := rawDir + "-html"
	for _, module := range refreshed.Targets[0].Modules {
		if module.APIHTML == "" || len(module.Artifacts) != 3 {
			t.Fatalf("module render metadata = %+v, want apiHtml plus json/openapi/html integrity", module)
		}
		if _, err := os.Stat(filepath.Join(htmlDir, filepath.FromSlash(module.APIHTML))); err != nil {
			t.Fatalf("module HTML %s missing: %v", module.APIHTML, err)
		}
	}
}

// TestRunFleetRenderDefaultsOutToReportDir is a regression test for
// docs/adr/0028-gin-recon-default-output-directory.md: a fleet render no
// longer requires --out — omitting it re-renders in place, into --report's
// own directory (the raw root a live fleet run would have used), so
// `render --report .gin-recon/<org>/fleet.json --force` alone regenerates
// the sibling .gin-recon/<org>-html/ with no --out needed. --force is
// still required regardless (unchanged, a fleet render always overwrites).
func TestRunFleetRenderDefaultsOutToReportDir(t *testing.T) {
	fleetBinaryPathForTests = buildRealGinReconBinary(t)
	defer func() { fleetBinaryPathForTests = "" }()

	root := t.TempDir()
	manifestPath := filepath.Join(root, "targets.json")
	manifest := fmt.Sprintf(`{"version":1,"targets":[{"name":"repo-a","src":%q}]}`, fixtureDir(t, "auth-wrappers"))
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(root, "out")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"fleet", "--targets", manifestPath, "--out", outDir, "--allow-downloads"}, &stdout, &stderr); code != cli.ExitSuccess {
		t.Fatalf("fleet exit code = %d; stderr: %s", code, stderr.String())
	}

	reportPath := filepath.Join(outDir, "fleet.json")

	stdout.Reset()
	stderr.Reset()
	code := run([]string{"render", "--report", reportPath, "--format", "json"}, &stdout, &stderr)
	if code != cli.ExitOperationalError {
		t.Errorf("exit code without --force = %d, want %d", code, cli.ExitOperationalError)
	}
	if !strings.Contains(stderr.String(), "--force is required") {
		t.Errorf("stderr = %q, want it to explain --force is required", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = run([]string{"render", "--report", reportPath, "--format", "json", "--force"}, &stdout, &stderr)
	if code != cli.ExitSuccess {
		t.Fatalf("render exit code = %d, want %d; stderr: %s", code, cli.ExitSuccess, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(outDir+"-html", "fleet.html")); err != nil {
		t.Errorf("expected fleet.html under the default sibling dir %s: %v", outDir+"-html", err)
	}
}

func TestRunFleetRenderRequiresForce(t *testing.T) {
	fleetBinaryPathForTests = buildRealGinReconBinary(t)
	defer func() { fleetBinaryPathForTests = "" }()

	root := t.TempDir()
	manifestPath := filepath.Join(root, "targets.json")
	manifest := fmt.Sprintf(`{"version":1,"targets":[{"name":"repo-a","src":%q}]}`, fixtureDir(t, "auth-wrappers"))
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(root, "out")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"fleet", "--targets", manifestPath, "--out", outDir, "--allow-downloads"}, &stdout, &stderr); code != cli.ExitSuccess {
		t.Fatalf("fleet exit code = %d; stderr: %s", code, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code := run([]string{"render", "--report", filepath.Join(outDir, "fleet.json"), "--format", "json", "--out", outDir}, &stdout, &stderr)
	if code != cli.ExitOperationalError {
		t.Errorf("exit code = %d, want %d", code, cli.ExitOperationalError)
	}
	if !strings.Contains(stderr.String(), "--force is required") {
		t.Errorf("stderr = %q, want it to explain --force is required", stderr.String())
	}
}

// TestRunFleetRenderRejectsPathTraversalTargetName is a regression test for
// a real path-traversal write: --report is an arbitrary file (someone else's
// fleet.json, a CI artifact, anything), and before this fix its targets'
// Name field was used to build both a read path (routes.json) and a write
// path (this target's own re-rendered output directory) with no validation
// at all — a crafted name like "../../../../tmp/..." would write gin-recon's
// own report files outside --out entirely.
func TestRunFleetRenderRejectsPathTraversalTargetName(t *testing.T) {
	root := t.TempDir()
	outDir := filepath.Join(root, "out")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatal(err)
	}
	escapeTarget := filepath.Join(root, "escaped")
	maliciousName := "../../escaped"
	reportPath := filepath.Join(outDir, "fleet.json")
	fleetJSON := fmt.Sprintf(`{"targets":[{"name":%q,"status":"ok"}]}`, maliciousName)
	if err := os.WriteFile(reportPath, []byte(fleetJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"render", "--report", reportPath, "--format", "json", "--force"}, &stdout, &stderr)
	if code != cli.ExitOperationalError {
		t.Fatalf("exit code = %d, want %d; stderr: %s", code, cli.ExitOperationalError, stderr.String())
	}
	if !strings.Contains(stderr.String(), "must match") {
		t.Errorf("stderr = %q, want it to reject the invalid target name", stderr.String())
	}
	if _, err := os.Stat(escapeTarget); err == nil {
		t.Fatalf("target escaped --out: %s was created", escapeTarget)
	}
}

// TestRunFleetRenderRejectsDuplicateTargetNames is a regression test for two
// targets silently clobbering the same output directory — a crafted or
// corrupted fleet.json listing the same target name twice must be refused
// outright, not processed with the second target's output overwriting the
// first's.
func TestRunFleetRenderRejectsDuplicateTargetNames(t *testing.T) {
	root := t.TempDir()
	outDir := filepath.Join(root, "out")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(outDir, "fleet.json")
	fleetJSON := `{"targets":[{"name":"repo-a","status":"ok"},{"name":"repo-a","status":"ok"}]}`
	if err := os.WriteFile(reportPath, []byte(fleetJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"render", "--report", reportPath, "--format", "json", "--force"}, &stdout, &stderr)
	if code != cli.ExitOperationalError {
		t.Fatalf("exit code = %d, want %d; stderr: %s", code, cli.ExitOperationalError, stderr.String())
	}
	if !strings.Contains(stderr.String(), "duplicate target name") {
		t.Errorf("stderr = %q, want it to reject the duplicate target name", stderr.String())
	}
}

func TestIsFleetAggregateJSON(t *testing.T) {
	if !isFleetAggregateJSON([]byte(`{"tool":"gin-recon","targets":[{"name":"a"}]}`)) {
		t.Error("a fleet aggregate (targets array, no schemaVersion) should be detected")
	}
	if isFleetAggregateJSON([]byte(`{"schemaVersion":"1.0","routes":[]}`)) {
		t.Error("an ordinary report.Report (schemaVersion present) should not be detected as a fleet aggregate")
	}
	if isFleetAggregateJSON([]byte(`not json`)) {
		t.Error("malformed JSON should not be detected as a fleet aggregate")
	}
}
