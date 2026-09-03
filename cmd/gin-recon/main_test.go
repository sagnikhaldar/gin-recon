package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sagnikhaldar/gin-recon/internal/cli"
)

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
// docs/cli-contract.md says "suggest-auth writes JSON to stdout unless --out
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
// exit 1 docs/report-contract.md requires for "Fatal inability to load the
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
	// schema does not register --src at all (docs/cli-contract.md: "accepts
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
// docs/cli-contract.md's "SARIF is audit-only" — cli.Validate must still
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
// docs/report-contract.md's baseline compatibility requirement.
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
		body, _ := json.Marshal([]map[string]string{
			{"name": "repo-a", "clone_url": repoURL, "default_branch": "main"},
			{"name": "repo-b", "clone_url": repoURL, "default_branch": "main"},
			{"name": "repo-c", "clone_url": repoURL, "default_branch": "main"},
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
