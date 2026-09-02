package analyzer

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sagnikhaldar/gin-recon/internal/config"
)

func loadAndAuditSyntax(t *testing.T, fixture string, cfg *config.Config) *AuditResult {
	t.Helper()
	loaded, err := LoadSyntax(context.Background(), syntaxOpts(fixtureDir(t, fixture)))
	if err != nil {
		t.Fatalf("LoadSyntax(%s): %v", fixture, err)
	}
	if cfg == nil {
		cfg = &config.Config{Version: 1}
	}
	return AuditSyntax(loaded, cfg, time.Now())
}

// TestAuditSyntaxEngineSecurityFindingsMatchTypedAndAreRelativized mirrors
// TestAuditEngineSecurityFindingsAndDiagnosticsAreRelativized for the
// syntax-only path: the same fixture must produce the same engine-security
// findings/diagnostics (see
// gin.TestAnalyzeEngineSecuritySyntaxMatchesFixtureManifest for the
// lower-level proof), with root-relative, slash-separated source paths.
func TestAuditSyntaxEngineSecurityFindingsMatchTypedAndAreRelativized(t *testing.T) {
	result := loadAndAuditSyntax(t, "engine-security", nil)

	sawEngineFinding := false
	for _, f := range result.Findings {
		if f.RuleID != "gin-explicit-trust-all-proxies" && f.RuleID != "gin-explicit-debug-mode" {
			continue
		}
		sawEngineFinding = true
		if f.Source == nil {
			t.Errorf("finding %s has no Source", f.RuleID)
			continue
		}
		if filepath.IsAbs(f.Source.File) {
			t.Errorf("finding %s Source.File = %q, want a root-relative path, not absolute", f.RuleID, f.Source.File)
		}
		if strings.Contains(f.Source.File, "\\") {
			t.Errorf("finding %s Source.File = %q, want slash-separated", f.RuleID, f.Source.File)
		}
	}
	if !sawEngineFinding {
		t.Fatal("expected at least one gin-explicit-trust-all-proxies or gin-explicit-debug-mode finding")
	}

	sawEngineDiagnostic := false
	for _, d := range result.Diagnostics {
		if d.Code != "gin-unresolved-trusted-proxies" && d.Code != "gin-unresolved-mode" {
			continue
		}
		sawEngineDiagnostic = true
		if d.Source != nil && filepath.IsAbs(d.Source.File) {
			t.Errorf("diagnostic %s Source.File = %q, want a root-relative path, not absolute", d.Code, d.Source.File)
		}
	}
	if !sawEngineDiagnostic {
		t.Fatal("expected at least one gin-unresolved-trusted-proxies or gin-unresolved-mode diagnostic")
	}
}

func fixtureConfigForModule(module, symbol string) *config.Config {
	return &config.Config{
		Version: 1,
		AuthMiddleware: map[string]config.AuthMiddlewareEntry{
			module + "." + symbol: {Assurance: config.AssuranceAnalyze},
		},
	}
}

// TestAuditSyntaxNeverEmitsProvenOrStaleAuthConfig locks in the two security
// invariants AuditSyntax exists to preserve even with a real authMiddleware
// config present: no route can classify proven (no canonical symbol ever
// resolves), and stale-auth-config must not spuriously fire for a symbol
// that is genuinely present in the source but simply unverifiable under
// this profile.
func TestAuditSyntaxNeverEmitsProvenOrStaleAuthConfig(t *testing.T) {
	cfg := fixtureConfigForModule("gin-recon-fixtures/middleware-order", "RequireAuth")
	result := loadAndAuditSyntax(t, "middleware-order", cfg)

	if result.Summary.ProvenByConfirmedShape != 0 || result.Summary.ProvenByAttestedUnresolved != 0 {
		t.Errorf("Summary = %+v, want zero proven routes under syntax-only", result.Summary)
	}
	for _, f := range result.Findings {
		if f.RuleID == "stale-auth-config" {
			t.Errorf("unexpected stale-auth-config finding: %+v", f)
		}
	}
	foundDiagnostic := false
	for _, d := range result.Diagnostics {
		if d.Code == "gin-syntax-auth-config-unverifiable" {
			foundDiagnostic = true
		}
	}
	if !foundDiagnostic {
		t.Errorf("expected a gin-syntax-auth-config-unverifiable diagnostic, got: %+v", result.Diagnostics)
	}
}
