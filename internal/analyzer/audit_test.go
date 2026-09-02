package analyzer

import (
	"context"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/sagnikhaldar/gin-recon/internal/config"
	"github.com/sagnikhaldar/gin-recon/internal/model"
)

func loadAndAudit(t *testing.T, fixture string, cfg *config.Config) *AuditResult {
	t.Helper()
	loaded, err := Load(context.Background(), LoadOptions{
		Src:            fixtureDir(t, fixture),
		GOOS:           runtime.GOOS,
		GOARCH:         runtime.GOARCH,
		ModuleMode:     model.ModuleReadonly,
		AllowDownloads: true,
	})
	if err != nil {
		t.Fatalf("Load(%s): %v", fixture, err)
	}
	if len(loaded.LoadErrors) != 0 {
		t.Fatalf("Load(%s) reported load errors: %+v", fixture, loaded.LoadErrors)
	}
	if cfg == nil {
		cfg = &config.Config{Version: 1}
	}
	return Audit(loaded, cfg, time.Now())
}

// TestAuditEngineSecurityFindingsAndDiagnosticsAreRelativized is the
// regression test for a real bug found by running gin-recon against a
// production repository: engineSecurityFindings (docs/gin-security-rules.md's
// gin-explicit-trust-all-proxies / gin-explicit-debug-mode rules, plus their
// gin-unresolved-* diagnostics) runs in Audit after discover's own
// relativizeSources pass already completed, so — before this fix — every
// finding and diagnostic it produced still carried the absolute checkout
// path go/packages' Fset naturally produces, violating docs/cli-contract.md's
// "Reports store root-relative slash-separated paths, never absolute
// checkout paths." No existing test caught this: internal/analyzer/gin's own
// security_test.go exercises AnalyzeEngineSecurity below the orchestration
// layer that does the relativizing, and no prior test ran Audit end-to-end
// against the engine-security fixture at all.
func TestAuditEngineSecurityFindingsAndDiagnosticsAreRelativized(t *testing.T) {
	result := loadAndAudit(t, "engine-security", nil)

	if len(result.Findings) == 0 {
		t.Fatal("expected at least one engine-security finding from the fixture")
	}
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
		if d.Source == nil {
			t.Errorf("diagnostic %s has no Source", d.Code)
			continue
		}
		if filepath.IsAbs(d.Source.File) {
			t.Errorf("diagnostic %s Source.File = %q, want a root-relative path, not absolute", d.Code, d.Source.File)
		}
	}
	if !sawEngineDiagnostic {
		t.Fatal("expected at least one gin-unresolved-trusted-proxies or gin-unresolved-mode diagnostic")
	}
}

// authWrappers classification itself is now implemented (internal/classify's
// matchGuardFor + the authWrappers branch in ClassifyRoute) — see
// internal/classify/classify_test.go and testdata/fixtures/auth-wrappers for
// the positive/negative/opaque/nested/factory/contradicted-wrapper coverage.
// The gin-auth-wrappers-not-implemented diagnostic these tests used to
// assert no longer exists; keeping a stale "not implemented" regression test
// here would itself become the misleading claim docs/threat-model.md warns
// against.
