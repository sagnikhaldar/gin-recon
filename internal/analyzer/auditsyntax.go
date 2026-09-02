package analyzer

import (
	"go/ast"
	"go/types"
	"time"

	"github.com/sagnikhaldar/gin-recon/internal/analyzer/gin"
	"github.com/sagnikhaldar/gin-recon/internal/classify"
	"github.com/sagnikhaldar/gin-recon/internal/config"
	"github.com/sagnikhaldar/gin-recon/internal/model"
	"github.com/sagnikhaldar/gin-recon/internal/policy"
	"github.com/sagnikhaldar/gin-recon/internal/report"
)

// AuditSyntax is Audit's syntax-only equivalent. Every route InventorySyntax
// discovers always has a nil CanonicalSymbol and Unresolved
// ResolutionStatus on every middleware entry (see discover_syntax.go's
// package doc comment), so classify.ClassifyRoute's own
// "if mw.CanonicalSymbol == nil { continue }" guard means a configured
// authMiddleware/authWrappers entry can never match — no special-casing is
// needed in internal/classify for this profile at all. This is the concrete
// enforcement mechanism behind docs/threat-model.md's "syntax-only... cannot
// emit proven": passing a nil API and empty FuncIndex/SymbolIndex here is
// safe precisely because that code path is unreachable for a route with no
// canonical symbol.
func AuditSyntax(loaded *LoadedSyntax, cfg *config.Config, now time.Time) *AuditResult {
	result := InventorySyntax(loaded)

	classified := classify.ClassifyAll(result.Routes, classify.Inputs{
		Config:      cfg,
		API:         nil,
		FuncIndex:   nil,
		SymbolIndex: map[string]*types.Func{},
		Profile:     model.ProfileSyntaxOnly,
	})

	policyResult := policy.Evaluate(result.Routes, cfg, now)
	engineFindings, engineDiagnostics := engineSecurityFindingsSyntax(loaded)
	result.Diagnostics = append(result.Diagnostics, engineDiagnostics...)
	if len(cfg.AuthMiddleware) > 0 || len(cfg.AuthWrappers) > 0 {
		result.Diagnostics = append(result.Diagnostics, model.Diagnostic{
			Code:     "gin-syntax-auth-config-unverifiable",
			Severity: model.DiagnosticInfo,
			Message:  "authMiddleware/authWrappers is configured, but syntax-only never resolves a canonical symbol, so stale-auth-config cannot distinguish an unused entry from one it simply cannot verify; this check is skipped for this profile",
		})
	}

	findings := append(classified.Findings, policyResult.Findings...)
	findings = append(findings, engineFindings...)

	return &AuditResult{
		InventoryResult:   result,
		Findings:          findings,
		Summary:           buildSummary(result.Routes, findings),
		EvaluatedPolicies: policyResult.EvaluatedPolicies,
	}
}

// engineSecurityFindingsSyntax mirrors engineSecurityFindings using
// gin.AnalyzeEngineSecuritySyntax's hermetic, go/types-free pattern
// matching instead of the typed analyzer.
func engineSecurityFindingsSyntax(loaded *LoadedSyntax) ([]report.Finding, []model.Diagnostic) {
	var findings []report.Finding
	var diagnostics []model.Diagnostic
	for _, sf := range loaded.Files {
		ginAlias, ok := gin.GinImportAlias(sf.File)
		if !ok {
			continue
		}
		for _, decl := range sf.File.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			evidence, diags := gin.AnalyzeEngineSecuritySyntax(loaded.Fset, ginAlias, fn)
			for i := range diags {
				relativizeSource(loaded.Root, nil, diags[i].Source)
			}
			diagnostics = append(diagnostics, diags...)
			for _, e := range evidence {
				relativizeSource(loaded.Root, nil, e.Source)
				findings = append(findings, newEngineFinding(e, sf.Path, fn.Name.Name))
			}
		}
	}
	return findings, diagnostics
}
