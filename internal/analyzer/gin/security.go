package gin

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"

	"github.com/sagnikhaldar/gin-recon/internal/model"
)

// EngineRuleID identifies one of the two Gin engine misconfiguration rules
// docs/gin-security-rules.md defines. That document deliberately closes the
// set at these two: "additional rules require an ADR, fixture corpus, and
// measured false-positive review" — this package must not grow a third rule
// without that.
type EngineRuleID string

const (
	RuleTrustAllProxies   EngineRuleID = "gin-explicit-trust-all-proxies"
	RuleExplicitDebugMode EngineRuleID = "gin-explicit-debug-mode"
)

// EngineEvidence is one resolved engine-misconfiguration finding's evidence.
// internal/analyzer turns this into a report.Finding; this package stays
// free of a dependency on internal/report, matching Discover's own
// separation between evidence-gathering and report construction.
type EngineEvidence struct {
	Rule   EngineRuleID
	Source *model.Source
}

// allAddressCIDRs are the literal forms docs/gin-security-rules.md names
// explicitly. This is intentionally an exact-match allowlist, not a general
// CIDR-containment check (which would require parsing arbitrary CIDR
// strings and reasoning about whether they cover 0.0.0.0/::) — the two
// canonical forms cover the overwhelmingly common way this misconfiguration
// is actually written.
var allAddressCIDRs = map[string]bool{
	"0.0.0.0/0": true,
	"::/0":      true,
}

// AnalyzeEngineSecurity walks one function body for the two Gin engine
// misconfiguration patterns. Unlike Discover, it does not require an engine
// value to have been created via gin.New()/gin.Default() in the same
// function — SetTrustedProxies is recognized on any expression whose static
// type is *gin.Engine, and SetMode is a global function unrelated to any
// particular engine instance — so this intentionally does not share
// Discover's tracked-object state.
func AnalyzeEngineSecurity(fset *token.FileSet, info *types.Info, api *API, fn *ast.FuncDecl) ([]EngineEvidence, []model.Diagnostic) {
	if fn.Body == nil {
		return nil, nil
	}
	a := &engineAnalyzer{fset: fset, info: info, api: api}
	ast.Inspect(fn.Body, a.visit)
	return a.evidence, a.diagnostics
}

type engineAnalyzer struct {
	fset        *token.FileSet
	info        *types.Info
	api         *API
	evidence    []EngineEvidence
	diagnostics []model.Diagnostic
}

func (a *engineAnalyzer) visit(n ast.Node) bool {
	call, ok := n.(*ast.CallExpr)
	if !ok {
		return true
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return true
	}

	switch {
	case sel.Sel.Name == "SetTrustedProxies" && a.isEngineReceiver(sel.X):
		a.checkTrustedProxies(call)
	case sel.Sel.Name == "SetMode" && a.isGinPackage(sel.X):
		a.checkSetMode(call)
	}
	return true
}

func (a *engineAnalyzer) isEngineReceiver(expr ast.Expr) bool {
	t := a.info.TypeOf(expr)
	if t == nil {
		return false
	}
	isEngine, _ := a.api.IsRouterValue(t)
	return isEngine
}

func (a *engineAnalyzer) isGinPackage(expr ast.Expr) bool {
	ident, ok := expr.(*ast.Ident)
	if !ok {
		return false
	}
	pkgName, ok := a.info.Uses[ident].(*types.PkgName)
	return ok && pkgName.Imported().Path() == PackagePath
}

// checkTrustedProxies implements docs/gin-security-rules.md's
// gin-explicit-trust-all-proxies: a finding requires the argument to be a
// fully resolved literal slice; anything else (a variable, a function
// result, a partially-resolved element) is a diagnostic, never a finding —
// this analyzer must not claim a vulnerability it has not actually proven.
func (a *engineAnalyzer) checkTrustedProxies(call *ast.CallExpr) {
	if len(call.Args) != 1 {
		return
	}
	cidrs, ok := a.stringSliceLiteral(call.Args[0])
	if !ok {
		a.diagnose("gin-unresolved-trusted-proxies", "SetTrustedProxies argument is not a fully resolved literal string slice; trust configuration could not be evaluated", call.Pos())
		return
	}
	for _, cidr := range cidrs {
		if allAddressCIDRs[cidr] {
			a.evidence = append(a.evidence, EngineEvidence{Rule: RuleTrustAllProxies, Source: a.sourceOf(call.Pos())})
			return
		}
	}
}

// checkSetMode implements gin-explicit-debug-mode: a finding requires the
// argument to resolve to the exact constant string "debug" (gin.DebugMode's
// value); this analyzer never infers debug mode from an unresolved
// expression, an environment variable, or the absence of an explicit
// release-mode call.
func (a *engineAnalyzer) checkSetMode(call *ast.CallExpr) {
	if len(call.Args) != 1 {
		return
	}
	tv, ok := a.info.Types[call.Args[0]]
	if !ok || tv.Value == nil || tv.Value.Kind() != constant.String {
		a.diagnose("gin-unresolved-mode", "SetMode argument is not a resolved constant; build mode could not be evaluated", call.Pos())
		return
	}
	if constant.StringVal(tv.Value) == "debug" {
		a.evidence = append(a.evidence, EngineEvidence{Rule: RuleExplicitDebugMode, Source: a.sourceOf(call.Pos())})
	}
}

func (a *engineAnalyzer) stringSliceLiteral(expr ast.Expr) ([]string, bool) {
	comp, ok := expr.(*ast.CompositeLit)
	if !ok {
		return nil, false
	}
	result := make([]string, 0, len(comp.Elts))
	for _, elt := range comp.Elts {
		tv, ok := a.info.Types[elt]
		if !ok || tv.Value == nil || tv.Value.Kind() != constant.String {
			return nil, false
		}
		result = append(result, constant.StringVal(tv.Value))
	}
	return result, true
}

func (a *engineAnalyzer) diagnose(code, message string, pos token.Pos) {
	a.diagnostics = append(a.diagnostics, model.Diagnostic{
		Code:     code,
		Severity: model.DiagnosticWarning,
		Message:  message,
		Source:   a.sourceOf(pos),
	})
}

func (a *engineAnalyzer) sourceOf(pos token.Pos) *model.Source {
	if pos == token.NoPos {
		return nil
	}
	p := a.fset.Position(pos)
	line := p.Line
	return &model.Source{File: p.Filename, Line: &line}
}
