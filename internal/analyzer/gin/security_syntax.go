package gin

import (
	"go/ast"
	"go/token"
	"strconv"

	"github.com/sagnikhaldar/gin-recon/internal/model"
)

// AnalyzeEngineSecuritySyntax is AnalyzeEngineSecurity's hermetic,
// go/types-free equivalent for the syntax-only profile. It recognizes the
// same two docs/gin-security-rules.md patterns purely syntactically:
//   - "<anything>.SetTrustedProxies([]string{literal, ...})" — unlike typed
//     mode, the receiver's type cannot be confirmed to be *gin.Engine at
//     all (no type information exists), so this matches the method name on
//     any receiver. This trades a narrow false-positive risk (an unrelated
//     type with a same-named method) for not silently losing this finding
//     in syntax-only entirely, consistent with diagnoseUntrackedValue's own
//     accepted trade-off elsewhere in this file's sibling
//     discover_syntax.go.
//   - "<ginAlias>.SetMode(<ginAlias>.DebugMode)" or
//     "<ginAlias>.SetMode("debug")" — recognized either by the literal
//     string or by the named gin.DebugMode identifier resolved against the
//     file's own import alias, since without go/constant folding a named
//     constant otherwise can never be distinguished from an arbitrary
//     identifier.
func AnalyzeEngineSecuritySyntax(fset *token.FileSet, ginAlias string, fn *ast.FuncDecl) ([]EngineEvidence, []model.Diagnostic) {
	if fn.Body == nil {
		return nil, nil
	}
	a := &engineAnalyzerSyntax{fset: fset, ginAlias: ginAlias}
	ast.Inspect(fn.Body, a.visit)
	return a.evidence, a.diagnostics
}

type engineAnalyzerSyntax struct {
	fset        *token.FileSet
	ginAlias    string
	evidence    []EngineEvidence
	diagnostics []model.Diagnostic
}

func (a *engineAnalyzerSyntax) visit(n ast.Node) bool {
	call, ok := n.(*ast.CallExpr)
	if !ok {
		return true
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return true
	}

	switch {
	case sel.Sel.Name == "SetTrustedProxies":
		a.checkTrustedProxies(call)
	case sel.Sel.Name == "SetMode" && a.isGinAlias(sel.X):
		a.checkSetMode(call)
	}
	return true
}

func (a *engineAnalyzerSyntax) isGinAlias(expr ast.Expr) bool {
	ident, ok := expr.(*ast.Ident)
	return ok && ident.Name == a.ginAlias
}

func (a *engineAnalyzerSyntax) checkTrustedProxies(call *ast.CallExpr) {
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

func (a *engineAnalyzerSyntax) checkSetMode(call *ast.CallExpr) {
	if len(call.Args) != 1 {
		return
	}
	if lit, ok := call.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
		value, err := strconv.Unquote(lit.Value)
		if err == nil && value == "debug" {
			a.evidence = append(a.evidence, EngineEvidence{Rule: RuleExplicitDebugMode, Source: a.sourceOf(call.Pos())})
		}
		return
	}
	if sel, ok := call.Args[0].(*ast.SelectorExpr); ok && a.isGinAlias(sel.X) && sel.Sel.Name == "DebugMode" {
		a.evidence = append(a.evidence, EngineEvidence{Rule: RuleExplicitDebugMode, Source: a.sourceOf(call.Pos())})
		return
	}
	a.diagnose("gin-unresolved-mode", "SetMode argument is not a resolved constant; build mode could not be evaluated", call.Pos())
}

func (a *engineAnalyzerSyntax) stringSliceLiteral(expr ast.Expr) ([]string, bool) {
	comp, ok := expr.(*ast.CompositeLit)
	if !ok {
		return nil, false
	}
	result := make([]string, 0, len(comp.Elts))
	for _, elt := range comp.Elts {
		lit, ok := elt.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return nil, false
		}
		value, err := strconv.Unquote(lit.Value)
		if err != nil {
			return nil, false
		}
		result = append(result, value)
	}
	return result, true
}

func (a *engineAnalyzerSyntax) diagnose(code, message string, pos token.Pos) {
	a.diagnostics = append(a.diagnostics, model.Diagnostic{
		Code:     code,
		Severity: model.DiagnosticWarning,
		Message:  message,
		Source:   a.sourceOf(pos),
	})
}

func (a *engineAnalyzerSyntax) sourceOf(pos token.Pos) *model.Source {
	if pos == token.NoPos {
		return nil
	}
	p := a.fset.Position(pos)
	line := p.Line
	return &model.Source{File: p.Filename, Line: &line}
}
