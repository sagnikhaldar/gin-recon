package gin

import (
	"go/ast"
	"testing"
)

func TestAnalyzeEngineSecurityMatchesFixtureManifest(t *testing.T) {
	pkgs, api := loadFixture(t, "engine-security")
	pkg, _ := findFunc(t, pkgs, "/engine-security", "TrustAllProxiesIPv4") // just to confirm the package loads

	wantFindings := map[string]EngineRuleID{
		"TrustAllProxiesIPv4":      RuleTrustAllProxies,
		"TrustAllProxiesIPv6":      RuleTrustAllProxies,
		"ExplicitDebugModeConst":   RuleExplicitDebugMode,
		"ExplicitDebugModeLiteral": RuleExplicitDebugMode,
	}
	wantNoFinding := []string{"TrustSafeProxies", "ExplicitReleaseMode"}
	wantDiagnostics := map[string]string{
		"TrustUnresolvedProxies": "gin-unresolved-trusted-proxies",
		"UnresolvedMode":         "gin-unresolved-mode",
	}

	for _, file := range pkg.Syntax {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			evidence, diagnostics := AnalyzeEngineSecurity(pkg.Fset, pkg.TypesInfo, api, fn)

			if wantRule, ok := wantFindings[fn.Name.Name]; ok {
				if len(evidence) != 1 || evidence[0].Rule != wantRule {
					t.Errorf("%s: evidence = %+v, want exactly one %q", fn.Name.Name, evidence, wantRule)
				}
				if len(evidence) == 1 && evidence[0].Source == nil {
					t.Errorf("%s: evidence Source is nil, want populated", fn.Name.Name)
				}
			}
			for _, name := range wantNoFinding {
				if fn.Name.Name == name && len(evidence) != 0 {
					t.Errorf("%s: evidence = %+v, want none", fn.Name.Name, evidence)
				}
			}
			if wantCode, ok := wantDiagnostics[fn.Name.Name]; ok {
				found := false
				for _, d := range diagnostics {
					if d.Code == wantCode {
						found = true
					}
				}
				if !found {
					t.Errorf("%s: diagnostics = %+v, want code %q", fn.Name.Name, diagnostics, wantCode)
				}
				if len(evidence) != 0 {
					t.Errorf("%s: evidence = %+v, want none (unresolved must never produce a finding)", fn.Name.Name, evidence)
				}
			}
		}
	}
}
