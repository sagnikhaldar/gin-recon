package gin

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"testing"
)

// TestAnalyzeEngineSecuritySyntaxMatchesFixtureManifest reuses the exact
// same engine-security fixture (testdata/fixtures/engine-security/main.go)
// typed mode's own TestAnalyzeEngineSecurityMatchesFixtureManifest verifies
// against — since syntax-only needs no go.mod/go.sum resolution at all, the
// fixture's real .go source can be parsed directly with go/parser, with no
// go/packages module load involved, proving hermetic and typed analysis
// agree on every case this fixture's manifest.json documents.
func TestAnalyzeEngineSecuritySyntaxMatchesFixtureManifest(t *testing.T) {
	fset := token.NewFileSet()
	path := filepath.Join("..", "..", "..", "testdata", "fixtures", "engine-security", "main.go")
	file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ginAlias, ok := ginImportAlias(file)
	if !ok {
		t.Fatal("fixture does not import gin-gonic/gin")
	}

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

	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		evidence, diagnostics := AnalyzeEngineSecuritySyntax(fset, ginAlias, fn)

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
