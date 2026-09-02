package analyzer

import (
	"go/ast"
	"go/token"
	"go/types"
	"strconv"

	"golang.org/x/tools/go/packages"
)

// buildPseudoConstIndex indexes every package-level `var` declared with a
// single string-literal initializer and never reassigned anywhere in its
// own package — the common real-world shape "var GET = \"GET\"" used as a
// pre-generics or intentionally-mutable stand-in for a constant, found
// scanning production services that build a Route{Type: POST, ...} literal
// from these vars rather than from real `const` declarations (which
// go/types already constant-folds without any help from this index).
//
// The "never reassigned" check is what makes trusting a var's own
// declaration-time value safe: a var that could be mutated elsewhere in its
// package before the registration code runs is not resolved here at all —
// this index only ever removes a candidate on any hint of reassignment, it
// never keeps one it cannot fully vouch for. It intentionally does not
// attempt to resolve a var whose address is ever taken (&GET) either, since
// that opens a mutation path this bounded, syntactic check cannot rule out.
func buildPseudoConstIndex(pkgs []*packages.Package) map[*types.Var]string {
	candidates := map[*types.Var]string{}
	reassignedOrAddressed := map[types.Object]bool{}

	for _, pkg := range pkgs {
		if pkg.TypesInfo == nil {
			continue
		}
		for _, file := range pkg.Syntax {
			for _, decl := range file.Decls {
				gd, ok := decl.(*ast.GenDecl)
				if !ok || gd.Tok != token.VAR {
					continue
				}
				for _, spec := range gd.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok || len(vs.Names) != len(vs.Values) {
						continue
					}
					for i, name := range vs.Names {
						if name.Name == "_" {
							continue
						}
						obj, ok := pkg.TypesInfo.Defs[name].(*types.Var)
						if !ok || !isPackageScopeVarObj(obj) {
							continue
						}
						lit, ok := vs.Values[i].(*ast.BasicLit)
						if !ok || lit.Kind != token.STRING {
							continue
						}
						value, err := strconv.Unquote(lit.Value)
						if err != nil {
							continue
						}
						candidates[obj] = value
					}
				}
			}
		}
	}

	for _, pkg := range pkgs {
		if pkg.TypesInfo == nil {
			continue
		}
		for _, file := range pkg.Syntax {
			ast.Inspect(file, func(n ast.Node) bool {
				switch s := n.(type) {
				case *ast.AssignStmt:
					if s.Tok != token.ASSIGN {
						return true
					}
					for _, lhs := range s.Lhs {
						markIfPseudoConstVar(pkg.TypesInfo, lhs, reassignedOrAddressed)
					}
				case *ast.IncDecStmt:
					markIfPseudoConstVar(pkg.TypesInfo, s.X, reassignedOrAddressed)
				case *ast.UnaryExpr:
					if s.Op == token.AND {
						markIfPseudoConstVar(pkg.TypesInfo, s.X, reassignedOrAddressed)
					}
				}
				return true
			})
		}
	}

	for obj := range candidates {
		if reassignedOrAddressed[obj] {
			delete(candidates, obj)
		}
	}
	return candidates
}

func markIfPseudoConstVar(info *types.Info, expr ast.Expr, marked map[types.Object]bool) {
	ident, ok := expr.(*ast.Ident)
	if !ok {
		return
	}
	obj := info.Uses[ident]
	if obj == nil {
		obj = info.Defs[ident]
	}
	if obj != nil {
		marked[obj] = true
	}
}

// isPackageScopeVarObj mirrors internal/analyzer/gin's own
// isPackageScopeVar (unexported there, and this package has no dependency
// on that one beyond the shared *types.Var identity check).
func isPackageScopeVarObj(v *types.Var) bool {
	return v.Pkg() != nil && v.Parent() == v.Pkg().Scope()
}
