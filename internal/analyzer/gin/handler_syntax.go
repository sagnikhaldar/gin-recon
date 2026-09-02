package gin

import (
	"go/ast"

	"github.com/sagnikhaldar/gin-recon/internal/model"
)

// resolveCallableSyntax is resolveCallable's hermetic, go/types-free
// equivalent, used only by DiscoverSyntax. DisplayName and CallableKind are
// recovered exactly as typed mode does — both are purely syntactic — but
// CanonicalSymbol is always "" and ResolutionStatus is always Unresolved:
// syntax-only cannot establish a stable package-qualified identity without
// type information, per docs/threat-model.md's syntax-only trust profile
// ("cannot provide... canonical cross-package symbol identity"). This is
// also why WrappedSymbols is always left nil — authWrappers matching
// requires a canonical symbol on the wrapper itself, which syntax-only never
// has, so wrapper-following is trivially inapplicable rather than
// separately implemented and always a no-op.
func resolveCallableSyntax(expr ast.Expr) callable {
	switch e := expr.(type) {
	case *ast.FuncLit:
		return callable{
			DisplayName:      "<anonymous>",
			CallableKind:     model.CallableAnonymous,
			ResolutionStatus: model.Unresolved,
		}

	case *ast.CallExpr:
		inner := resolveCallableSyntax(e.Fun)
		return callable{
			DisplayName:      inner.DisplayName,
			CallableKind:     model.CallableCall,
			ResolutionStatus: model.Unresolved,
		}

	case *ast.IndexExpr:
		// Generic instantiation "pkg.Func[T]" — see resolveCallable's own
		// IndexExpr case for why the type argument is discarded rather than
		// folded into identity.
		return resolveCallableSyntax(e.X)

	case *ast.IndexListExpr:
		return resolveCallableSyntax(e.X)

	case *ast.Ident:
		return callable{DisplayName: e.Name, CallableKind: model.CallableIdentifier, ResolutionStatus: model.Unresolved}

	case *ast.SelectorExpr:
		return callable{DisplayName: selectorDisplayName(e), CallableKind: model.CallableIdentifier, ResolutionStatus: model.Unresolved}

	default:
		return callable{
			DisplayName:      "<unresolved>",
			CallableKind:     model.CallableUnknown,
			ResolutionStatus: model.Unresolved,
		}
	}
}
