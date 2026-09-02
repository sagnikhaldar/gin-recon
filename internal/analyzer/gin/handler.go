package gin

import (
	"go/ast"
	"go/types"

	"github.com/sagnikhaldar/gin-recon/internal/model"
)

// callable is resolveCallable's result: enough to build a model.Middleware
// once the caller attaches Source, RegistrationScope, and OrderingIndex.
type callable struct {
	DisplayName      string
	CallableKind     model.CallableKind
	CanonicalSymbol  string // "" means unresolved
	ResolutionStatus model.ResolutionStatus
	WrappedSymbols   []string // see resolveMiddlewareCallable; empty for a handler-position callable
}

// resolveCallable classifies one handler/middleware argument expression.
// It deliberately never inspects or records a *ast.CallExpr's Args — only
// the callee — per docs/configuration-contract.md's "its arguments are never
// recorded" and the threat model's prohibition on middleware arguments
// appearing in reports at all. Anything it cannot resolve to a name or a
// known shape becomes CallableUnknown with no display text derived from
// source, never a raw source snippet.
func resolveCallable(info *types.Info, expr ast.Expr) callable {
	switch e := expr.(type) {
	case *ast.FuncLit:
		return callable{
			DisplayName:      "<anonymous>",
			CallableKind:     model.CallableAnonymous,
			ResolutionStatus: model.Unresolved,
		}

	case *ast.CallExpr:
		inner := resolveCallable(info, e.Fun)
		return callable{
			DisplayName:      inner.DisplayName,
			CallableKind:     model.CallableCall,
			CanonicalSymbol:  inner.CanonicalSymbol,
			ResolutionStatus: inner.ResolutionStatus,
		}

	case *ast.IndexExpr:
		// A generic function instantiation with one type argument,
		// "pkg.Func[T]" — e.g. middlewares.BindAndValidate[dtos.Foo]("body").
		// Per docs/configuration-contract.md: "Generic instantiation
		// arguments... are not part of identity," so this resolves straight
		// through to the base function/selector, discarding the type
		// argument entirely rather than trying to fold it into the symbol.
		return resolveCallable(info, e.X)

	case *ast.IndexListExpr:
		// The multi-type-argument form, "pkg.Func[T1, T2]". Same rule as
		// *ast.IndexExpr above.
		return resolveCallable(info, e.X)

	case *ast.Ident:
		return resolveIdent(info, e)

	case *ast.SelectorExpr:
		return resolveSelector(info, e)

	default:
		return callable{
			DisplayName:      "<unresolved>",
			CallableKind:     model.CallableUnknown,
			ResolutionStatus: model.Unresolved,
		}
	}
}

func resolveIdent(info *types.Info, id *ast.Ident) callable {
	name := id.Name
	obj := info.Uses[id]
	if obj == nil {
		return callable{DisplayName: name, CallableKind: model.CallableIdentifier, ResolutionStatus: model.Unresolved}
	}
	switch o := obj.(type) {
	case *types.Func:
		if sym := funcCanonicalSymbol(o); sym != "" {
			return callable{DisplayName: name, CallableKind: model.CallableIdentifier, CanonicalSymbol: sym, ResolutionStatus: model.Resolved}
		}
	case *types.Var:
		if o.Pkg() != nil && isPackageScopeVar(o) {
			sym := o.Pkg().Path() + "." + o.Name()
			return callable{DisplayName: name, CallableKind: model.CallableIdentifier, CanonicalSymbol: sym, ResolutionStatus: model.Resolved}
		}
	}
	// A local variable, function parameter, or anything else without a
	// stable package-qualified identity: still a plain name reference
	// syntactically, but not resolvable to a canonical symbol without
	// dataflow tracking this analyzer does not perform in v1 — see ADR 0008
	// for the same "bounded, not unbounded" principle applied here.
	return callable{DisplayName: name, CallableKind: model.CallableIdentifier, ResolutionStatus: model.Unresolved}
}

func resolveSelector(info *types.Info, sel *ast.SelectorExpr) callable {
	// pkg.Func: X is a package name, not a value.
	if pkgIdent, ok := sel.X.(*ast.Ident); ok {
		if pkgName, ok := info.Uses[pkgIdent].(*types.PkgName); ok {
			if fn, ok := info.Uses[sel.Sel].(*types.Func); ok {
				name := pkgName.Name() + "." + sel.Sel.Name
				if sym := funcCanonicalSymbol(fn); sym != "" {
					return callable{DisplayName: name, CallableKind: model.CallableIdentifier, CanonicalSymbol: sym, ResolutionStatus: model.Resolved}
				}
				return callable{DisplayName: name, CallableKind: model.CallableIdentifier, ResolutionStatus: model.Unresolved}
			}
		}
	}

	// Method value (recv.Method) or a struct field of function type.
	if selection, ok := info.Selections[sel]; ok {
		name := selectorDisplayName(sel)
		if selection.Kind() == types.MethodVal {
			if fn, ok := selection.Obj().(*types.Func); ok {
				if sym := funcCanonicalSymbol(fn); sym != "" {
					return callable{DisplayName: name, CallableKind: model.CallableIdentifier, CanonicalSymbol: sym, ResolutionStatus: model.Resolved}
				}
			}
		}
		// FieldVal (a struct field holding a function value) or any other
		// selection kind: syntactically a name reference, no stable
		// canonical symbol without further dataflow tracking.
		return callable{DisplayName: name, CallableKind: model.CallableIdentifier, ResolutionStatus: model.Unresolved}
	}

	return callable{DisplayName: selectorDisplayName(sel), CallableKind: model.CallableUnknown, ResolutionStatus: model.Unresolved}
}

// selectorDisplayName renders "x.Sel" using only identifier text already
// present in source (never a computed/serialized argument value), which is
// safe to surface: it is exactly what the developer wrote as a name, not
// evidence derived from evaluating anything.
func selectorDisplayName(sel *ast.SelectorExpr) string {
	if id, ok := sel.X.(*ast.Ident); ok {
		return id.Name + "." + sel.Sel.Name
	}
	return sel.Sel.Name
}

// FuncCanonicalSymbol is the exported form of funcCanonicalSymbol, for
// callers outside this package (internal/analyzer builds a canonical-symbol
// index for internal/classify from it) that need the exact same formatting
// resolveCallable uses internally, so a config author's configured symbol
// string and the analyzer's own derived symbol are guaranteed to agree.
func FuncCanonicalSymbol(fn *types.Func) string { return funcCanonicalSymbol(fn) }

// funcCanonicalSymbol formats a *types.Func per
// docs/configuration-contract.md#canonical-symbols-and-assurance:
// "pkg/path.Func" for a plain function, "pkg/path.(*Type).Method" or
// "pkg/path.(Type).Method" for a method, matching pointer-vs-value receiver
// exactly as declared.
func funcCanonicalSymbol(fn *types.Func) string {
	if fn.Pkg() == nil {
		return ""
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return fn.Pkg().Path() + "." + fn.Name()
	}
	recvType := sig.Recv().Type()
	if ptr, ok := recvType.(*types.Pointer); ok {
		if named, ok := ptr.Elem().(*types.Named); ok {
			return fn.Pkg().Path() + ".(*" + named.Obj().Name() + ")." + fn.Name()
		}
		return ""
	}
	if named, ok := recvType.(*types.Named); ok {
		return fn.Pkg().Path() + ".(" + named.Obj().Name() + ")." + fn.Name()
	}
	return ""
}

// isPackageScopeVar reports whether v was declared directly at package
// scope (a top-level `var`), as opposed to a local variable or function
// parameter — only the former has the kind of stable identity
// docs/configuration-contract.md's "Value with function type" canonical
// symbol format describes.
func isPackageScopeVar(v *types.Var) bool {
	return v.Pkg() != nil && v.Parent() == v.Pkg().Scope()
}

// maxWrapperHops bounds wrappedSymbolChain's recursion into nested call
// arguments — the same "bounded, not unbounded" philosophy already applied
// to registrar-following (maxRegistrarDepth) and factory-closure resolution
// (maxFactoryHops) elsewhere in this package, needed here for the same
// reason: docs/threat-model.md assumes a scanned repository may contain
// "extreme syntax," and this function walks into source-controlled AST
// shape (call arguments), not a bounded internal structure, so it must stop
// on its own rather than trust the input to be well-behaved.
const maxWrapperHops = 3

// resolveMiddlewareCallable resolves expr exactly as resolveCallable does,
// additionally recording a bounded chain of wrapped-call argument symbols.
// It exists as a separate function — rather than folding this into
// resolveCallable itself — so resolveCallable's own recursion (which never
// inspects Args at all, by design, for every other caller) stays completely
// unchanged; only call sites building a middleware-position callableRef
// need this, never a route's final handler position, since only middleware
// is ever a wrapper-following candidate for
// docs/configuration-contract.md's authWrappers.
func resolveMiddlewareCallable(info *types.Info, expr ast.Expr) callable {
	c := resolveCallable(info, expr)
	c.WrappedSymbols = wrappedSymbolChain(info, expr, maxWrapperHops)
	return c
}

// wrappedSymbolChain peels through up to hopsLeft levels of a
// "wrapper(inner)" call's first argument, recording each level's own
// canonical symbol — never a literal value, never arbitrary expression
// text, only ever a symbol resolveCallable itself already resolves
// independently. For "Outer(Middle(Inner))" it returns
// ["Middle","Inner"] (the outer callable's own symbol, "Outer", is already
// available separately as CanonicalSymbol — this chain is only what's
// nested inside). Recording this chain makes no judgment about whether any
// of these calls actually preserve or invoke their argument; that judgment
// belongs entirely to internal/classify, driven by a reviewer-configured
// authWrappers entry, never to this package.
func wrappedSymbolChain(info *types.Info, expr ast.Expr, hopsLeft int) []string {
	if hopsLeft <= 0 {
		return nil
	}
	call, ok := expr.(*ast.CallExpr)
	if !ok || len(call.Args) == 0 {
		return nil
	}
	arg := call.Args[0]
	resolved := resolveCallable(info, arg)
	if resolved.CanonicalSymbol == "" {
		return nil
	}
	return append([]string{resolved.CanonicalSymbol}, wrappedSymbolChain(info, arg, hopsLeft-1)...)
}
