// Package gin recognizes Gin engine/group/route/middleware constructs
// through type and package identity (go/types), never through local variable
// names or source text matching, per PLAN.md's analyzer design and ADR 0005.
package gin

import "go/types"

// PackagePath is the canonical import path recognized as "the" Gin package.
// A fork or vendored copy under a different import path is not recognized —
// this is deliberate: the compatibility matrix in
// docs/accuracy-strategy.md is scoped to upstream gin-gonic/gin.
const PackagePath = "github.com/gin-gonic/gin"

// API holds the specific Gin symbols the analyzer needs, resolved once per
// loaded target package set. A nil API (from Find returning ok=false) means
// the target does not import Gin at all, which is a normal, valid outcome —
// not an error.
type API struct {
	pkg         *types.Package
	Engine      *types.Named
	RouterGroup *types.Named
	Context     *types.Named
	HandlerFunc *types.Named
}

// Find locates the loaded gin-gonic/gin package among imports (typically
// reached via (*packages.Package).Imports, keyed by PackagePath) and resolves
// the core types this package depends on. It returns ok=false, not an error,
// when Gin is not imported anywhere in the analyzed package set.
func Find(imports map[string]*types.Package) (*API, bool) {
	ginPkg, ok := imports[PackagePath]
	if !ok || ginPkg == nil {
		return nil, false
	}
	api := &API{pkg: ginPkg}
	api.Engine = lookupNamed(ginPkg, "Engine")
	api.RouterGroup = lookupNamed(ginPkg, "RouterGroup")
	api.Context = lookupNamed(ginPkg, "Context")
	api.HandlerFunc = lookupNamed(ginPkg, "HandlerFunc")
	if api.Engine == nil || api.RouterGroup == nil {
		// A package claiming to be gin-gonic/gin without these core types is
		// not a Gin version this analyzer understands; treat it the same as
		// "Gin not found" rather than proceeding on a false premise.
		return nil, false
	}
	return api, true
}

func lookupNamed(pkg *types.Package, name string) *types.Named {
	obj := pkg.Scope().Lookup(name)
	if obj == nil {
		return nil
	}
	tn, ok := obj.(*types.TypeName)
	if !ok {
		return nil
	}
	named, ok := tn.Type().(*types.Named)
	if !ok {
		return nil
	}
	return named
}

// IsRouterValue reports whether t (as used as a method receiver expression's
// static type) is a *gin.Engine or *gin.RouterGroup — the two concrete types
// every route/group/middleware-registration method in Gin is ultimately
// defined on or promoted from. Interfaces (gin.IRoutes, gin.IRouter) are
// deliberately not matched here: a value only known through one of those
// interfaces has lost the concrete identity needed to track its
// accumulated middleware/base-path state, so callers should treat that case
// as unresolved rather than pretend continuity with the underlying group.
func (a *API) IsRouterValue(t types.Type) (isEngine bool, isGroup bool) {
	named := namedOf(t)
	if named == nil {
		return false, false
	}
	return types.Identical(named, a.Engine), types.Identical(named, a.RouterGroup)
}

// IsHandlerFuncType reports whether t is gin.HandlerFunc itself, or a
// function type structurally identical to it (func(*gin.Context)) —
// middleware is frequently stored in a variable typed as a plain function
// signature rather than the named gin.HandlerFunc alias.
func (a *API) IsHandlerFuncType(t types.Type) bool {
	if named := namedOf(t); named != nil && types.Identical(named, a.HandlerFunc) {
		return true
	}
	sig, ok := t.Underlying().(*types.Signature)
	if !ok || sig.Params().Len() != 1 || sig.Results().Len() != 0 || sig.Variadic() {
		return false
	}
	paramNamed := namedOf(sig.Params().At(0).Type())
	return paramNamed != nil && types.Identical(paramNamed, a.Context)
}

// namedOf unwraps a single level of pointer indirection and returns the
// underlying *types.Named, or nil if t is neither a named type nor a pointer
// to one (e.g. an interface, a slice, a basic type).
func namedOf(t types.Type) *types.Named {
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, _ := t.(*types.Named)
	return named
}
