package gin

import (
	"go/token"
	"go/types"
	"strings"
	"testing"
)

// TestUnresolvedRegistrarMessageNamesTheSymbol is the regression for a real
// diagnosability gap found scanning production repositories: two services
// call an Init(router *gin.RouterGroup, ...) function that genuinely lives
// in a separate Go module (a same-organization internal dependency,
// registrar-following is deliberately never followed across a module
// boundary — see buildFuncIndex's doc comment in internal/analyzer). The
// diagnostic used to say only "external package or missing syntax," giving
// a reviewer no way to tell which other repository to go scan; it must now
// name the exact canonical symbol instead.
func TestUnresolvedRegistrarMessageNamesTheSymbol(t *testing.T) {
	pkg := types.NewPackage("github.com/example/lender/pkg/webhook", "webhook")
	sig := types.NewSignatureType(nil, nil, nil, nil, nil, false)
	fn := types.NewFunc(token.NoPos, pkg, "Init", sig)

	got := unresolvedRegistrarMessage(fn)
	want := "github.com/example/lender/pkg/webhook.Init"
	if !strings.Contains(got, want) {
		t.Errorf("message = %q, want it to name %q", got, want)
	}
}

// TestUnresolvedRegistrarMessageDistinguishesInterfaceDispatch is the
// regression for a real inaccuracy found scanning a production repository:
// a call through an interface-typed value (e.g. "router.Initialize()"
// where router is typed as an interface, returned by a factory) resolves
// to the interface's own abstract method — which is absent from funcIndex
// for a completely different reason than a genuine cross-module dependency
// (interface dispatch cannot be statically resolved to a concrete
// implementation at all, in or out of the target module). The message must
// say so, not incorrectly suggest scanning "another module."
func TestUnresolvedRegistrarMessageDistinguishesInterfaceDispatch(t *testing.T) {
	pkg := types.NewPackage("github.com/example/task", "task")
	iface := types.NewInterfaceType([]*types.Func{}, nil)
	iface.Complete()
	recv := types.NewVar(token.NoPos, pkg, "", iface)
	sig := types.NewSignatureType(recv, nil, nil, nil, nil, false)
	fn := types.NewFunc(token.NoPos, pkg, "Initialize", sig)

	got := unresolvedRegistrarMessage(fn)
	if !strings.Contains(got, "declared on an interface") {
		t.Errorf("message = %q, want it to explain interface dispatch, not suggest a cross-module dependency", got)
	}
	if strings.Contains(got, "dependency module") {
		t.Errorf("message = %q, must not describe an interface method as a cross-module dependency", got)
	}
}

// TestUnresolvedRegistrarMessageFallsBackWhenSymbolUnavailable confirms the
// pre-existing generic message survives for the (rare) case where the
// resolved *types.Func itself has no canonical symbol form — e.g. a method
// on an unnamed or generic-instantiated receiver type funcCanonicalSymbol
// cannot format.
func TestUnresolvedRegistrarMessageFallsBackWhenSymbolUnavailable(t *testing.T) {
	// A *types.Func with no owning package (Pkg() == nil, e.g. a universe-
	// scope builtin) is exactly the case funcCanonicalSymbol itself
	// documents as returning "".
	fn := types.NewFunc(token.NoPos, nil, "Init", types.NewSignatureType(nil, nil, nil, nil, nil, false))
	got := unresolvedRegistrarMessage(fn)
	if !strings.Contains(got, "external package or missing syntax") {
		t.Errorf("message = %q, want the generic fallback", got)
	}
}
