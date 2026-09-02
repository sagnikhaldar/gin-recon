package gin

import (
	"go/parser"
	"go/token"
	"testing"

	"github.com/sagnikhaldar/gin-recon/internal/model"
)

// parseSyntax parses src (a complete Go source file) with no go/packages or
// type-checking involved at all — this is the whole point of syntax-only
// discovery, and it is exactly why these tests need no fixture module,
// go.mod, or network/module resolution the way discover_test.go's typed
// fixtures do.
func parseSyntax(t *testing.T, src string) *Registry {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "router.go", src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return DiscoverFileSyntax(fset, file)
}

func routeByMethodPath(t *testing.T, routes []model.Route, method, path string) model.Route {
	t.Helper()
	for _, r := range routes {
		if r.Method == method && r.NormalizedPath == path {
			return r
		}
	}
	t.Fatalf("route %s %s not found in %+v", method, path, routes)
	return model.Route{}
}

func TestDiscoverFileSyntaxNoGinImportIsEmptyNotError(t *testing.T) {
	reg := parseSyntax(t, `package main

func main() {}
`)
	if len(reg.Routes) != 0 || len(reg.Diagnostics) != 0 {
		t.Errorf("expected an empty registry for a file with no gin import, got %+v", reg)
	}
}

func TestDiscoverFileSyntaxDirectEngineAndVerbs(t *testing.T) {
	reg := parseSyntax(t, `package main

import "github.com/gin-gonic/gin"

func RequireAuth(c *gin.Context) {}
func Health(c *gin.Context)      {}

func NewRouter() *gin.Engine {
	r := gin.New()
	r.Use(RequireAuth)
	r.GET("/health", Health)
	return r
}
`)
	if len(reg.Routes) != 1 {
		t.Fatalf("Routes = %+v, want 1", reg.Routes)
	}
	route := reg.Routes[0]
	if route.NormalizedPath != "/health" || route.Method != "GET" {
		t.Errorf("route = %+v, want GET /health", route)
	}
	if len(route.Middleware) != 1 || route.Middleware[0].DisplayName != "RequireAuth" {
		t.Errorf("Middleware = %+v, want [RequireAuth]", route.Middleware)
	}
	if route.Middleware[0].ResolutionStatus != model.Unresolved {
		t.Errorf("ResolutionStatus = %q, want unresolved (syntax-only never resolves a canonical symbol)", route.Middleware[0].ResolutionStatus)
	}
	if route.Middleware[0].CanonicalSymbol != nil {
		t.Errorf("CanonicalSymbol = %v, want nil", route.Middleware[0].CanonicalSymbol)
	}
	if route.FinalHandler.DisplayName != "Health" {
		t.Errorf("FinalHandler = %+v, want Health", route.FinalHandler)
	}
	if route.AnalysisConfidence != model.ConfidenceLow {
		t.Errorf("AnalysisConfidence = %q, want low", route.AnalysisConfidence)
	}
	if len(reg.GlobalMiddleware) != 1 || reg.GlobalMiddleware[0].DisplayName != "RequireAuth" {
		t.Errorf("GlobalMiddleware = %+v, want [RequireAuth]", reg.GlobalMiddleware)
	}
}

func TestDiscoverFileSyntaxNestedNamedGroups(t *testing.T) {
	reg := parseSyntax(t, `package main

import "github.com/gin-gonic/gin"

func RequireAuth(c *gin.Context)  {}
func RequireAdmin(c *gin.Context) {}
func DeleteUser(c *gin.Context)   {}

func NewRouter() *gin.Engine {
	r := gin.New()
	admin := r.Group("/admin", RequireAuth)
	users := admin.Group("/users", RequireAdmin)
	users.DELETE("/:id", DeleteUser)
	return r
}
`)
	route := routeByMethodPath(t, reg.Routes, "DELETE", "/admin/users/:id")
	names := []string{}
	for _, mw := range route.Middleware {
		names = append(names, mw.DisplayName)
	}
	if len(names) != 2 || names[0] != "RequireAuth" || names[1] != "RequireAdmin" {
		t.Errorf("Middleware order = %v, want [RequireAuth RequireAdmin]", names)
	}
}

func TestDiscoverFileSyntaxInlineUnassignedGroupChain(t *testing.T) {
	reg := parseSyntax(t, `package main

import "github.com/gin-gonic/gin"

func ListUsers(c *gin.Context) {}

func NewRouter() *gin.Engine {
	r := gin.New()
	r.Group("/v1").GET("/users", ListUsers)
	return r
}
`)
	route := routeByMethodPath(t, reg.Routes, "GET", "/v1/users")
	if route.FinalHandler.DisplayName != "ListUsers" {
		t.Errorf("FinalHandler = %+v, want ListUsers", route.FinalHandler)
	}
}

func TestDiscoverFileSyntaxAnyExpandsToNineMethods(t *testing.T) {
	reg := parseSyntax(t, `package main

import "github.com/gin-gonic/gin"

func Wildcard(c *gin.Context) {}

func NewRouter() *gin.Engine {
	r := gin.New()
	r.Any("/wildcard", Wildcard)
	return r
}
`)
	if len(reg.Routes) != len(anyMethods) {
		t.Fatalf("Routes = %d, want %d (one per Any()-expanded method)", len(reg.Routes), len(anyMethods))
	}
}

func TestDiscoverFileSyntaxHandleAndMatchWithLiteralMethods(t *testing.T) {
	reg := parseSyntax(t, `package main

import "github.com/gin-gonic/gin"

func H(c *gin.Context) {}

func NewRouter() *gin.Engine {
	r := gin.New()
	r.Handle("PATCH", "/handled", H)
	r.Match([]string{"GET", "POST"}, "/matched", H)
	return r
}
`)
	routeByMethodPath(t, reg.Routes, "PATCH", "/handled")
	routeByMethodPath(t, reg.Routes, "GET", "/matched")
	routeByMethodPath(t, reg.Routes, "POST", "/matched")
}

func TestDiscoverFileSyntaxStaticExpandsGetAndHead(t *testing.T) {
	reg := parseSyntax(t, `package main

import "github.com/gin-gonic/gin"

func NewRouter() *gin.Engine {
	r := gin.New()
	r.Static("/assets", "./public")
	return r
}
`)
	routeByMethodPath(t, reg.Routes, "GET", "/assets/*filepath")
	routeByMethodPath(t, reg.Routes, "HEAD", "/assets/*filepath")
}

func TestDiscoverFileSyntaxNoRouteUsesFinalGlobalMiddleware(t *testing.T) {
	reg := parseSyntax(t, `package main

import "github.com/gin-gonic/gin"

func Logger(c *gin.Context)   {}
func NotFound(c *gin.Context) {}

func NewRouter() *gin.Engine {
	r := gin.New()
	r.NoRoute(NotFound)
	r.Use(Logger)
	return r
}
`)
	if len(reg.FallbackSurfaces) != 1 {
		t.Fatalf("FallbackSurfaces = %+v, want 1", reg.FallbackSurfaces)
	}
	fb := reg.FallbackSurfaces[0]
	if fb.Kind != model.FallbackNoRoute {
		t.Errorf("Kind = %q, want no-route", fb.Kind)
	}
	// Use() was called AFTER NoRoute() in source, but Gin recomputes the
	// combined 404 chain on every subsequent Use() — the final global
	// middleware state must still be reflected, matching typed's own
	// finish()-time resolution.
	if len(fb.Middleware) != 1 || fb.Middleware[0].DisplayName != "Logger" {
		t.Errorf("Middleware = %+v, want [Logger] even though Use() came after NoRoute() in source", fb.Middleware)
	}
}

func TestDiscoverFileSyntaxNonLiteralPathIsDiagnosedNotFabricated(t *testing.T) {
	reg := parseSyntax(t, `package main

import "github.com/gin-gonic/gin"

func H(c *gin.Context) {}

func NewRouter() *gin.Engine {
	r := gin.New()
	path := "/dynamic"
	r.GET(path, H)
	return r
}
`)
	if len(reg.Routes) != 0 {
		t.Errorf("Routes = %+v, want none — a non-literal path must never be fabricated", reg.Routes)
	}
	found := false
	for _, d := range reg.Diagnostics {
		if d.Code == "gin-unresolved-path" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a gin-unresolved-path diagnostic, got %+v", reg.Diagnostics)
	}
}

// TestDiscoverFileSyntaxUntrackedValueIsDiagnosed exercises a router value
// this analyzer cannot trace to a direct gin.New()/Default() call — the
// wrapping-factory-return-value pattern discover_syntax.go's package doc
// comment describes as out of scope. NewRouter itself must still call
// gin.New() directly (satisfying HasEngineConstructionSyntax's entry gate)
// so this scenario is actually reachable: an untracked value used
// elsewhere in a function that is otherwise a legitimate discovery entry
// point, mirroring exactly how typed mode's own HasEngineConstruction gate
// means diagnoseUntrackedRouterValue can only ever fire from within a
// function that itself constructs a real engine somewhere.
func TestDiscoverFileSyntaxUntrackedValueIsDiagnosed(t *testing.T) {
	reg := parseSyntax(t, `package main

import "github.com/gin-gonic/gin"

func H(c *gin.Context) {}

func NewEngine() *gin.Engine {
	return gin.New()
}

func NewRouter() *gin.Engine {
	r := gin.New()
	other := NewEngine()
	other.GET("/health", H)
	return r
}
`)
	if len(reg.Routes) != 0 {
		t.Errorf("Routes = %+v, want none — a wrapping factory's return value is not traced in syntax-only", reg.Routes)
	}
	found := false
	for _, d := range reg.Diagnostics {
		if d.Code == "gin-syntax-untracked-value" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a gin-syntax-untracked-value diagnostic, got %+v", reg.Diagnostics)
	}
}

func TestDiscoverFileSyntaxNeverEmitsCanonicalSymbolOrProvenEvidence(t *testing.T) {
	reg := parseSyntax(t, `package main

import "github.com/gin-gonic/gin"

func RequireAuth(c *gin.Context) {}
func H(c *gin.Context)           {}

func NewRouter() *gin.Engine {
	r := gin.New()
	r.GET("/secure", RequireAuth, H)
	return r
}
`)
	route := routeByMethodPath(t, reg.Routes, "GET", "/secure")
	for _, mw := range route.Middleware {
		if mw.CanonicalSymbol != nil {
			t.Errorf("Middleware %+v has a CanonicalSymbol — syntax-only must never resolve one", mw)
		}
		if mw.ResolutionStatus != model.Unresolved {
			t.Errorf("Middleware %+v ResolutionStatus = %q, want unresolved", mw, mw.ResolutionStatus)
		}
	}
}

func TestGinImportAliasHandlesRenamedImport(t *testing.T) {
	reg := parseSyntax(t, `package main

import gg "github.com/gin-gonic/gin"

func H(c *gg.Context) {}

func NewRouter() *gg.Engine {
	r := gg.New()
	r.GET("/health", H)
	return r
}
`)
	routeByMethodPath(t, reg.Routes, "GET", "/health")
}

func TestGinImportAliasIgnoresBlankImport(t *testing.T) {
	reg := parseSyntax(t, `package main

import _ "github.com/gin-gonic/gin"

func main() {}
`)
	if len(reg.Routes) != 0 || len(reg.Diagnostics) != 0 {
		t.Errorf("expected an empty registry for a blank gin import, got %+v", reg)
	}
}

// parseSyntaxWithComments is parseSyntax's counterpart that retains doc
// comments — needed only for the swag annotation tests below, since
// parseSyntax's parser.SkipObjectResolution-only mode never attaches
// *ast.CommentGroup to declarations at all.
func parseSyntaxWithComments(t *testing.T, src string) *Registry {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "router.go", src, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return DiscoverFileSyntax(fset, file)
}

// TestDiscoverFileSyntaxAppliesSwagFromSameFileHandler confirms the
// syntax-only profile's narrower swag support (docs/adr/0012-swag-annotation-evidence.md
// and discoverSyntax's fileFuncs doc comment): a handler referenced by a
// bare identifier and declared in the very same file has its doc comment's
// swag directives applied exactly like the typed path.
func TestDiscoverFileSyntaxAppliesSwagFromSameFileHandler(t *testing.T) {
	reg := parseSyntaxWithComments(t, `package main

import "github.com/gin-gonic/gin"

// GetUser returns a user.
//
// @Summary Get a user
// @Router /users/{id} [get]
func GetUser(c *gin.Context) {}

func NewRouter() *gin.Engine {
	r := gin.New()
	r.GET("/users/:id", GetUser)
	return r
}
`)
	if len(reg.Diagnostics) != 0 {
		t.Fatalf("unexpected diagnostics: %+v", reg.Diagnostics)
	}
	route := routeByMethodPath(t, reg.Routes, "GET", "/users/:id")
	if route.Swag == nil {
		t.Fatal("Swag is nil, want populated from GetUser's same-file doc comment")
	}
	if route.Swag.Summary != "Get a user" {
		t.Errorf("Summary = %q, want %q", route.Swag.Summary, "Get a user")
	}
}

// TestDiscoverFileSyntaxSwagRouterMismatchIsDiagnosed mirrors the typed
// path's mismatch behavior for the syntax-only profile.
func TestDiscoverFileSyntaxSwagRouterMismatchIsDiagnosed(t *testing.T) {
	reg := parseSyntaxWithComments(t, `package main

import "github.com/gin-gonic/gin"

// @Summary List users
// @Router /users [post]
func ListUsers(c *gin.Context) {}

func NewRouter() *gin.Engine {
	r := gin.New()
	r.GET("/users", ListUsers)
	return r
}
`)
	route := routeByMethodPath(t, reg.Routes, "GET", "/users")
	if route.Swag == nil || route.Swag.Summary != "List users" {
		t.Errorf("Swag = %+v, want Summary to survive the @Router mismatch", route.Swag)
	}
	found := false
	for _, d := range reg.Diagnostics {
		if d.Code == "swag-router-mismatch" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a swag-router-mismatch diagnostic, got: %+v", reg.Diagnostics)
	}
}
