package gin

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/sagnikhaldar/gin-recon/internal/model"
)

// docOf parses src (a single top-level function declaration, optionally
// preceded by a doc comment) and returns that function's *ast.CommentGroup,
// exactly what a real handler's fn.Doc would be at the point discovery
// records a route — so these tests exercise ParseSwagAnnotations against
// real Go doc comments, not hand-built comment strings.
func docOf(t *testing.T, src string) *ast.CommentGroup {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "handler.go", "package p\n"+src, parser.ParseComments)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			return fn.Doc
		}
	}
	t.Fatal("no function declaration found in src")
	return nil
}

func TestParseSwagAnnotations(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want *model.SwagInfo
	}{
		{
			name: "no doc comment at all",
			src:  `func H() {}`,
			want: nil,
		},
		{
			name: "ordinary prose doc comment with no swag directive",
			src: `// H handles the request and does something useful for the
// caller, returning a JSON body on success.
func H() {}`,
			want: nil,
		},
		{
			name: "summary only",
			src: `// @Summary Get a user by ID
func H() {}`,
			want: &model.SwagInfo{Summary: "Get a user by ID"},
		},
		{
			name: "multi-line description concatenates",
			src: `// @Description This endpoint returns a user.
// @Description It requires a valid session.
func H() {}`,
			want: &model.SwagInfo{Description: "This endpoint returns a user. It requires a valid session."},
		},
		{
			name: "tags",
			src: `// @Tags users, admin , internal
func H() {}`,
			want: &model.SwagInfo{Tags: []string{"users", "admin", "internal"}},
		},
		{
			name: "router match, no mismatch fields populated by the parser itself",
			src: `// @Router /users/{id} [get]
func H() {}`,
			want: &model.SwagInfo{RouterPath: "/users/{id}", RouterMethod: "GET"},
		},
		{
			name: "router without bracketed method",
			src: `// @Router /users/{id}
func H() {}`,
			want: &model.SwagInfo{RouterPath: "/users/{id}"},
		},
		{
			name: "deprecated bare marker",
			src: `// @Deprecated
func H() {}`,
			want: &model.SwagInfo{Deprecated: true},
		},
		{
			name: "combination",
			src: `// H does a thing.
// @Summary Get a user
// @Description Returns a user by ID.
// @Tags users
// @Router /users/{id} [get]
// @Deprecated
func H() {}`,
			want: &model.SwagInfo{
				Summary:      "Get a user",
				Description:  "Returns a user by ID.",
				Tags:         []string{"users"},
				Deprecated:   true,
				RouterPath:   "/users/{id}",
				RouterMethod: "GET",
			},
		},
		{
			name: "malformed router directive (empty brackets, no path) does not crash",
			src: `// @Router
func H() {}`,
			want: nil,
		},
		{
			name: "unrecognized directive alongside a recognized one",
			src: `// @Success 200 {object} User
// @Summary Get a user
func H() {}`,
			want: &model.SwagInfo{Summary: "Get a user"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := docOf(t, c.src)
			got := ParseSwagAnnotations(doc)
			assertSwagInfoEqual(t, got, c.want)
		})
	}
}

func assertSwagInfoEqual(t *testing.T, got, want *model.SwagInfo) {
	t.Helper()
	if (got == nil) != (want == nil) {
		t.Fatalf("ParseSwagAnnotations() = %+v, want %+v", got, want)
	}
	if got == nil {
		return
	}
	if got.Summary != want.Summary ||
		got.Description != want.Description ||
		got.Deprecated != want.Deprecated ||
		got.RouterPath != want.RouterPath ||
		got.RouterMethod != want.RouterMethod ||
		!stringSlicesEqual(got.Tags, want.Tags) {
		t.Errorf("ParseSwagAnnotations() = %+v, want %+v", got, want)
	}
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestApplySwagFromDocRouterMismatch(t *testing.T) {
	cases := []struct {
		name       string
		src        string
		route      model.Route
		wantDiag   bool
		wantSwag   bool
		wantMethod string
	}{
		{
			name:     "no doc comment: no swag, no diagnostic",
			src:      `func H() {}`,
			route:    model.Route{Method: "GET", GinPath: "/users/:id"},
			wantDiag: false,
			wantSwag: false,
		},
		{
			name:     "router path and method match",
			src:      "// @Router /users/{id} [get]\nfunc H() {}",
			route:    model.Route{Method: "GET", GinPath: "/users/:id"},
			wantDiag: false,
			wantSwag: true,
		},
		{
			name:     "router path mismatch",
			src:      "// @Router /users/{userId} [get]\nfunc H() {}",
			route:    model.Route{Method: "GET", GinPath: "/users/:id"},
			wantDiag: true,
			wantSwag: true,
		},
		{
			name:     "router method mismatch",
			src:      "// @Router /users/{id} [post]\nfunc H() {}",
			route:    model.Route{Method: "GET", GinPath: "/users/:id"},
			wantDiag: true,
			wantSwag: true,
		},
		{
			name:     "summary/description/tags still applied despite mismatch",
			src:      "// @Summary Get a user\n// @Router /wrong [post]\nfunc H() {}",
			route:    model.Route{Method: "GET", GinPath: "/users/:id"},
			wantDiag: true,
			wantSwag: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := docOf(t, c.src)
			route := c.route
			diag := ApplySwagFromDoc(&route, doc)
			if (diag != nil) != c.wantDiag {
				t.Errorf("ApplySwagFromDoc diagnostic = %+v, wantDiag = %v", diag, c.wantDiag)
			}
			if diag != nil {
				if diag.Code != "swag-router-mismatch" {
					t.Errorf("diagnostic code = %q, want swag-router-mismatch", diag.Code)
				}
				if diag.Severity != model.DiagnosticWarning {
					t.Errorf("diagnostic severity = %q, want warning", diag.Severity)
				}
			}
			if (route.Swag != nil) != c.wantSwag {
				t.Errorf("route.Swag = %+v, wantSwag = %v", route.Swag, c.wantSwag)
			}
			if c.name == "summary/description/tags still applied despite mismatch" {
				if route.Swag == nil || route.Swag.Summary != "Get a user" {
					t.Errorf("expected Summary to survive a @Router mismatch, got %+v", route.Swag)
				}
			}
		})
	}
}
