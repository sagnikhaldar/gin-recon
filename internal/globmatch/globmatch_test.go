package globmatch

import "testing"

func TestMatch(t *testing.T) {
	for _, tc := range []struct {
		pattern, target string
		want            bool
	}{
		{"/admin/**", "/admin/users", true},
		{"/admin/**", "/admin/users/123", true},
		{"/admin/**", "/admin", true},
		{"/admin/**", "/other", false},
		{"/admin/*", "/admin/users", true},
		{"/admin/*", "/admin/users/123", false},
		{"/health", "/health", true},
		{"/health", "/healthz", false},
		{"/*/users", "/admin/users", true},
		{"/*/users", "/admin/sub/users", false},
		{"**/*.go", "internal/analyzer/loader.go", true},
		{"**/*.go", "main.go", true},
		{"**/*.go", "internal/analyzer/loader.txt", false},
		{"**/generated/**", "internal/api/generated/routes.go", true},
		{"**/generated/**", "internal/api/routes.go", false},
	} {
		if got := Match(tc.pattern, tc.target); got != tc.want {
			t.Errorf("Match(%q, %q) = %v, want %v", tc.pattern, tc.target, got, tc.want)
		}
	}
}

func TestAny(t *testing.T) {
	patterns := []string{"vendor/**", "**/*_test.go"}
	if !Any(patterns, "vendor/github.com/x/y.go") {
		t.Error("expected vendor/** to match")
	}
	if !Any(patterns, "internal/foo_test.go") {
		t.Error("expected **/*_test.go to match")
	}
	if Any(patterns, "internal/foo.go") {
		t.Error("expected no match")
	}
	if Any(nil, "anything") {
		t.Error("expected no match against an empty pattern list")
	}
}
