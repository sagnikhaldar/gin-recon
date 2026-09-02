package gin

import "testing"

// TestJoinPathsMatchesUpstream transcribes gin-gonic/gin@v1.10.0's own
// utils_test.go TestJoinPaths verbatim (verified against
// $GOMODCACHE/github.com/gin-gonic/gin@v1.10.0/utils_test.go), so a
// divergence from real Gin behavior is caught immediately rather than
// discovered later as a route-identity mismatch against a real target
// repository.
func TestJoinPathsMatchesUpstream(t *testing.T) {
	for _, tc := range []struct{ a, b, want string }{
		{"", "", ""},
		{"", "/", "/"},
		{"/a", "", "/a"},
		{"/a/", "", "/a/"},
		{"/a/", "/", "/a/"},
		{"/a", "/", "/a/"},
		{"/a", "/hola", "/a/hola"},
		{"/a/", "/hola", "/a/hola"},
		{"/a/", "/hola/", "/a/hola/"},
		{"/a/", "/hola//", "/a/hola/"},
	} {
		if got := JoinPaths(tc.a, tc.b); got != tc.want {
			t.Errorf("JoinPaths(%q, %q) = %q, want %q", tc.a, tc.b, got, tc.want)
		}
	}
}
