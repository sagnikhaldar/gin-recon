package analyzer

import "testing"

func TestMatchKeyGinAndOpenAPIParamSyntaxAgree(t *testing.T) {
	cases := []struct {
		method, path string
	}{
		{"GET", "/users/:id"},
		{"GET", "/users/{id}"},
		{"GET", "/users/{userId}"}, // different param name, same shape
		{"get", "/users/:id"},      // lowercase method
	}
	want := matchKey("GET", "/users/:id")
	for _, c := range cases {
		if got := matchKey(c.method, c.path); got != want {
			t.Errorf("matchKey(%q, %q) = %q, want %q", c.method, c.path, got, want)
		}
	}
}

func TestMatchKeyWildcardAgreesWithOpenAPIParam(t *testing.T) {
	got := matchKey("GET", "/static/*filepath")
	want := matchKey("GET", "/static/{path}")
	if got != want {
		t.Errorf("matchKey wildcard = %q, want %q (wildcard and named param erase to the same shape)", got, want)
	}
}

func TestMatchKeyDiffersOnLiteralSegment(t *testing.T) {
	if matchKey("GET", "/users/:id") == matchKey("GET", "/accounts/:id") {
		t.Error("differing literal segments must never match")
	}
}

func TestMatchKeyDiffersOnSegmentCount(t *testing.T) {
	if matchKey("GET", "/users/:id") == matchKey("GET", "/users/:id/profile") {
		t.Error("differing segment counts must never match")
	}
}

func TestMatchKeyDiffersOnMethod(t *testing.T) {
	if matchKey("GET", "/users/:id") == matchKey("POST", "/users/:id") {
		t.Error("differing methods must never match")
	}
}

func TestMatchKeyRootPath(t *testing.T) {
	if got, want := matchKey("GET", "/"), matchKey("GET", ""); got != want {
		t.Errorf("matchKey(%q) = %q, want %q to agree with empty path", "/", got, want)
	}
}

func TestParamNames(t *testing.T) {
	cases := []struct {
		path string
		want []string
	}{
		{"/users/:id", []string{"id"}},
		{"/users/{id}", []string{"id"}},
		{"/static/*filepath", []string{"filepath"}},
		{"/users/:id/posts/:postId", []string{"id", "postId"}},
		{"/users", nil},
		{"/", nil},
	}
	for _, c := range cases {
		got := paramNames(c.path)
		if len(got) != len(c.want) {
			t.Errorf("paramNames(%q) = %v, want %v", c.path, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("paramNames(%q) = %v, want %v", c.path, got, c.want)
				break
			}
		}
	}
}

func TestParamNamesAgree(t *testing.T) {
	if !paramNamesAgree([]string{"id"}, []string{"id"}) {
		t.Error("identical single param names should agree")
	}
	if paramNamesAgree([]string{"id"}, []string{"userId"}) {
		t.Error("differing param names should not agree")
	}
	if !paramNamesAgree(nil, nil) {
		t.Error("no params on either side should agree")
	}
	if paramNamesAgree([]string{"a", "b"}, []string{"a"}) {
		t.Error("differing counts should not agree")
	}
}
