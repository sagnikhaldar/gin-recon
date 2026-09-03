package fleet

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func reposJSON(t *testing.T, repos []githubRepo) string {
	t.Helper()
	data, err := json.Marshal(repos)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestDiscoverOrgReposBasic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Accept"); got != "application/vnd.github+json" {
			t.Errorf("Accept header = %q", got)
		}
		w.Write([]byte(reposJSON(t, []githubRepo{
			{Name: "svc-a", FullName: "myorg/svc-a", CloneURL: "https://github.com/myorg/svc-a.git", DefaultBranch: "main"},
			{Name: "svc-b", FullName: "myorg/svc-b", CloneURL: "https://github.com/myorg/svc-b.git", DefaultBranch: "master"},
		})))
	}))
	defer srv.Close()

	result, err := DiscoverOrgRepos(context.Background(), DiscoverOptions{Org: "myorg", APIBase: srv.URL})
	if err != nil {
		t.Fatalf("DiscoverOrgRepos: %v", err)
	}
	if len(result.Manifest.Targets) != 2 {
		t.Fatalf("Targets = %+v", result.Manifest.Targets)
	}
	if result.Manifest.Targets[0].Name != "svc-a" || result.Manifest.Targets[0].Git.URL != "https://github.com/myorg/svc-a.git" {
		t.Errorf("Targets[0] = %+v", result.Manifest.Targets[0])
	}
	if result.Incomplete {
		t.Error("Incomplete = true, want false")
	}
}

func TestDiscoverOrgReposSendsAuthorizationHeader(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Write([]byte("[]"))
	}))
	defer srv.Close()

	_, err := DiscoverOrgRepos(context.Background(), DiscoverOptions{Org: "myorg", APIBase: srv.URL, Token: "secret123"})
	if err == nil {
		t.Fatal("expected an error: zero repositories discovered")
	}
	if gotAuth != "Bearer secret123" {
		t.Errorf("Authorization = %q, want \"Bearer secret123\"", gotAuth)
	}
}

func TestDiscoverOrgReposFiltersArchivedAndForksByDefault(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(reposJSON(t, []githubRepo{
			{Name: "active", CloneURL: "https://github.com/myorg/active.git"},
			{Name: "archived", CloneURL: "https://github.com/myorg/archived.git", Archived: true},
			{Name: "forked", CloneURL: "https://github.com/myorg/forked.git", Fork: true},
		})))
	}))
	defer srv.Close()

	result, err := DiscoverOrgRepos(context.Background(), DiscoverOptions{Org: "myorg", APIBase: srv.URL})
	if err != nil {
		t.Fatalf("DiscoverOrgRepos: %v", err)
	}
	if len(result.Manifest.Targets) != 1 || result.Manifest.Targets[0].Name != "active" {
		t.Fatalf("Targets = %+v, want only \"active\"", result.Manifest.Targets)
	}
}

func TestDiscoverOrgReposIncludeArchivedAndForks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(reposJSON(t, []githubRepo{
			{Name: "active", CloneURL: "https://github.com/myorg/active.git"},
			{Name: "archived", CloneURL: "https://github.com/myorg/archived.git", Archived: true},
			{Name: "forked", CloneURL: "https://github.com/myorg/forked.git", Fork: true},
		})))
	}))
	defer srv.Close()

	result, err := DiscoverOrgRepos(context.Background(), DiscoverOptions{
		Org: "myorg", APIBase: srv.URL, IncludeArchived: true, IncludeForks: true,
	})
	if err != nil {
		t.Fatalf("DiscoverOrgRepos: %v", err)
	}
	if len(result.Manifest.Targets) != 3 {
		t.Fatalf("Targets = %+v, want all 3", result.Manifest.Targets)
	}
}

func TestDiscoverOrgReposPaginates(t *testing.T) {
	var page1URL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "" && !strings.Contains(r.URL.RawQuery, "page=2") {
			w.Header().Set("Link", fmt.Sprintf(`<%s?page=2>; rel="next"`, page1URL))
			w.Write([]byte(reposJSON(t, []githubRepo{{Name: "a", CloneURL: "https://github.com/myorg/a.git"}})))
			return
		}
		w.Write([]byte(reposJSON(t, []githubRepo{{Name: "b", CloneURL: "https://github.com/myorg/b.git"}})))
	}))
	defer srv.Close()
	page1URL = srv.URL + "/orgs/myorg/repos"

	result, err := DiscoverOrgRepos(context.Background(), DiscoverOptions{Org: "myorg", APIBase: srv.URL, MaxRepos: 10})
	if err != nil {
		t.Fatalf("DiscoverOrgRepos: %v", err)
	}
	if len(result.Manifest.Targets) != 2 {
		t.Fatalf("Targets = %+v, want 2 across both pages", result.Manifest.Targets)
	}
}

func TestDiscoverOrgReposMaxReposMarksIncomplete(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(reposJSON(t, []githubRepo{
			{Name: "a", CloneURL: "https://github.com/myorg/a.git"},
			{Name: "b", CloneURL: "https://github.com/myorg/b.git"},
			{Name: "c", CloneURL: "https://github.com/myorg/c.git"},
		})))
	}))
	defer srv.Close()

	result, err := DiscoverOrgRepos(context.Background(), DiscoverOptions{Org: "myorg", APIBase: srv.URL, MaxRepos: 2})
	if err != nil {
		t.Fatalf("DiscoverOrgRepos: %v", err)
	}
	if len(result.Manifest.Targets) != 2 {
		t.Fatalf("Targets = %+v, want exactly 2 (MaxRepos)", result.Manifest.Targets)
	}
	if !result.Incomplete {
		t.Error("Incomplete = false, want true: 3 repos exist but MaxRepos capped at 2")
	}
}

func TestDiscoverOrgReposSkipsBadNames(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"name":"good-repo","full_name":"myorg/good-repo","clone_url":"https://github.com/myorg/good-repo.git"},
			{"name":"bad repo!","full_name":"myorg/bad repo!","clone_url":"https://github.com/myorg/bad.git"}]`))
	}))
	defer srv.Close()

	result, err := DiscoverOrgRepos(context.Background(), DiscoverOptions{Org: "myorg", APIBase: srv.URL})
	if err != nil {
		t.Fatalf("DiscoverOrgRepos: %v", err)
	}
	if len(result.Manifest.Targets) != 1 || result.Manifest.Targets[0].Name != "good-repo" {
		t.Fatalf("Targets = %+v", result.Manifest.Targets)
	}
	if len(result.Skipped) != 1 || result.Skipped[0] != "myorg/bad repo!" {
		t.Fatalf("Skipped = %+v", result.Skipped)
	}
}

func TestDiscoverOrgReposRejectsBadOrgName(t *testing.T) {
	_, err := DiscoverOrgRepos(context.Background(), DiscoverOptions{Org: "-bad-org"})
	if err == nil || !strings.Contains(err.Error(), "must contain only letters") {
		t.Fatalf("err = %v, want an org-name complaint", err)
	}
}

func TestDiscoverOrgReposRejectsOutOfRangeMaxRepos(t *testing.T) {
	_, err := DiscoverOrgRepos(context.Background(), DiscoverOptions{Org: "myorg", MaxRepos: MaxMaxRepos + 1})
	if err == nil || !strings.Contains(err.Error(), "--max-repos") {
		t.Fatalf("err = %v, want a --max-repos complaint", err)
	}
}

func TestDiscoverOrgReposHandlesNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	_, err := DiscoverOrgRepos(context.Background(), DiscoverOptions{Org: "myorg", APIBase: srv.URL})
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("err = %v, want a not-found complaint", err)
	}
}

func TestDiscoverOrgReposHandlesRateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	_, err := DiscoverOrgRepos(context.Background(), DiscoverOptions{Org: "myorg", APIBase: srv.URL})
	if err == nil || !strings.Contains(err.Error(), "rate limit") {
		t.Fatalf("err = %v, want a rate-limit complaint", err)
	}
}

func TestDiscoverOrgReposEmptyResultIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("[]"))
	}))
	defer srv.Close()

	_, err := DiscoverOrgRepos(context.Background(), DiscoverOptions{Org: "myorg", APIBase: srv.URL})
	if err == nil || !strings.Contains(err.Error(), "no repositories discovered") {
		t.Fatalf("err = %v, want a no-repositories complaint", err)
	}
}
