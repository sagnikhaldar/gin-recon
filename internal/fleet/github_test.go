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
		if got := r.Header.Get("User-Agent"); got != discoveryUserAgent {
			t.Errorf("User-Agent = %q, want %q", got, discoveryUserAgent)
		}
		w.Write([]byte(reposJSON(t, []githubRepo{
			{Name: "svc-a", FullName: "myorg/svc-a", CloneURL: "https://github.com/myorg/svc-a.git", DefaultBranch: "main", Size: 1},
			{Name: "svc-b", FullName: "myorg/svc-b", CloneURL: "https://github.com/myorg/svc-b.git", DefaultBranch: "master", Size: 1},
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
			{Name: "active", CloneURL: "https://github.com/myorg/active.git", Size: 1},
			{Name: "archived", CloneURL: "https://github.com/myorg/archived.git", Archived: true, Size: 1},
			{Name: "forked", CloneURL: "https://github.com/myorg/forked.git", Fork: true, Size: 1},
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
			{Name: "active", CloneURL: "https://github.com/myorg/active.git", Size: 1},
			{Name: "archived", CloneURL: "https://github.com/myorg/archived.git", Archived: true, Size: 1},
			{Name: "forked", CloneURL: "https://github.com/myorg/forked.git", Fork: true, Size: 1},
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
			w.Write([]byte(reposJSON(t, []githubRepo{{Name: "a", CloneURL: "https://github.com/myorg/a.git", Size: 1}})))
			return
		}
		w.Write([]byte(reposJSON(t, []githubRepo{{Name: "b", CloneURL: "https://github.com/myorg/b.git", Size: 1}})))
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
			{Name: "a", CloneURL: "https://github.com/myorg/a.git", Size: 1},
			{Name: "b", CloneURL: "https://github.com/myorg/b.git", Size: 1},
			{Name: "c", CloneURL: "https://github.com/myorg/c.git", Size: 1},
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
		w.Write([]byte(`[{"name":"good-repo","full_name":"myorg/good-repo","clone_url":"https://github.com/myorg/good-repo.git","size":1},
			{"name":"bad repo!","full_name":"myorg/bad repo!","clone_url":"https://github.com/myorg/bad.git","size":1}]`))
	}))
	defer srv.Close()

	result, err := DiscoverOrgRepos(context.Background(), DiscoverOptions{Org: "myorg", APIBase: srv.URL})
	if err != nil {
		t.Fatalf("DiscoverOrgRepos: %v", err)
	}
	if len(result.Manifest.Targets) != 1 || result.Manifest.Targets[0].Name != "good-repo" {
		t.Fatalf("Targets = %+v", result.Manifest.Targets)
	}
	if len(result.SkippedBadName) != 1 || result.SkippedBadName[0] != "myorg/bad repo!" {
		t.Fatalf("SkippedBadName = %+v", result.SkippedBadName)
	}
}

func TestDiscoverOrgReposSkipsDisabledAndEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(reposJSON(t, []githubRepo{
			{Name: "active", FullName: "myorg/active", CloneURL: "https://github.com/myorg/active.git", Size: 1},
			{Name: "disabled-repo", FullName: "myorg/disabled-repo", CloneURL: "https://github.com/myorg/disabled-repo.git", Disabled: true, Size: 1},
			{Name: "empty-repo", FullName: "myorg/empty-repo", CloneURL: "https://github.com/myorg/empty-repo.git", Size: 0},
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
	if len(result.SkippedDisabled) != 1 || result.SkippedDisabled[0] != "myorg/disabled-repo" {
		t.Errorf("SkippedDisabled = %+v", result.SkippedDisabled)
	}
	if len(result.SkippedEmpty) != 1 || result.SkippedEmpty[0] != "myorg/empty-repo" {
		t.Errorf("SkippedEmpty = %+v", result.SkippedEmpty)
	}
}

func TestDiscoverOrgReposRepoIncludeExclude(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(reposJSON(t, []githubRepo{
			{Name: "payments-api", CloneURL: "https://github.com/myorg/payments-api.git", Size: 1},
			{Name: "payments-worker", CloneURL: "https://github.com/myorg/payments-worker.git", Size: 1},
			{Name: "legacy-billing", CloneURL: "https://github.com/myorg/legacy-billing.git", Size: 1},
		})))
	}))
	defer srv.Close()

	result, err := DiscoverOrgRepos(context.Background(), DiscoverOptions{
		Org: "myorg", APIBase: srv.URL,
		RepoInclude: []string{"payments-*"},
		RepoExclude: []string{"*-worker"},
	})
	if err != nil {
		t.Fatalf("DiscoverOrgRepos: %v", err)
	}
	if len(result.Manifest.Targets) != 1 || result.Manifest.Targets[0].Name != "payments-api" {
		t.Fatalf("Targets = %+v, want only \"payments-api\"", result.Manifest.Targets)
	}
}

func TestDiscoverOrgReposRejectsRedirect(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(reposJSON(t, []githubRepo{{Name: "a", CloneURL: "https://github.com/myorg/a.git", Size: 1}})))
	}))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusFound)
	}))
	defer redirector.Close()

	_, err := DiscoverOrgRepos(context.Background(), DiscoverOptions{Org: "myorg", APIBase: redirector.URL})
	if err == nil || !strings.Contains(err.Error(), "refusing to follow a redirect") {
		t.Fatalf("err = %v, want a redirect-refusal complaint", err)
	}
}

func TestDiscoverOrgReposRecordsGitHubMetadata(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(reposJSON(t, []githubRepo{
			{ID: 42, Name: "svc-a", FullName: "myorg/svc-a", CloneURL: "https://github.com/myorg/svc-a.git", Private: true, Visibility: "private", PushedAt: "2026-09-01T00:00:00Z", Size: 1},
		})))
	}))
	defer srv.Close()

	result, err := DiscoverOrgRepos(context.Background(), DiscoverOptions{Org: "myorg", APIBase: srv.URL})
	if err != nil {
		t.Fatalf("DiscoverOrgRepos: %v", err)
	}
	gh := result.Manifest.Targets[0].GitHub
	if gh == nil || gh.ID != 42 || gh.FullName != "myorg/svc-a" || !gh.Private || gh.Visibility != "private" || gh.PushedAt != "2026-09-01T00:00:00Z" {
		t.Fatalf("GitHub = %+v", gh)
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
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	_, err := DiscoverOrgRepos(context.Background(), DiscoverOptions{Org: "myorg", APIBase: srv.URL})
	if err == nil || !strings.Contains(err.Error(), "rate limit") {
		t.Fatalf("err = %v, want a rate-limit complaint", err)
	}
}

func TestDiscoverOrgReposHandlesAccessDenied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "500")
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	_, err := DiscoverOrgRepos(context.Background(), DiscoverOptions{Org: "myorg", APIBase: srv.URL})
	if err == nil || !strings.Contains(err.Error(), "access denied") {
		t.Fatalf("err = %v, want an access-denied complaint (rate limit is not exhausted)", err)
	}
}

func TestDiscoverOrgReposHandlesOversizedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, maxAPIResponseBytes+1))
	}))
	defer srv.Close()

	_, err := DiscoverOrgRepos(context.Background(), DiscoverOptions{Org: "myorg", APIBase: srv.URL})
	if err == nil || !strings.Contains(err.Error(), "exceeded") {
		t.Fatalf("err = %v, want an exceeded-limit complaint", err)
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
