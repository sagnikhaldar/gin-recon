package fleet

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/sagnikhaldar/gin-recon/internal/globmatch"
)

const (
	githubAPIBase           = "https://api.github.com"
	maxDiscoveryPages       = 100
	perPage                 = 100
	maxAPIResponseBytes     = 16 << 20
	discoveryUserAgent      = "gin-recon-fleet"
	discoveryRequestTimeout = 30 * time.Second
	discoveryAttempts       = 3
	DefaultMaxRepos         = 100
	MaxMaxRepos             = 10_000
)

var orgNamePattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,99})$`)

type DiscoverOptions struct {
	Org             string
	IncludeArchived bool
	IncludeForks    bool
	RepoInclude     []string
	RepoExclude     []string
	MaxRepos        int
	Token           string
	HTTPClient      *http.Client
	APIBase         string
}

type RepositoryDisposition struct {
	ID            int64  `json:"id,omitempty"`
	FullName      string `json:"fullName"`
	DefaultBranch string `json:"defaultBranch,omitempty"`
	PushedAt      string `json:"pushedAt,omitempty"`
	Status        string `json:"status"`
	Reason        string `json:"reason,omitempty"`
}

type RateLimitState struct {
	Remaining int    `json:"remaining"`
	Reset     string `json:"reset,omitempty"`
}

type DiscoverySummary struct {
	Complete     bool                    `json:"complete"`
	PagesFetched int                     `json:"pagesFetched"`
	Visible      int                     `json:"visibleRepositories"`
	Selected     int                     `json:"selectedRepositories"`
	Repositories []RepositoryDisposition `json:"repositories"`
	Diagnostics  []string                `json:"diagnostics,omitempty"`
	RateLimit    *RateLimitState         `json:"rateLimit,omitempty"`
}

type DiscoveryResult struct {
	Manifest        *Manifest
	Incomplete      bool
	SkippedBadName  []string
	SkippedDisabled []string
	SkippedEmpty    []string
	Summary         DiscoverySummary
}

type githubRepo struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	FullName      string `json:"full_name"`
	Private       bool   `json:"private"`
	Visibility    string `json:"visibility"`
	PushedAt      string `json:"pushed_at"`
	Archived      bool   `json:"archived"`
	Disabled      bool   `json:"disabled"`
	Fork          bool   `json:"fork"`
	Size          int64  `json:"size"`
	CloneURL      string `json:"clone_url"`
	DefaultBranch string `json:"default_branch"`
}

type pageResult struct {
	repositories []githubRepo
	hasNext      bool
	rateLimit    *RateLimitState
}

type discoveryHTTPError struct {
	message   string
	retryable bool
}

func (e *discoveryHTTPError) Error() string { return e.message }

func DiscoverOrgRepos(ctx context.Context, opts DiscoverOptions) (*DiscoveryResult, error) {
	if !orgNamePattern.MatchString(opts.Org) {
		return nil, fmt.Errorf("fleet: --org: %q must contain only letters, numbers, or interior hyphens", opts.Org)
	}
	maxRepos := opts.MaxRepos
	if maxRepos == 0 {
		maxRepos = DefaultMaxRepos
	}
	if maxRepos < 1 || maxRepos > MaxMaxRepos {
		return nil, fmt.Errorf("fleet: --max-repos: must be between 1 and %d, got %d", MaxMaxRepos, maxRepos)
	}

	client := opts.HTTPClient
	if client == nil {
		client = newDiscoveryClient()
	} else {
		// Do not trust an injected client's redirect policy: Authorization is
		// attached below, so following even a same-looking 3xx could forward a
		// workspace token outside the configured API origin.
		clone := *client
		clone.CheckRedirect = refuseDiscoveryRedirect
		client = &clone
	}
	base := opts.APIBase
	if base == "" {
		base = githubAPIBase
	}
	baseURL, err := url.Parse(base)
	if err != nil || baseURL.Scheme == "" || baseURL.Host == "" {
		return nil, fmt.Errorf("fleet: --org: invalid GitHub API base %q", base)
	}

	result := &DiscoveryResult{}
	result.Summary.Complete = true
	seen := make(map[string]bool)
	var targets []Target
	hasNext := true
	for page := 1; page <= maxDiscoveryPages && hasNext; page++ {
		pageURL := repositoryPageURL(baseURL, opts.Org, page)
		fetched, err := fetchRepoPageWithRetry(ctx, client, pageURL, opts.Token)
		if err != nil {
			if page == 1 {
				return nil, err
			}
			result.Incomplete = true
			result.Summary.Complete = false
			result.Summary.Diagnostics = append(result.Summary.Diagnostics, fmt.Sprintf("page %d: %v", page, err))
			break
		}
		result.Summary.PagesFetched++
		result.Summary.RateLimit = fetched.rateLimit
		hasNext = fetched.hasNext

		for _, repo := range fetched.repositories {
			identity := strings.ToLower(repo.FullName)
			if identity == "" {
				identity = strings.ToLower(opts.Org + "/" + repo.Name)
			}
			if seen[identity] {
				result.Summary.Repositories = append(result.Summary.Repositories, disposition(repo, "skipped", "duplicate API entry"))
				continue
			}
			seen[identity] = true
			result.Summary.Visible++

			status, reason := repositorySelection(repo, opts)
			gitSource := &GitSource{URL: repo.CloneURL, Ref: repo.DefaultBranch}
			if status == "selected" {
				if err := validateGitSource(repo.Name, gitSource); err != nil {
					status, reason = "skipped", "repository source metadata is invalid"
					result.Incomplete = true
					result.Summary.Complete = false
				}
			}
			if status == "selected" && len(targets) >= maxRepos {
				status, reason = "capped", fmt.Sprintf("selected repository cap %d reached", maxRepos)
				result.Incomplete = true
				result.Summary.Complete = false
			}
			result.Summary.Repositories = append(result.Summary.Repositories, disposition(repo, status, reason))
			switch reason {
			case "repository is disabled":
				result.SkippedDisabled = append(result.SkippedDisabled, repo.FullName)
			case "repository is empty":
				result.SkippedEmpty = append(result.SkippedEmpty, repo.FullName)
			case "repository name is not a safe fleet target name":
				result.SkippedBadName = append(result.SkippedBadName, repo.FullName)
			}
			if status != "selected" {
				continue
			}
			targets = append(targets, Target{
				Name: repo.Name,
				Git:  gitSource,
				GitHub: &GitHubMeta{
					ID: repo.ID, FullName: repo.FullName, DefaultBranch: repo.DefaultBranch,
					Private: repo.Private, Visibility: repo.Visibility, PushedAt: repo.PushedAt,
					Archived: repo.Archived, Fork: repo.Fork,
				},
			})
		}
	}
	if hasNext && result.Summary.PagesFetched == maxDiscoveryPages {
		result.Incomplete = true
		result.Summary.Complete = false
		result.Summary.Diagnostics = append(result.Summary.Diagnostics, fmt.Sprintf("enumeration exceeded %d pages", maxDiscoveryPages))
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("fleet: --org %q: no repositories discovered or selected; inspect discovery filters, repository dispositions, and token access", opts.Org)
	}
	result.Summary.Selected = len(targets)
	result.Manifest = &Manifest{Version: 1, Targets: targets}
	return result, nil
}

func repositorySelection(repo githubRepo, opts DiscoverOptions) (status, reason string) {
	switch {
	case repo.Disabled:
		return "skipped", "repository is disabled"
	case repo.Size == 0:
		return "skipped", "repository is empty"
	case repo.Archived && !opts.IncludeArchived:
		return "skipped", "archived repositories were excluded"
	case repo.Fork && !opts.IncludeForks:
		return "skipped", "forks were excluded"
	case len(opts.RepoInclude) > 0 && !globmatch.Any(opts.RepoInclude, repo.Name) && !globmatch.Any(opts.RepoInclude, repo.FullName):
		return "filtered", "repository did not match --repo-include"
	case globmatch.Any(opts.RepoExclude, repo.Name) || globmatch.Any(opts.RepoExclude, repo.FullName):
		return "filtered", "repository matched --repo-exclude"
	case ValidTargetName(repo.Name) != nil:
		return "skipped", "repository name is not a safe fleet target name"
	case repo.CloneURL == "":
		return "skipped", "repository lacks clone URL"
	default:
		return "selected", ""
	}
}

func disposition(repo githubRepo, status, reason string) RepositoryDisposition {
	return RepositoryDisposition{ID: repo.ID, FullName: repo.FullName, DefaultBranch: repo.DefaultBranch, PushedAt: repo.PushedAt, Status: status, Reason: reason}
}

func repositoryPageURL(base *url.URL, org string, page int) string {
	u := *base
	u.Path = strings.TrimRight(u.Path, "/") + "/orgs/" + url.PathEscape(org) + "/repos"
	query := u.Query()
	query.Set("per_page", strconv.Itoa(perPage))
	query.Set("sort", "full_name")
	if page > 1 {
		query.Set("page", strconv.Itoa(page))
	}
	u.RawQuery = query.Encode()
	u.Fragment = ""
	return u.String()
}

func newDiscoveryClient() *http.Client {
	return &http.Client{
		Timeout:       discoveryRequestTimeout,
		CheckRedirect: refuseDiscoveryRedirect,
	}
}

func refuseDiscoveryRedirect(req *http.Request, via []*http.Request) error {
	return fmt.Errorf("fleet: --org: refusing to follow a redirect from the GitHub API (to %s)", req.URL)
}

func fetchRepoPageWithRetry(ctx context.Context, client *http.Client, pageURL, token string) (pageResult, error) {
	var last error
	for attempt := 1; attempt <= discoveryAttempts; attempt++ {
		result, err := fetchRepoPage(ctx, client, pageURL, token)
		if err == nil {
			return result, nil
		}
		last = err
		httpErr, retryable := err.(*discoveryHTTPError)
		if !retryable || !httpErr.retryable || attempt == discoveryAttempts {
			break
		}
		timer := time.NewTimer(time.Duration(attempt) * 100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return pageResult{}, fmt.Errorf("fleet: --org: %w", ctx.Err())
		case <-timer.C:
		}
	}
	return pageResult{}, last
}

func fetchRepoPage(ctx context.Context, client *http.Client, pageURL, token string) (pageResult, error) {
	requestContext, cancel := context.WithTimeout(ctx, discoveryRequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestContext, http.MethodGet, pageURL, nil)
	if err != nil {
		return pageResult{}, fmt.Errorf("fleet: --org: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", discoveryUserAgent)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		if strings.Contains(err.Error(), "refusing to follow a redirect") {
			return pageResult{}, err
		}
		return pageResult{}, &discoveryHTTPError{message: fmt.Sprintf("fleet: --org: requesting GitHub repository page: %v", err), retryable: true}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAPIResponseBytes+1))
	if err != nil {
		return pageResult{}, &discoveryHTTPError{message: fmt.Sprintf("fleet: --org: reading response: %v", err), retryable: true}
	}
	if len(body) > maxAPIResponseBytes {
		return pageResult{}, fmt.Errorf("fleet: --org: GitHub API response exceeded the %d MiB page limit", maxAPIResponseBytes>>20)
	}

	rate := parseRateLimit(resp.Header)
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return pageResult{}, fmt.Errorf("fleet: --org: organization not found, or the configured token cannot see it")
	case http.StatusForbidden, http.StatusTooManyRequests:
		if rate != nil && rate.Remaining == 0 {
			return pageResult{}, &discoveryHTTPError{message: fmt.Sprintf("fleet: --org: GitHub API rate limit is exhausted (status %d)", resp.StatusCode), retryable: true}
		}
		return pageResult{}, fmt.Errorf("fleet: --org: GitHub API access denied (status %d); check organization read access", resp.StatusCode)
	default:
		return pageResult{}, &discoveryHTTPError{message: fmt.Sprintf("fleet: --org: GitHub API returned status %d", resp.StatusCode), retryable: resp.StatusCode >= 500}
	}

	var repositories []githubRepo
	if err := json.Unmarshal(body, &repositories); err != nil {
		return pageResult{}, fmt.Errorf("fleet: --org: decoding GitHub API response: %w", err)
	}
	return pageResult{repositories: repositories, hasNext: linkHasNext(resp.Header.Get("Link")), rateLimit: rate}, nil
}

func parseRateLimit(header http.Header) *RateLimitState {
	value := header.Get("X-RateLimit-Remaining")
	if value == "" {
		return nil
	}
	remaining, err := strconv.Atoi(value)
	if err != nil {
		return nil
	}
	state := &RateLimitState{Remaining: remaining}
	if epoch, err := strconv.ParseInt(header.Get("X-RateLimit-Reset"), 10, 64); err == nil && epoch > 0 {
		state.Reset = time.Unix(epoch, 0).UTC().Format(time.RFC3339)
	}
	return state
}

// linkHasNext treats Link as pagination metadata only. The next request URL
// is reconstructed against APIBase, so authorization is never forwarded to
// an origin supplied by a response header.
func linkHasNext(link string) bool {
	for _, part := range strings.Split(link, ",") {
		if strings.Contains(part, `rel="next"`) {
			return true
		}
	}
	return false
}
