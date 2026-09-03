package fleet

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/sagnikhaldar/gin-recon/internal/globmatch"
)

// githubAPIBase is the default GitHub REST API host. Overridable in
// DiscoverOptions purely for tests — production callers never set it.
const githubAPIBase = "https://api.github.com"

// maxDiscoveryPages bounds pagination independent of MaxRepos
// (docs/adr/0021-fleet-org-enumeration.md): 100 pages at up to 100
// repositories per page is 10,000 repositories, regardless of how a
// pathological or hostile response might try to keep a Link header going.
const maxDiscoveryPages = 100

const perPage = 100

// maxAPIResponseBytes bounds one page's response body, read via
// io.LimitReader(..., maxAPIResponseBytes+1) so an oversized response is
// detected and reported clearly rather than silently truncated into a
// confusing JSON-decode error.
const maxAPIResponseBytes = 16 << 20

// discoveryUserAgent identifies fleet's own GitHub API calls, per GitHub's
// own API guidance and so a response ever needing follow-up is attributable
// to this specific caller rather than a generic HTTP client string.
const discoveryUserAgent = "gin-recon-fleet"

var orgNamePattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,99})$`)

// DiscoverOptions configures one --org enumeration pass.
type DiscoverOptions struct {
	Org             string
	IncludeArchived bool
	IncludeForks    bool
	RepoInclude     []string // glob against repo name and "org/name"; empty means include all
	RepoExclude     []string
	MaxRepos        int // 0 means DefaultMaxRepos
	Token           string
	HTTPClient      *http.Client // nil builds a redirect-rejecting client (see newDiscoveryClient)
	APIBase         string       // "" uses githubAPIBase
}

// DefaultMaxRepos and MaxMaxRepos are --max-repos's default and hard cap
// (docs/adr/0021-fleet-org-enumeration.md).
const (
	DefaultMaxRepos = 100
	MaxMaxRepos     = 1000
)

// DiscoveryResult is a --org enumeration's outcome: a Manifest in the exact
// shape LoadManifest already produces from a hand-written file, plus
// whether the discovered list is known to be partial and which
// repositories were left out and why.
type DiscoveryResult struct {
	Manifest        *Manifest
	Incomplete      bool
	SkippedBadName  []string // repository full names skipped: name doesn't fit a target name
	SkippedDisabled []string // repository full names skipped: GitHub has disabled the repository
	SkippedEmpty    []string // repository full names skipped: zero content, nothing to clone
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
	Size          int64  `json:"size"` // KB; 0 means an empty repository
	CloneURL      string `json:"clone_url"`
	DefaultBranch string `json:"default_branch"`
}

// DiscoverOrgRepos enumerates a GitHub organization's repositories and
// turns each into a git Target, per docs/adr/0021-fleet-org-enumeration.md.
// It performs its own network calls directly — the caller is responsible
// for having already checked --allow-remote-targets and that
// fleet.allowedRemoteHosts actually authorizes api.github.com before ever
// calling this, the same two-gate rule ADR 0019 established for the clones
// this discovery result will go on to request.
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
	}
	base := opts.APIBase
	if base == "" {
		base = githubAPIBase
	}

	var targets []Target
	result := &DiscoveryResult{}

	url := fmt.Sprintf("%s/orgs/%s/repos?per_page=%d&sort=full_name", base, opts.Org, perPage)
	for page := 0; url != "" && page < maxDiscoveryPages && len(targets) < maxRepos; page++ {
		repos, next, err := fetchRepoPage(ctx, client, url, opts.Token)
		if err != nil {
			return nil, err
		}
		for _, r := range repos {
			if r.Disabled {
				result.SkippedDisabled = append(result.SkippedDisabled, r.FullName)
				continue
			}
			if r.Size == 0 {
				result.SkippedEmpty = append(result.SkippedEmpty, r.FullName)
				continue
			}
			if r.Archived && !opts.IncludeArchived {
				continue
			}
			if r.Fork && !opts.IncludeForks {
				continue
			}
			if len(opts.RepoInclude) > 0 && !globmatch.Any(opts.RepoInclude, r.Name) && !globmatch.Any(opts.RepoInclude, r.FullName) {
				continue
			}
			if globmatch.Any(opts.RepoExclude, r.Name) || globmatch.Any(opts.RepoExclude, r.FullName) {
				continue
			}
			if len(targets) >= maxRepos {
				result.Incomplete = true
				break
			}
			if !validTargetName.MatchString(r.Name) {
				result.SkippedBadName = append(result.SkippedBadName, r.FullName)
				continue
			}
			targets = append(targets, Target{
				Name: r.Name,
				Git:  &GitSource{URL: r.CloneURL, Ref: r.DefaultBranch},
				GitHub: &GitHubMeta{
					ID:         r.ID,
					FullName:   r.FullName,
					Private:    r.Private,
					Visibility: r.Visibility,
					PushedAt:   r.PushedAt,
					Archived:   r.Archived,
					Fork:       r.Fork,
				},
			})
		}
		url = next
	}
	if url != "" {
		result.Incomplete = true
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("fleet: --org %q: no repositories discovered (check the organization name, --include-archived/--include-forks/--repo-include/--repo-exclude, and that the token in fleet.allowedRemoteHosts has access)", opts.Org)
	}

	result.Manifest = &Manifest{Version: 1, Targets: targets}
	return result, nil
}

// newDiscoveryClient rejects redirects rather than following them. A
// redirected GitHub API response would otherwise be silently retried
// against whatever host the redirect names, bypassing the whole point of
// requiring api.github.com in fleet.allowedRemoteHosts
// (docs/adr/0019-fleet-remote-targets.md's two-gate model): the allowlist
// only means something if this client actually stops at the host it names.
func newDiscoveryClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return fmt.Errorf("fleet: --org: refusing to follow a redirect from the GitHub API (to %s)", req.URL)
		},
	}
}

// fetchRepoPage performs one paginated GitHub API request, returning the
// decoded repositories and the next page's URL (empty when there is none).
func fetchRepoPage(ctx context.Context, client *http.Client, url, token string) ([]githubRepo, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", fmt.Errorf("fleet: --org: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", discoveryUserAgent)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		if isRedirectError(err) {
			return nil, "", err
		}
		return nil, "", fmt.Errorf("fleet: --org: requesting %s: %w", url, err)
	}
	defer resp.Body.Close()

	// Read one byte past the cap so an oversized response is detected and
	// reported clearly, rather than silently truncated by io.LimitReader
	// into a confusing "invalid JSON" decode error further down.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAPIResponseBytes+1))
	if err != nil {
		return nil, "", fmt.Errorf("fleet: --org: reading response: %w", err)
	}
	if len(body) > maxAPIResponseBytes {
		return nil, "", fmt.Errorf("fleet: --org: GitHub API response exceeded the %d MiB page limit", maxAPIResponseBytes>>20)
	}

	rateRemaining, hasRate := parseRateRemaining(resp.Header.Get("X-RateLimit-Remaining"))

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, "", fmt.Errorf("fleet: --org: organization not found, or the token in fleet.allowedRemoteHosts cannot see it")
	case http.StatusForbidden, http.StatusTooManyRequests:
		if hasRate && rateRemaining == 0 {
			return nil, "", fmt.Errorf("fleet: --org: GitHub API rate limit is exhausted (status %d)", resp.StatusCode)
		}
		return nil, "", fmt.Errorf("fleet: --org: GitHub API access denied (status %d) — check the token in fleet.allowedRemoteHosts has organization read access", resp.StatusCode)
	default:
		return nil, "", fmt.Errorf("fleet: --org: GitHub API returned status %d", resp.StatusCode)
	}

	var repos []githubRepo
	if err := json.Unmarshal(body, &repos); err != nil {
		return nil, "", fmt.Errorf("fleet: --org: decoding GitHub API response: %w", err)
	}
	return repos, nextPageURL(resp.Header.Get("Link")), nil
}

// isRedirectError recognizes the error newDiscoveryClient's CheckRedirect
// produces, which net/http wraps in a *url.Error — unwrapped here so the
// caller's message is exactly what CheckRedirect said, not a generic
// "requesting <url>: ..." wrapper that would bury the actual reason.
func isRedirectError(err error) bool {
	return strings.Contains(err.Error(), "refusing to follow a redirect")
}

func parseRateRemaining(header string) (int, bool) {
	if header == "" {
		return 0, false
	}
	n, err := strconv.Atoi(header)
	if err != nil {
		return 0, false
	}
	return n, true
}

// nextPageURL parses a GitHub API Link header
// (`<url>; rel="next", <url>; rel="last"`) for the "next" relation.
func nextPageURL(link string) string {
	for _, part := range strings.Split(link, ",") {
		segments := strings.Split(part, ";")
		if len(segments) < 2 {
			continue
		}
		if !strings.Contains(segments[1], `rel="next"`) {
			continue
		}
		u := strings.TrimSpace(segments[0])
		u = strings.TrimPrefix(u, "<")
		u = strings.TrimSuffix(u, ">")
		return u
	}
	return ""
}
