package fleet

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
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

var orgNamePattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,99})$`)

// DiscoverOptions configures one --org enumeration pass.
type DiscoverOptions struct {
	Org             string
	IncludeArchived bool
	IncludeForks    bool
	MaxRepos        int // 0 means DefaultMaxRepos
	Token           string
	HTTPClient      *http.Client // nil uses http.DefaultClient
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
// whether the discovered list is known to be partial.
type DiscoveryResult struct {
	Manifest   *Manifest
	Incomplete bool
	Skipped    []string // repository full names skipped for a bad target name
}

type githubRepo struct {
	Name          string `json:"name"`
	FullName      string `json:"full_name"`
	Archived      bool   `json:"archived"`
	Fork          bool   `json:"fork"`
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
		client = http.DefaultClient
	}
	base := opts.APIBase
	if base == "" {
		base = githubAPIBase
	}

	var targets []Target
	var skipped []string
	incomplete := false

	url := fmt.Sprintf("%s/orgs/%s/repos?per_page=%d&sort=full_name", base, opts.Org, perPage)
	for page := 0; url != "" && page < maxDiscoveryPages && len(targets) < maxRepos; page++ {
		repos, next, err := fetchRepoPage(ctx, client, url, opts.Token)
		if err != nil {
			return nil, err
		}
		for _, r := range repos {
			if r.Archived && !opts.IncludeArchived {
				continue
			}
			if r.Fork && !opts.IncludeForks {
				continue
			}
			if len(targets) >= maxRepos {
				incomplete = true
				break
			}
			if !validTargetName.MatchString(r.Name) {
				skipped = append(skipped, r.FullName)
				continue
			}
			targets = append(targets, Target{
				Name: r.Name,
				Git:  &GitSource{URL: r.CloneURL, Ref: r.DefaultBranch},
			})
		}
		url = next
	}
	if url != "" {
		incomplete = true
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("fleet: --org %q: no repositories discovered (check the organization name, --include-archived/--include-forks, and that the token in fleet.allowedRemoteHosts has access)", opts.Org)
	}

	return &DiscoveryResult{
		Manifest:   &Manifest{Version: 1, Targets: targets},
		Incomplete: incomplete,
		Skipped:    skipped,
	}, nil
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
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("fleet: --org: requesting %s: %w", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20)) // 16 MiB cap per response
	if err != nil {
		return nil, "", fmt.Errorf("fleet: --org: reading response: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, "", fmt.Errorf("fleet: --org: organization not found, or the token in fleet.allowedRemoteHosts cannot see it")
	case http.StatusForbidden, http.StatusTooManyRequests:
		return nil, "", fmt.Errorf("fleet: --org: GitHub API rate limit or access denied (status %d)", resp.StatusCode)
	default:
		return nil, "", fmt.Errorf("fleet: --org: GitHub API returned status %d", resp.StatusCode)
	}

	var repos []githubRepo
	if err := json.Unmarshal(body, &repos); err != nil {
		return nil, "", fmt.Errorf("fleet: --org: decoding GitHub API response: %w", err)
	}
	return repos, nextPageURL(resp.Header.Get("Link")), nil
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
