// Package fleet implements gin-recon's fleet command
// (docs/adr/0018-fleet-scanning.md): orchestrating one audit subprocess per
// target named in a manifest, aggregating the results, and supporting
// checkpointed resume. It never calls internal/analyzer directly — every
// target's own report comes from re-invoking the same gin-recon binary
// every other caller already uses, so a fleet run's per-target results stay
// byte-identical to running audit on that target directly.
package fleet

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
)

// validTargetName matches docs/adr/0018-fleet-scanning.md's target name
// rule: it becomes a per-target output subdirectory name, so it is
// validated up front and rejected outright on a bad character rather than
// silently sanitized into something the manifest author didn't write.
var validTargetName = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// ValidTargetName reports whether name is a safe fleet target name,
// returning a descriptive error if not. Exported so external, untrusted
// fleet.json data — a --baseline file (baseline.go's LoadBaseline) or a
// render --report file (cmd/gin-recon's runFleetRender) — can validate a
// target Name before ever using it to build a filesystem path. Both read a
// different shape (Aggregate/TargetResult, not Manifest/Target) than
// ParseManifest validates, so they never go through this check any other
// way; a hand-written --targets manifest and --org's own discovery
// (github.go) already call this same check by construction.
func ValidTargetName(name string) error {
	if name == "" || name == "." || name == ".." || !validTargetName.MatchString(name) {
		return fmt.Errorf("fleet: target name %q must match %s", name, validTargetName.String())
	}
	return nil
}

// GitSource names a remote target to shallow-clone before scanning
// (docs/adr/0019-fleet-remote-targets.md). URL must be an https:// URL with
// no embedded userinfo; Ref is optional and defaults to the remote's own
// default branch.
type GitSource struct {
	URL string `json:"url"`
	Ref string `json:"ref,omitempty"`
}

// GitHubMeta is discovery provenance a --org run records alongside a
// discovered target (docs/adr/0021-fleet-org-enumeration.md) — never
// required, never written by a hand-authored manifest, and never read by
// anything that resolves or scans the target. It exists purely so
// discovered-targets.json stays a useful audit record of *why* a repository
// was or wasn't included, independent of GitHub's own state possibly
// changing before the next run.
type GitHubMeta struct {
	ID            int64  `json:"id,omitempty"`
	FullName      string `json:"fullName,omitempty"`
	DefaultBranch string `json:"defaultBranch,omitempty"`
	Private       bool   `json:"private,omitempty"`
	Visibility    string `json:"visibility,omitempty"`
	PushedAt      string `json:"pushedAt,omitempty"`
	Archived      bool   `json:"archived,omitempty"`
	Fork          bool   `json:"fork,omitempty"`
}

// Target is one entry in a targets manifest. Exactly one of Src (a local
// directory, ADR 0018) or Git (a remote to clone, ADR 0019) must be set.
type Target struct {
	Name   string      `json:"name"`
	Src    string      `json:"src,omitempty"`
	Git    *GitSource  `json:"git,omitempty"`
	GitHub *GitHubMeta `json:"github,omitempty"`
}

// Host returns the target's git remote hostname for allowlist matching. It
// is only meaningful when Git is non-nil and the manifest already passed
// LoadManifest's own URL validation.
func (t Target) Host() string {
	if t.Git == nil {
		return ""
	}
	u, err := url.Parse(t.Git.URL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// Manifest is the strict, data-only shape of a --targets file.
type Manifest struct {
	Version int      `json:"version"`
	Targets []Target `json:"targets"`
}

// LoadManifest reads and strictly validates a targets file, returning both
// the decoded Manifest and its raw bytes — the raw bytes are hashed into the
// checkpoint identity (see checkpoint.go) so a resumed run can detect a
// manifest that changed since the checkpoint was written.
func LoadManifest(path string) (*Manifest, []byte, error) {
	data, err := ReadBoundedFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("fleet: reading --targets file: %w", err)
	}
	m, err := ParseManifest(data)
	if err != nil {
		return nil, nil, err
	}
	return m, data, nil
}

// ParseManifest strictly validates a manifest's raw bytes — the same
// validation LoadManifest applies to a hand-written --targets file, factored
// out so a manifest built in memory (--repo, docs/adr/0038-fleet-repo-shorthand.md)
// goes through the identical checks rather than a second, potentially
// divergent copy of them.
func ParseManifest(data []byte) (*Manifest, error) {
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return nil, fmt.Errorf("fleet: invalid targets file: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("fleet: invalid targets file: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("fleet: invalid targets file: trailing content after the top-level object")
	}
	if m.Version != 1 {
		return nil, fmt.Errorf("fleet: targets file version must be 1, got %d", m.Version)
	}
	if len(m.Targets) == 0 {
		return nil, fmt.Errorf("fleet: targets file has no targets")
	}

	seen := make(map[string]bool, len(m.Targets))
	for _, t := range m.Targets {
		if err := ValidTargetName(t.Name); err != nil {
			return nil, err
		}
		if seen[t.Name] {
			return nil, fmt.Errorf("fleet: duplicate target name %q", t.Name)
		}
		seen[t.Name] = true

		if (t.Src == "") == (t.Git == nil) {
			return nil, fmt.Errorf("fleet: target %q: exactly one of \"src\" or \"git\" is required", t.Name)
		}
		if t.Git != nil {
			if err := validateGitSource(t.Name, t.Git); err != nil {
				return nil, err
			}
		}
	}
	return &m, nil
}

func rejectDuplicateJSONKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	const maxJSONDepth = 100
	var readValue func(int) error
	readValue = func(depth int) error {
		if depth > maxJSONDepth {
			return fmt.Errorf("JSON nesting exceeds %d levels", maxJSONDepth)
		}
		token, err := dec.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for dec.More() {
				keyToken, err := dec.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return fmt.Errorf("object key is not a string")
				}
				if seen[key] {
					return fmt.Errorf("duplicate object key %q", key)
				}
				seen[key] = true
				if err := readValue(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for dec.More() {
				if err := readValue(depth + 1); err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("unexpected delimiter %q", delim)
		}
		_, err = dec.Token()
		return err
	}
	if err := readValue(0); err != nil {
		return err
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("trailing content after the top-level value")
	}
	return nil
}

// validateGitSource enforces docs/adr/0019-fleet-remote-targets.md's URL
// shape up front, at manifest-load time — before any network access is even
// contemplated, and regardless of whether --allow-remote-targets ends up
// being set for this invocation.
func validateGitSource(name string, g *GitSource) error {
	if g.URL == "" {
		return fmt.Errorf("fleet: target %q: git.url is required", name)
	}
	u, err := url.Parse(g.URL)
	if err != nil {
		return fmt.Errorf("fleet: target %q: git.url %q could not be parsed: %w", name, g.URL, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("fleet: target %q: git.url must be https://, got scheme %q", name, u.Scheme)
	}
	if u.User != nil {
		return fmt.Errorf("fleet: target %q: git.url must not contain embedded credentials; use fleet.allowedRemoteHosts[].tokenEnv instead", name)
	}
	if u.Hostname() == "" {
		return fmt.Errorf("fleet: target %q: git.url has no host", name)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("fleet: target %q: git.url must not contain a query or fragment", name)
	}
	if !validGitRef(g.Ref) {
		return fmt.Errorf("fleet: target %q: git.ref %q is not a safe Git ref", name, g.Ref)
	}
	return nil
}

func validGitRef(ref string) bool {
	if ref == "" {
		return true
	}
	if ref == "@" || strings.HasPrefix(ref, "-") || strings.HasSuffix(ref, ".") || strings.HasSuffix(ref, "/") ||
		strings.Contains(ref, "..") || strings.Contains(ref, "@{") || strings.Contains(ref, "//") ||
		strings.ContainsAny(ref, "\x00\r\n ~^:?*[\\") {
		return false
	}
	for _, component := range strings.Split(ref, "/") {
		if component == "" || strings.HasPrefix(component, ".") || strings.HasSuffix(component, ".lock") {
			return false
		}
	}
	return true
}
