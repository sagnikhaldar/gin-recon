// Package globmatch implements the "*"/"**" path-glob matching
// docs/configuration-contract.md's policy selectors document (e.g.
// "/admin/**") — extracted from internal/policy, which introduced it first,
// so internal/analyzer's scan scoping (--include/--exclude/ignoreFile) can
// share the exact same matching rules rather than a second, potentially
// divergent implementation of the same "**" semantics.
package globmatch

import (
	"path"
	"strings"
)

// Match reports whether target matches pattern, where "*" matches exactly
// one path segment and "**" matches any number of segments, including zero.
// path.Match alone does not support "**".
func Match(pattern, target string) bool {
	patternSegs := strings.Split(strings.Trim(pattern, "/"), "/")
	targetSegs := strings.Split(strings.Trim(target, "/"), "/")
	return matchSegments(patternSegs, targetSegs)
}

// Any reports whether target matches at least one pattern in patterns.
func Any(patterns []string, target string) bool {
	for _, p := range patterns {
		if Match(p, target) {
			return true
		}
	}
	return false
}

func matchSegments(pattern, target []string) bool {
	if len(pattern) == 0 {
		return len(target) == 0
	}
	head := pattern[0]
	if head == "**" {
		if len(pattern) == 1 {
			return true // "**" at the end matches everything remaining, including nothing
		}
		for i := 0; i <= len(target); i++ {
			if matchSegments(pattern[1:], target[i:]) {
				return true
			}
		}
		return false
	}
	if len(target) == 0 {
		return false
	}
	// A bare "*" already matches any single segment via path.Match, but
	// segmentMatches also handles a partial-segment pattern combining a
	// wildcard with a literal — "*.go" — which docs/configuration-contract.md's
	// own example ("**/*.go") requires and a whole-segment-only "*" check
	// cannot express.
	if !segmentMatches(head, target[0]) {
		return false
	}
	return matchSegments(pattern[1:], target[1:])
}

// segmentMatches matches one path segment against one pattern segment using
// path.Match's shell-style wildcards ("*", "?", "[...]"), which never cross
// a "/" boundary — exactly the property needed here, since "/" boundaries
// are already handled by splitting into segments before this is called. An
// invalid pattern (mismatched brackets) matches nothing rather than erroring,
// since a malformed include/exclude glob should exclude nothing silently
// wrong rather than panic or abort a scan.
func segmentMatches(patternSeg, targetSeg string) bool {
	ok, err := path.Match(patternSeg, targetSeg)
	return err == nil && ok
}
