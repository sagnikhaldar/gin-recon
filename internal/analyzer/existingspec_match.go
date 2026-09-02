package analyzer

import "strings"

// pathSegments splits a path into its non-empty, slash-separated segments —
// the shared building block for both matchKey and pathParamNames below, so
// the two can never disagree about what counts as "a segment" (e.g. how
// leading/trailing slashes or a bare "/" are handled).
func pathSegments(path string) []string {
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "/")
}

// isParamSegment reports whether seg is a path parameter in either Gin's
// (":name", "*name") or OpenAPI's ("{name}") syntax.
func isParamSegment(seg string) bool {
	switch {
	case strings.HasPrefix(seg, ":"), strings.HasPrefix(seg, "*"):
		return true
	case strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") && len(seg) > 2:
		return true
	default:
		return false
	}
}

// paramName extracts the bare parameter name from a segment already
// confirmed by isParamSegment to be a parameter — ":id" / "*id" / "{id}" all
// yield "id".
func paramName(seg string) string {
	switch {
	case strings.HasPrefix(seg, ":"), strings.HasPrefix(seg, "*"):
		return seg[1:]
	case strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}"):
		return seg[1 : len(seg)-1]
	default:
		return seg
	}
}

// matchKey builds the comparable (method, path) identity ADR 0013's matching
// rule uses: method uppercased, and every parameter segment — regardless of
// which of Gin's or OpenAPI's syntaxes wrote it — erased to a bare "{}"
// placeholder. Erasing parameter names (rather than merely converting Gin's
// ":name"/"*name" to OpenAPI's "{name}") is deliberate: a document operation
// that names a path parameter differently from the code it documents must
// still be found and matched — that disagreement is exactly what the
// separate structural-compatibility check (paramNamesAgree) exists to catch
// and diagnose as openapi-spec-conflict, not something matching itself
// should silently treat as "no match, therefore orphaned." No other kind of
// difference is erased or tolerated: a literal segment, or a differing
// number of segments, never matches — per ADR 0013's explicit rejection of
// fuzzy/prefix matching.
func matchKey(method, path string) string {
	segments := pathSegments(path)
	key := make([]string, len(segments))
	for i, seg := range segments {
		if isParamSegment(seg) {
			key[i] = "{}"
		} else {
			key[i] = seg
		}
	}
	return strings.ToUpper(method) + " /" + strings.Join(key, "/")
}

// paramNames returns, in order, the bare names of every parameter segment in
// path (Gin or OpenAPI syntax — see isParamSegment/paramName).
func paramNames(path string) []string {
	var names []string
	for _, seg := range pathSegments(path) {
		if isParamSegment(seg) {
			names = append(names, paramName(seg))
		}
	}
	return names
}

// paramNamesAgree implements ADR 0013's structural-compatibility check for
// path parameters: a matched route and document operation must name their
// path parameters identically, in the same positions, before the document's
// parameter-level content (e.g. a parameter description) is trusted. Two
// paths that reached matchKey agreement always have the same number of
// parameter segments in the same positions, so this only ever compares
// names, never counts or positions.
func paramNamesAgree(routeParams, docParams []string) bool {
	if len(routeParams) != len(docParams) {
		return false // should-never-happen given matching already agreed on shape; defensive, not reachable in practice
	}
	for i := range routeParams {
		if routeParams[i] != docParams[i] {
			return false
		}
	}
	return true
}
