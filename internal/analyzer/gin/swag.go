package gin

import (
	"fmt"
	"go/ast"
	"strings"

	"github.com/sagnikhaldar/gin-recon/internal/model"
)

// ParseSwagAnnotations extracts swaggo/swag-style (https://github.com/swaggo/swag)
// directives from a Go doc comment directly above a handler function
// declaration. Per docs/adr/0012-swag-annotation-evidence.md, only the
// directives with zero ambiguity about what they mean for OpenAPI prose are
// recognized:
//
//   - @Summary <text>                 — single line.
//   - @Description <text>             — may repeat across consecutive lines,
//     concatenated with a space, matching swaggo's own convention.
//   - @Tags <comma,separated,tags>
//   - @Router <path> [<HTTP_METHOD>]  — parsed for cross-checking only; see
//     ApplySwagFromDoc. Never used to set a route's actual path/method.
//   - @Deprecated                     — a bare marker line.
//
// swaggo's much larger @Param/@Success/@Failure type-schema system is
// deliberately not implemented — it would need its own model-registry
// subsystem, out of scope here (see ADR 0012's Rejected Alternatives).
//
// Returns nil, not an empty &model.SwagInfo{}, when doc contains no
// recognized directive at all — the overwhelmingly common case for an
// ordinary Go doc comment that just describes what a function does in
// prose. This keeps Route.Swag genuinely absent (not a garbage empty
// object) exactly when there is nothing to report.
func ParseSwagAnnotations(doc *ast.CommentGroup) *model.SwagInfo {
	if doc == nil {
		return nil
	}

	var info model.SwagInfo
	var descLines []string
	found := false

	for _, line := range swagCommentLines(doc) {
		if !strings.HasPrefix(line, "@") {
			continue
		}
		directive, rest := splitDirective(line)
		switch strings.ToLower(directive) {
		case "@summary":
			info.Summary = strings.TrimSpace(rest)
			found = true

		case "@description":
			if text := strings.TrimSpace(rest); text != "" {
				descLines = append(descLines, text)
			}
			found = true

		case "@tags":
			for _, tag := range strings.Split(rest, ",") {
				if tag = strings.TrimSpace(tag); tag != "" {
					info.Tags = append(info.Tags, tag)
				}
			}
			found = true

		case "@router":
			if path, method, ok := parseRouterDirective(rest); ok {
				info.RouterPath = path
				info.RouterMethod = method
				found = true
			}

		case "@deprecated":
			info.Deprecated = true
			found = true
		}
	}

	if !found {
		return nil
	}
	if len(descLines) > 0 {
		info.Description = strings.Join(descLines, " ")
	}
	return &info
}

// swagCommentLines flattens a doc comment's list of "// ..." line comments
// and "/* ... */" block comments into plain, trimmed text lines, stripping
// comment markers and any leading "*" a block comment's continuation lines
// conventionally carry. swaggo annotations are written as line comments in
// every real-world case this project has observed, but block-comment doc
// groups are valid Go and must not crash this parser.
func swagCommentLines(doc *ast.CommentGroup) []string {
	var lines []string
	for _, c := range doc.List {
		text := c.Text
		text = strings.TrimPrefix(text, "/*")
		text = strings.TrimSuffix(text, "*/")
		for _, sub := range strings.Split(text, "\n") {
			sub = strings.TrimSpace(sub)
			sub = strings.TrimPrefix(sub, "//")
			sub = strings.TrimSpace(sub)
			sub = strings.TrimPrefix(sub, "*")
			sub = strings.TrimSpace(sub)
			if sub != "" {
				lines = append(lines, sub)
			}
		}
	}
	return lines
}

// splitDirective splits a line already confirmed to start with "@" into its
// directive token ("@Summary") and the remaining text, if any.
func splitDirective(line string) (directive, rest string) {
	fields := strings.SplitN(line, " ", 2)
	if len(fields) == 1 {
		return fields[0], ""
	}
	return fields[0], fields[1]
}

// parseRouterDirective parses swaggo's "@Router <path> [<METHOD>]" form,
// e.g. "/users/{id} [get]". A malformed or partial line — missing the
// bracketed method, or missing a path entirely — is handled without a
// panic: real codebases routinely carry partially-written swag comments,
// and this analyzer must never crash on one.
func parseRouterDirective(rest string) (routerPath, method string, ok bool) {
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return "", "", false
	}
	open := strings.Index(rest, "[")
	if open < 0 {
		// No bracketed method at all — still record the path.
		return rest, "", true
	}
	closeRel := strings.Index(rest[open:], "]")
	if closeRel < 0 {
		return strings.TrimSpace(rest[:open]), "", strings.TrimSpace(rest[:open]) != ""
	}
	routerPath = strings.TrimSpace(rest[:open])
	method = strings.ToUpper(strings.TrimSpace(rest[open+1 : open+closeRel]))
	if routerPath == "" {
		return "", "", false
	}
	return routerPath, method, true
}

// ApplySwagFromDoc parses doc and, if it carries any recognized swag
// directive, attaches the result to route.Swag and returns a
// "swag-router-mismatch" diagnostic when the annotation's @Router path/method
// disagrees with route's own already-discovered GinPath/Method. It returns
// nil for both when doc carries no swag directive, and — critically — still
// attaches Swag even when a mismatch is found: a stale @Router line does not
// make the same comment's @Summary/@Description/@Tags/@Deprecated any less
// useful (docs/adr/0012-swag-annotation-evidence.md).
func ApplySwagFromDoc(route *model.Route, doc *ast.CommentGroup) *model.Diagnostic {
	info := ParseSwagAnnotations(doc)
	if info == nil {
		return nil
	}
	route.Swag = info
	return swagRouterMismatchDiagnostic(*route, *info)
}

func swagRouterMismatchDiagnostic(route model.Route, info model.SwagInfo) *model.Diagnostic {
	if info.RouterPath == "" && info.RouterMethod == "" {
		return nil
	}
	var mismatches []string
	if info.RouterPath != "" && swagPathForm(route.GinPath) != info.RouterPath {
		mismatches = append(mismatches, fmt.Sprintf("path %q vs discovered %q", info.RouterPath, route.GinPath))
	}
	if info.RouterMethod != "" && info.RouterMethod != route.Method {
		mismatches = append(mismatches, fmt.Sprintf("method %q vs discovered %q", info.RouterMethod, route.Method))
	}
	if len(mismatches) == 0 {
		return nil
	}
	return &model.Diagnostic{
		Code:     "swag-router-mismatch",
		Severity: model.DiagnosticWarning,
		Message:  fmt.Sprintf("@Router annotation disagrees with the discovered route (%s); analyzer evidence remains authoritative per ADR 0007/0012", strings.Join(mismatches, "; ")),
		Source:   route.Source,
	}
}

// swagPathForm converts Gin's :name/*name path syntax to swag/OpenAPI's
// {name} form, the form swaggo authors themselves write in an @Router
// annotation — so comparison is meaningful rather than a guaranteed mismatch
// on every parameterized route.
func swagPathForm(ginPath string) string {
	segments := strings.Split(ginPath, "/")
	for i, seg := range segments {
		switch {
		case strings.HasPrefix(seg, ":"):
			segments[i] = "{" + seg[1:] + "}"
		case strings.HasPrefix(seg, "*"):
			segments[i] = "{" + seg[1:] + "}"
		}
	}
	return strings.Join(segments, "/")
}
