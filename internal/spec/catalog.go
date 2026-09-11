// Package spec performs bounded, offline source-document discovery. It does
// not follow remote references, execute generators, or modify source specs.
package spec

import (
	"crypto/sha256"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sagnikhaldar/gin-recon/internal/model"
	"go.yaml.in/yaml/v3"
)

const (
	maxVisitedEntries = 100000
	maxCandidateFiles = 2048
	maxDocumentBytes  = 2 << 20
	maxCatalogBytes   = 16 << 20
	maxYAMLNodes      = 100000
	maxYAMLDepth      = 64
)

var operationMethods = map[string]bool{"get": true, "put": true, "post": true, "delete": true, "options": true, "head": true, "patch": true, "trace": true}

// Discover catalogs OpenAPI 3.x and Swagger 2 JSON/YAML beneath root.
func Discover(root string, routes []model.Route, coverage model.ScanCoverage) *model.SpecificationCatalog {
	cat := &model.SpecificationCatalog{Status: "complete", Specifications: []model.SpecificationRecord{}, Issues: []model.SpecificationIssue{}}
	var visited, candidates, total int
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		visited++
		if visited > maxVisitedEntries {
			cat.Status = "unknown"
			cat.Issues = append(cat.Issues, issue("spec-walk-limit", "", fmt.Sprintf("directory-entry limit %d reached", maxVisitedEntries)))
			return fs.SkipAll
		}
		if walkErr != nil {
			cat.Status = "unavailable"
			cat.Issues = append(cat.Issues, issue("spec-walk-unavailable", relative(root, path), walkErr.Error()))
			return nil
		}
		if entry.IsDir() {
			if path != root && (entry.Name() == ".git" || entry.Name() == "vendor" || entry.Name() == "node_modules" || strings.HasPrefix(entry.Name(), ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext != ".json" && ext != ".yaml" && ext != ".yml" {
			return nil
		}
		candidates++
		if candidates > maxCandidateFiles {
			cat.Status = "unknown"
			cat.Issues = append(cat.Issues, issue("spec-file-limit", "", fmt.Sprintf("candidate file limit %d reached", maxCandidateFiles)))
			return fs.SkipAll
		}
		if entry.Type()&os.ModeSymlink != 0 {
			cat.Status = "unknown"
			cat.Issues = append(cat.Issues, issue("spec-symlink-rejected", relative(root, path), "symbolic-link candidates are not followed"))
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			cat.Status = "unavailable"
			cat.Issues = append(cat.Issues, issue("spec-read-unavailable", relative(root, path), err.Error()))
			return nil
		}
		if info.Size() > maxDocumentBytes {
			cat.Status = "unknown"
			cat.Issues = append(cat.Issues, issue("spec-document-size-limit", relative(root, path), fmt.Sprintf("document exceeds %d-byte limit", maxDocumentBytes)))
			return nil
		}
		if total+int(info.Size()) > maxCatalogBytes {
			cat.Status = "unknown"
			cat.Issues = append(cat.Issues, issue("spec-catalog-size-limit", "", fmt.Sprintf("catalog read budget %d bytes reached", maxCatalogBytes)))
			return fs.SkipAll
		}
		if !info.Mode().IsRegular() {
			cat.Status = "unknown"
			cat.Issues = append(cat.Issues, issue("spec-nonregular-rejected", relative(root, path), "candidate is not a regular file"))
			return nil
		}
		data, err := readBounded(path, maxDocumentBytes)
		if err != nil {
			cat.Status = "unavailable"
			cat.Issues = append(cat.Issues, issue("spec-read-unavailable", relative(root, path), err.Error()))
			return nil
		}
		if len(data) > maxDocumentBytes {
			cat.Status = "unknown"
			cat.Issues = append(cat.Issues, issue("spec-document-size-limit", relative(root, path), fmt.Sprintf("document exceeds %d-byte limit", maxDocumentBytes)))
			return nil
		}
		if total+len(data) > maxCatalogBytes {
			cat.Status = "unknown"
			cat.Issues = append(cat.Issues, issue("spec-catalog-size-limit", "", fmt.Sprintf("catalog read budget %d bytes reached", maxCatalogBytes)))
			return fs.SkipAll
		}
		total += len(data)
		record, issues, detected := parseDocument(root, path, data)
		cat.Issues = append(cat.Issues, issues...)
		for _, parseIssue := range issues {
			switch parseIssue.Code {
			case "spec-parse-invalid", "spec-parse-limit", "spec-version-unsupported", "spec-remote-ref-rejected", "spec-ref-escape-rejected", "spec-local-ref-unavailable", "spec-ref-symlink-rejected":
				cat.Status = "unknown"
			}
		}
		if detected {
			cat.Specifications = append(cat.Specifications, record)
		}
		return nil
	})
	if err != nil {
		cat.Status = "unavailable"
		cat.Issues = append(cat.Issues, issue("spec-walk-unavailable", "", err.Error()))
	}
	sort.Slice(cat.Specifications, func(i, j int) bool { return cat.Specifications[i].Path < cat.Specifications[j].Path })
	sort.Slice(cat.Issues, func(i, j int) bool {
		if cat.Issues[i].Path == cat.Issues[j].Path {
			return cat.Issues[i].Code < cat.Issues[j].Code
		}
		return cat.Issues[i].Path < cat.Issues[j].Path
	})
	cat.Metrics = reconcile(cat.Specifications, routes, coverage, cat.Status)
	return cat
}

func readBounded(path string, limit int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("candidate is not a regular file")
	}
	return io.ReadAll(io.LimitReader(f, int64(limit)+1))
}

func parseDocument(root, path string, data []byte) (model.SpecificationRecord, []model.SpecificationIssue, bool) {
	rel := relative(root, path)
	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil {
		if looksLikeSpecification(data) {
			return model.SpecificationRecord{}, []model.SpecificationIssue{issue("spec-parse-invalid", rel, err.Error())}, false
		}
		return model.SpecificationRecord{}, nil, false
	}
	nodes, depth, alias, duplicate := inspectYAML(&node, 0, map[*yaml.Node]bool{})
	if nodes > maxYAMLNodes || depth > maxYAMLDepth || alias || duplicate {
		reason := "unsafe YAML structure"
		switch {
		case alias:
			reason = "YAML aliases are unsupported"
		case duplicate:
			reason = "duplicate mapping keys are unsupported"
		case nodes > maxYAMLNodes:
			reason = "YAML node limit exceeded"
		case depth > maxYAMLDepth:
			reason = "YAML depth limit exceeded"
		}
		return model.SpecificationRecord{}, []model.SpecificationIssue{issue("spec-parse-limit", rel, reason)}, false
	}
	var raw map[string]any
	if err := node.Decode(&raw); err != nil {
		if looksLikeSpecification(data) {
			return model.SpecificationRecord{}, []model.SpecificationIssue{issue("spec-parse-invalid", rel, err.Error())}, false
		}
		return model.SpecificationRecord{}, nil, false
	}
	dialect, version := "", ""
	openAPIVersion := stringValue(raw["openapi"])
	swaggerVersion := stringValue(raw["swagger"])
	switch {
	case strings.HasPrefix(openAPIVersion, "3."):
		dialect, version = "openapi3", openAPIVersion
	case swaggerVersion == "2.0" || swaggerVersion == "2":
		dialect, version = "swagger2", "2.0"
	case openAPIVersion != "" || swaggerVersion != "":
		declared := openAPIVersion
		if declared == "" {
			declared = swaggerVersion
		}
		return model.SpecificationRecord{}, []model.SpecificationIssue{issue("spec-version-unsupported", rel, "unsupported OpenAPI/Swagger version "+declared)}, false
	default:
		return model.SpecificationRecord{}, nil, false
	}
	hash := sha256.Sum256(data)
	record := model.SpecificationRecord{ID: fmt.Sprintf("spec-%x", hash[:8]), Path: rel, Dialect: dialect, Version: version, Authorship: authorship(raw), Provenance: model.DocumentationEvidence{Source: "source-document", Status: "declared", Provenance: &model.Source{File: rel}}, SHA256: fmt.Sprintf("%x", hash[:]), Bytes: int64(len(data))}
	if info, ok := raw["info"].(map[string]any); ok {
		record.Title = stringValue(info["title"])
		record.APIVersion = stringValue(info["version"])
	}
	if paths, ok := raw["paths"].(map[string]any); ok {
		for p, item := range paths {
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			for method := range m {
				method = strings.ToLower(method)
				if operationMethods[method] {
					record.Operations = append(record.Operations, model.SpecificationOperation{Method: strings.ToUpper(method), Path: p})
				}
			}
		}
	}
	sort.Slice(record.Operations, func(i, j int) bool {
		if record.Operations[i].Path == record.Operations[j].Path {
			return record.Operations[i].Method < record.Operations[j].Method
		}
		return record.Operations[i].Path < record.Operations[j].Path
	})
	refs := collectRefs(raw)
	issues := validateRefs(root, path, refs)
	record.LocalRefs = refs
	return record, issues, true
}

func inspectYAML(root *yaml.Node, depth int, seen map[*yaml.Node]bool) (nodes, maxDepth int, alias, duplicate bool) {
	type work struct {
		n     *yaml.Node
		depth int
	}
	stack := []work{{n: root, depth: depth}}
	for len(stack) > 0 {
		item := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if item.n == nil {
			continue
		}
		if seen[item.n] {
			alias = true
			continue
		}
		seen[item.n] = true
		nodes++
		if item.depth > maxDepth {
			maxDepth = item.depth
		}
		// Stop traversing as soon as a configured structural bound is exceeded.
		// The caller only needs to know that the document is unsafe.
		if nodes > maxYAMLNodes || item.depth > maxYAMLDepth {
			return nodes, maxDepth, alias, duplicate
		}
		if item.n.Kind == yaml.AliasNode {
			alias = true
		}
		if item.n.Kind == yaml.MappingNode {
			keys := map[string]bool{}
			for i := 0; i+1 < len(item.n.Content); i += 2 {
				key := item.n.Content[i].Value
				if keys[key] {
					duplicate = true
				}
				keys[key] = true
			}
		}
		for _, child := range item.n.Content {
			stack = append(stack, work{n: child, depth: item.depth + 1})
		}
	}
	return nodes, maxDepth, alias, duplicate
}

func looksLikeSpecification(data []byte) bool {
	trimmed := strings.TrimSpace(strings.TrimPrefix(string(data), "\ufeff"))
	if strings.HasPrefix(trimmed, "{") {
		return strings.Contains(trimmed, `"openapi"`) || strings.Contains(trimmed, `"swagger"`)
	}
	for _, line := range strings.Split(trimmed, "\n") {
		if line == "" || line[0] == ' ' || line[0] == '\t' || line[0] == '#' {
			continue
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "openapi:") || strings.HasPrefix(lower, "swagger:") {
			return true
		}
	}
	return false
}
func authorship(raw map[string]any) string {
	if v, ok := raw["x-gin-recon-authorship"].(string); ok && (v == "authored" || v == "generated") {
		return v
	}
	if v, ok := raw["x-generated"].(bool); ok && v {
		return "generated"
	}
	return "unknown"
}
func stringValue(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}
func collectRefs(v any) []string {
	set := map[string]bool{}
	var walk func(any)
	walk = func(x any) {
		switch n := x.(type) {
		case map[string]any:
			for k, v := range n {
				if k == "$ref" {
					if s, ok := v.(string); ok {
						set[s] = true
					}
				}
				walk(v)
			}
		case []any:
			for _, v := range n {
				walk(v)
			}
		}
	}
	walk(v)
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
func validateRefs(root, document string, refs []string) []model.SpecificationIssue {
	var out []model.SpecificationIssue
	for _, ref := range refs {
		if strings.HasPrefix(ref, "#") {
			continue
		}
		if strings.Contains(ref, "://") || strings.HasPrefix(ref, "//") {
			out = append(out, issue("spec-remote-ref-rejected", relative(root, document), ref))
			continue
		}
		target := strings.SplitN(ref, "#", 2)[0]
		resolved := filepath.Clean(filepath.Join(filepath.Dir(document), filepath.FromSlash(target)))
		if !within(root, resolved) {
			out = append(out, issue("spec-ref-escape-rejected", relative(root, document), ref))
			continue
		}
		info, err := os.Lstat(resolved)
		if err != nil {
			out = append(out, issue("spec-local-ref-unavailable", relative(root, document), ref))
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 || containsSymlink(root, resolved) {
			out = append(out, issue("spec-ref-symlink-rejected", relative(root, document), ref))
		}
	}
	return out
}

func containsSymlink(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == "." {
		return false
	}
	current := root
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return false
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return true
		}
	}
	return false
}
func reconcile(specs []model.SpecificationRecord, routes []model.Route, coverage model.ScanCoverage, catalogStatus string) model.DocumentationMetrics {
	m := model.DocumentationMetrics{SourceFiles: model.DocumentationMetric{Numerator: coverage.AnalyzedFiles, Denominator: coverage.DiscoveredFiles, Status: "complete"}, ObservedOperations: model.DocumentationMetric{Status: "complete"}, IncompleteScope: !coverage.Complete}
	if coverage.DiscoveredFiles == 0 {
		m.SourceFiles.Status = "unknown"
	}
	code := map[string]model.SpecificationOperation{}
	for _, r := range routes {
		p := swaggerPath(r.GinPath)
		op := model.SpecificationOperation{Method: r.Method, Path: p}
		code[r.Method+" "+p] = op
	}
	m.ObservedOperations.Denominator = len(code)
	owners := map[string]int{}
	authored := map[string]bool{}
	unknownRelevant := false
	docOnly := map[string]model.SpecificationOperation{}
	for _, s := range specs {
		for _, op := range s.Operations {
			k := op.Method + " " + op.Path
			owners[k]++
			if s.Authorship == "authored" {
				authored[k] = true
			} else if s.Authorship == "unknown" {
				if code[k].Method != "" {
					unknownRelevant = true
				}
			}
			if code[k].Method == "" {
				docOnly[k] = op
			}
		}
	}
	for k, op := range code {
		if authored[k] {
			m.ObservedOperations.Numerator++
		} else {
			m.CodeOnly = append(m.CodeOnly, op)
		}
		if owners[k] > 1 {
			m.AmbiguousOwnership = append(m.AmbiguousOwnership, op)
		}
	}
	for _, op := range docOnly {
		m.DocumentationOnly = append(m.DocumentationOnly, op)
	}
	if len(code) == 0 || unknownRelevant || catalogStatus != "complete" {
		m.ObservedOperations.Status = "unknown"
	}
	sortOps(m.CodeOnly)
	sortOps(m.DocumentationOnly)
	sortOps(m.AmbiguousOwnership)
	return m
}
func sortOps(v []model.SpecificationOperation) {
	sort.Slice(v, func(i, j int) bool {
		if v[i].Path == v[j].Path {
			return v[i].Method < v[j].Method
		}
		return v[i].Path < v[j].Path
	})
}
func swaggerPath(path string) string {
	parts := strings.Split(path, "/")
	for i, p := range parts {
		if strings.HasPrefix(p, ":") || strings.HasPrefix(p, "*") {
			parts[i] = "{" + p[1:] + "}"
		}
	}
	return strings.Join(parts, "/")
}
func issue(code, path, message string) model.SpecificationIssue {
	return model.SpecificationIssue{Code: code, Path: path, Message: message}
}
func relative(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(rel)
}
func within(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
