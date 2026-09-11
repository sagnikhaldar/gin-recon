package spec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sagnikhaldar/gin-recon/internal/model"
)

func writeFixture(t *testing.T, root, name, contents string) {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoverMultipleDialectsAndReconcileWithoutDoubleCounting(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "openapi.yaml", "openapi: 3.1.0\nx-gin-recon-authorship: authored\ninfo: {title: Primary, version: v1}\npaths:\n  /users/{id}:\n    get: {responses: {'200': {description: ok}}}\n")
	writeFixture(t, root, "legacy.json", `{"swagger":"2.0","x-gin-recon-authorship":"authored","info":{"title":"Legacy","version":"v1"},"paths":{"/users/{id}":{"get":{}},"/docs":{"get":{}}}}`)
	coverage := model.ScanCoverage{DiscoveredFiles: 4, AnalyzedFiles: 3, Complete: false}
	cat := Discover(root, []model.Route{{Method: "GET", GinPath: "/users/:id"}, {Method: "POST", GinPath: "/users"}}, coverage)
	if cat.Status != "complete" || len(cat.Specifications) != 2 {
		t.Fatalf("catalog=%+v", cat)
	}
	if cat.Metrics.ObservedOperations.Numerator != 1 || cat.Metrics.ObservedOperations.Denominator != 2 {
		t.Fatalf("operation metric=%+v", cat.Metrics.ObservedOperations)
	}
	if len(cat.Metrics.AmbiguousOwnership) != 1 {
		t.Fatalf("ambiguous=%+v", cat.Metrics.AmbiguousOwnership)
	}
	if got := cat.Metrics.SourceFiles; got.Numerator != 3 || got.Denominator != 4 {
		t.Fatalf("source metric=%+v", got)
	}
	if !cat.Metrics.IncompleteScope {
		t.Fatal("incomplete scope was lost")
	}
}

func TestGeneratedAndUnknownSpecsAreNotAuthoredCoverage(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "generated.yaml", "openapi: 3.0.3\nx-generated: true\ninfo: {title: G, version: v1}\npaths: {/x: {get: {}}}\n")
	writeFixture(t, root, "unknown.yaml", "swagger: '2.0'\ninfo: {title: U, version: v1}\npaths: {/y: {get: {}}}\n")
	cat := Discover(root, []model.Route{{Method: "GET", GinPath: "/x"}, {Method: "GET", GinPath: "/y"}}, model.ScanCoverage{DiscoveredFiles: 1, AnalyzedFiles: 1, Complete: true})
	if cat.Metrics.ObservedOperations.Numerator != 0 || cat.Metrics.ObservedOperations.Status != "unknown" {
		t.Fatalf("generated/unknown counted as authored: %+v", cat.Metrics.ObservedOperations)
	}
}

func TestUnsafeRefsAliasesAndDuplicateKeysAreDiagnosed(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "refs.yaml", "openapi: 3.1.0\ninfo: {title: R, version: v1}\npaths: {}\ncomponents: {schemas: {A: {$ref: 'https://example.test/a'}, B: {$ref: '../../escape.yaml'}}}\n")
	writeFixture(t, root, "alias.yaml", "openapi: 3.1.0\ninfo: &i {title: X, version: v1}\nx-copy: *i\npaths: {}\n")
	writeFixture(t, root, "duplicate.yaml", "openapi: 3.1.0\nopenapi: 3.0.0\ninfo: {title: X, version: v1}\npaths: {}\n")
	cat := Discover(root, nil, model.ScanCoverage{})
	codes := map[string]bool{}
	for _, i := range cat.Issues {
		codes[i.Code] = true
	}
	for _, code := range []string{"spec-remote-ref-rejected", "spec-ref-escape-rejected", "spec-parse-limit"} {
		if !codes[code] {
			t.Errorf("missing %s in %+v", code, cat.Issues)
		}
	}
}

func TestSymlinkCandidateIsNeverFollowed(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "openapi.yaml")
	if err := os.WriteFile(outside, []byte("openapi: 3.1.0\ninfo: {title: X, version: v1}\npaths: {}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "openapi.yaml")); err != nil {
		t.Skip(err)
	}
	cat := Discover(root, nil, model.ScanCoverage{})
	if len(cat.Specifications) != 0 || len(cat.Issues) != 1 || cat.Issues[0].Code != "spec-symlink-rejected" {
		t.Fatalf("catalog=%+v", cat)
	}
}

func TestMalformedAndUnsupportedSpecificationCandidatesMakeCatalogUnknown(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "broken.yaml", "openapi: 3.1.0\ninfo: [\n")
	writeFixture(t, root, "future.yaml", "openapi: 4.0.0\ninfo: {title: Future, version: v1}\npaths: {}\n")
	writeFixture(t, root, "ordinary.yaml", "application:\n  feature: [also, valid]\n")
	cat := Discover(root, nil, model.ScanCoverage{})
	if cat.Status != "unknown" {
		t.Fatalf("status=%q, want unknown", cat.Status)
	}
	codes := map[string]bool{}
	for _, got := range cat.Issues {
		codes[got.Code] = true
	}
	for _, code := range []string{"spec-parse-invalid", "spec-version-unsupported"} {
		if !codes[code] {
			t.Errorf("missing %s in %+v", code, cat.Issues)
		}
	}
	if len(cat.Issues) != 2 {
		t.Fatalf("ordinary YAML was misclassified as a spec: %+v", cat.Issues)
	}
}

func TestUnquotedSwaggerVersionIsDetected(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "swagger.yaml", "swagger: 2.0\ninfo: {title: Legacy, version: v1}\npaths: {}\n")
	cat := Discover(root, nil, model.ScanCoverage{})
	if len(cat.Specifications) != 1 || cat.Specifications[0].Dialect != "swagger2" || cat.Specifications[0].Version != "2.0" {
		t.Fatalf("catalog=%+v", cat)
	}
}

func TestDeepDocumentIsRejectedWithoutRecursiveInspection(t *testing.T) {
	root := t.TempDir()
	data := `{"openapi":"3.1.0","info":{"title":"Deep","version":"v1"},"paths":{},"x":` + strings.Repeat("[", maxYAMLDepth+2) + `0` + strings.Repeat("]", maxYAMLDepth+2) + `}`
	writeFixture(t, root, "deep.json", data)
	cat := Discover(root, nil, model.ScanCoverage{})
	if cat.Status != "unknown" || len(cat.Issues) != 1 || cat.Issues[0].Code != "spec-parse-limit" {
		t.Fatalf("catalog=%+v", cat)
	}
}

func TestOversizedDocumentIsNotReadOrCataloged(t *testing.T) {
	root := t.TempDir()
	data := "openapi: 3.1.0\ninfo: {title: Large, version: v1}\npaths: {}\nx-pad: " + strings.Repeat("x", maxDocumentBytes)
	writeFixture(t, root, "large.yaml", data)
	cat := Discover(root, nil, model.ScanCoverage{})
	if cat.Status != "unknown" || len(cat.Specifications) != 0 || len(cat.Issues) != 1 || cat.Issues[0].Code != "spec-document-size-limit" {
		t.Fatalf("catalog=%+v", cat)
	}
}

func TestLocalRefThroughSymlinkedDirectoryIsRejected(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	writeFixture(t, outside, "schema.yaml", "type: object\n")
	if err := os.Symlink(outside, filepath.Join(root, "schemas")); err != nil {
		t.Skip(err)
	}
	writeFixture(t, root, "openapi.yaml", "openapi: 3.1.0\ninfo: {title: Ref, version: v1}\npaths: {}\ncomponents: {schemas: {A: {$ref: 'schemas/schema.yaml'}}}\n")
	cat := Discover(root, nil, model.ScanCoverage{})
	if cat.Status != "unknown" || len(cat.Specifications) != 1 || len(cat.Issues) != 1 || cat.Issues[0].Code != "spec-ref-symlink-rejected" {
		t.Fatalf("catalog=%+v", cat)
	}
}
