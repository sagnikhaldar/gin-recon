package analyzer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sagnikhaldar/gin-recon/internal/model"
)

// writeCandidate writes contents at src/relPath, creating any parent
// directories a candidate like "docs/openapi.yaml" needs.
func writeCandidate(t *testing.T, src, relPath, contents string) {
	t.Helper()
	full := filepath.Join(src, relPath)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir for %s: %v", relPath, err)
	}
	if err := os.WriteFile(full, []byte(contents), 0o644); err != nil {
		t.Fatalf("writing %s: %v", relPath, err)
	}
}

func TestResolveAndReconcileExistingDocumentExplicitWinsOverCandidate(t *testing.T) {
	src := t.TempDir()
	// Both an explicit doc and a same-content-shaped auto-detect candidate
	// exist; only the explicit one's summary text should ever be observed —
	// per ADR 0014, auto-detection must never even run when explicit is set.
	writeCandidate(t, src, "explicit.yaml", docWithSummary("from explicit"))
	writeCandidate(t, src, "openapi.yaml", docWithSummary("from candidate"))

	routes := []model.Route{routeFor("GET", "/users/:id")}
	result := ResolveAndReconcileExistingDocument(routes, src, "explicit.yaml", false)
	if result == nil {
		t.Fatal("result is nil, want populated from the explicit document")
	}
	if routes[0].ExistingDocument == nil || routes[0].ExistingDocument.Summary != "from explicit" {
		t.Fatalf("ExistingDocument = %+v, want summary \"from explicit\"", routes[0].ExistingDocument)
	}
}

func TestResolveAndReconcileExistingDocumentAutoDetectsFirstMatchInOrder(t *testing.T) {
	src := t.TempDir()
	// openapi.yaml precedes swagger.yaml in ExistingDocumentCandidates;
	// both exist here, so openapi.yaml must win.
	writeCandidate(t, src, "swagger.yaml", docWithSummary("from swagger.yaml"))
	writeCandidate(t, src, "openapi.yaml", docWithSummary("from openapi.yaml"))

	routes := []model.Route{routeFor("GET", "/users/:id")}
	result := ResolveAndReconcileExistingDocument(routes, src, "", false)
	if result == nil {
		t.Fatal("result is nil, want auto-detected reconciliation")
	}
	if routes[0].ExistingDocument == nil || routes[0].ExistingDocument.Summary != "from openapi.yaml" {
		t.Fatalf("ExistingDocument = %+v, want summary \"from openapi.yaml\" (first candidate in order)", routes[0].ExistingDocument)
	}
}

func TestResolveAndReconcileExistingDocumentAutoDetectSkipsEmptyDocument(t *testing.T) {
	src := t.TempDir()
	// openapi.yaml exists and parses but declares zero paths — ADR 0014
	// requires "at least one path item" to win, so detection must fall
	// through to the next candidate, swagger.yaml.
	writeCandidate(t, src, "openapi.yaml", `{"openapi":"3.1.0","info":{"title":"t","version":"1"},"paths":{}}`)
	writeCandidate(t, src, "swagger.yaml", docWithSummary("from swagger.yaml"))

	routes := []model.Route{routeFor("GET", "/users/:id")}
	result := ResolveAndReconcileExistingDocument(routes, src, "", false)
	if result == nil {
		t.Fatal("result is nil, want auto-detected reconciliation via swagger.yaml")
	}
	if routes[0].ExistingDocument == nil || routes[0].ExistingDocument.Summary != "from swagger.yaml" {
		t.Fatalf("ExistingDocument = %+v, want summary \"from swagger.yaml\" (openapi.yaml has no paths)", routes[0].ExistingDocument)
	}
}

func TestResolveAndReconcileExistingDocumentDisabledSuppressesAutoDetect(t *testing.T) {
	src := t.TempDir()
	writeCandidate(t, src, "openapi.yaml", docWithSummary("from openapi.yaml"))

	routes := []model.Route{routeFor("GET", "/users/:id")}
	result := ResolveAndReconcileExistingDocument(routes, src, "", true)
	if result != nil {
		t.Fatalf("result = %+v, want nil: disableExistingOpenAPIAutoDetect must suppress auto-detection entirely", result)
	}
	if routes[0].ExistingDocument != nil {
		t.Errorf("ExistingDocument = %+v, want nil", routes[0].ExistingDocument)
	}
}

func TestResolveAndReconcileExistingDocumentNoCandidatesIsNoOp(t *testing.T) {
	src := t.TempDir()
	// Nothing at all in src — not even a candidate filename.
	routes := []model.Route{routeFor("GET", "/users/:id")}
	result := ResolveAndReconcileExistingDocument(routes, src, "", false)
	if result != nil {
		t.Fatalf("result = %+v, want nil (no explicit config, no candidate present)", result)
	}
}

// TestResolveAndReconcileExistingDocumentGinReconDirNeverPickedUp confirms
// docs/adr/0014's exclusion of ".gin-recon/" holds by construction: a stray
// openapi.json sitting inside .gin-recon/reports/ (e.g. gin-recon's own
// prior output) is never on the candidate list at that relative path, only
// "openapi.json" at src's own root is, so it must never be auto-detected
// even though "openapi.json" itself is a real candidate name.
func TestResolveAndReconcileExistingDocumentGinReconDirNeverPickedUp(t *testing.T) {
	src := t.TempDir()
	writeCandidate(t, src, filepath.Join(".gin-recon", "reports", "openapi.json"), docWithSummary("stray prior report output"))

	routes := []model.Route{routeFor("GET", "/users/:id")}
	result := ResolveAndReconcileExistingDocument(routes, src, "", false)
	if result != nil {
		t.Fatalf("result = %+v, want nil: .gin-recon/reports/openapi.json must never be auto-detected", result)
	}
	if routes[0].ExistingDocument != nil {
		t.Errorf("ExistingDocument = %+v, want nil", routes[0].ExistingDocument)
	}
}

// TestExistingDocumentCandidatesExcludesBaseFiles confirms the fixed
// candidate list itself contains no "*.base.*" entry (swaggo's partial-
// template convention, ADR 0014's second exclusion) — this is a property of
// the literal list, not something that needs a repo fixture to demonstrate.
func TestExistingDocumentCandidatesExcludesBaseFiles(t *testing.T) {
	for _, candidate := range ExistingDocumentCandidates {
		if strings.Contains(candidate, ".base.") {
			t.Errorf("ExistingDocumentCandidates contains a .base. entry: %q", candidate)
		}
	}
}

// TestResolveAndReconcileExistingDocumentBaseFileOnlyFindsNothing confirms a
// repo that has only a swaggo-style ".base." file (no real candidate
// present) is correctly treated as having nothing to auto-detect, since
// ".base." files are simply never on the candidate list at all.
func TestResolveAndReconcileExistingDocumentBaseFileOnlyFindsNothing(t *testing.T) {
	src := t.TempDir()
	writeCandidate(t, src, filepath.Join("docs", "swagger.base.yaml"), docWithSummary("swaggo partial template"))

	routes := []model.Route{routeFor("GET", "/users/:id")}
	result := ResolveAndReconcileExistingDocument(routes, src, "", false)
	if result != nil {
		t.Fatalf("result = %+v, want nil: docs/swagger.base.yaml is not on the candidate list", result)
	}
}

// TestExistingDocumentCandidatesOrder pins the exact documented order from
// docs/adr/0014-auto-detect-existing-openapi-document.md so a future,
// well-intentioned reordering (e.g. alphabetizing) is caught as a behavior
// change to the ADR's own precedence, not waved through as a refactor.
func TestExistingDocumentCandidatesOrder(t *testing.T) {
	want := []string{
		"openapi.yaml", "openapi.yml", "openapi.json",
		"swagger.yaml", "swagger.yml", "swagger.json",
		"docs/openapi.yaml", "docs/openapi.yml", "docs/openapi.json",
		"docs/swagger.yaml", "docs/swagger.yml", "docs/swagger.json",
		"openapi/openapi.yaml", "openapi/openapi.yml",
		"api/openapi.yaml", "api/openapi.json",
	}
	if len(ExistingDocumentCandidates) != len(want) {
		t.Fatalf("ExistingDocumentCandidates has %d entries, want %d: %v", len(ExistingDocumentCandidates), len(want), ExistingDocumentCandidates)
	}
	for i, w := range want {
		if ExistingDocumentCandidates[i] != w {
			t.Errorf("ExistingDocumentCandidates[%d] = %q, want %q", i, ExistingDocumentCandidates[i], w)
		}
	}
}

// docWithSummary is a minimal single-operation OpenAPI 3.1 document whose
// only distinguishing content is its summary string, used to tell which
// candidate file reconciliation actually picked.
func docWithSummary(summary string) string {
	return `{
  "openapi": "3.1.0",
  "info": {"title": "t", "version": "1"},
  "paths": {
    "/users/{id}": {
      "get": {"summary": "` + summary + `"}
    }
  }
}`
}
