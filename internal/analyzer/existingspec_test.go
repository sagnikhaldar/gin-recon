package analyzer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sagnikhaldar/gin-recon/internal/model"
)

func writeTempDoc(t *testing.T, contents string) (dir, name string) {
	t.Helper()
	dir = t.TempDir()
	name = "openapi.json"
	if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0o644); err != nil {
		t.Fatalf("writing temp doc: %v", err)
	}
	return dir, name
}

func routeFor(method, ginPath string) model.Route {
	return model.Route{Method: method, GinPath: ginPath, NormalizedPath: ginPath}
}

func TestReconcileExistingDocumentUnconfiguredIsNoOp(t *testing.T) {
	routes := []model.Route{routeFor("GET", "/users/:id")}
	if got := ReconcileExistingDocument(routes, "/does/not/matter", ""); got != nil {
		t.Fatalf("ReconcileExistingDocument with empty docPath = %+v, want nil", got)
	}
}

func TestReconcileExistingDocumentFileNotFound(t *testing.T) {
	routes := []model.Route{routeFor("GET", "/users/:id")}
	result := ReconcileExistingDocument(routes, t.TempDir(), "missing.json")
	if result == nil {
		t.Fatal("result is nil, want a not-found diagnostic")
	}
	if result.Reconciled != nil {
		t.Errorf("Reconciled = %+v, want nil (degrade exactly as if unconfigured)", result.Reconciled)
	}
	if len(result.Diagnostics) != 1 || result.Diagnostics[0].Code != "openapi-spec-not-found" {
		t.Fatalf("Diagnostics = %+v, want exactly one openapi-spec-not-found", result.Diagnostics)
	}
	if result.Diagnostics[0].Severity != model.DiagnosticWarning {
		t.Errorf("severity = %q, want warning", result.Diagnostics[0].Severity)
	}
}

func TestReconcileExistingDocumentInvalidDocument(t *testing.T) {
	routes := []model.Route{routeFor("GET", "/users/:id")}
	dir, name := writeTempDoc(t, "this is not { valid json or yaml : [")
	result := ReconcileExistingDocument(routes, dir, name)
	if result == nil {
		t.Fatal("result is nil, want an invalid diagnostic")
	}
	if result.Reconciled != nil {
		t.Errorf("Reconciled = %+v, want nil", result.Reconciled)
	}
	if len(result.Diagnostics) != 1 || result.Diagnostics[0].Code != "openapi-spec-invalid" {
		t.Fatalf("Diagnostics = %+v, want exactly one openapi-spec-invalid", result.Diagnostics)
	}
}

const reconcileFixtureDoc = `{
  "openapi": "3.1.0",
  "info": {"title": "t", "version": "1"},
  "paths": {
    "/users/{id}": {
      "get": {
        "summary": "Existing doc summary for GetUser",
        "description": "Existing doc description.",
        "tags": ["users", "legacy"],
        "parameters": [
          {"name": "id", "in": "path", "required": true, "schema": {"type": "string"}, "description": "the user id, per the doc"}
        ]
      }
    },
    "/orders/{id}": {
      "get": {
        "summary": "Existing doc summary for order (param name conflict)"
      }
    },
    "/legacy/{id}": {
      "delete": {
        "summary": "Legacy operation no longer in code"
      }
    }
  }
}`

func TestReconcileExistingDocumentMatchesFillsEmptyFields(t *testing.T) {
	routes := []model.Route{routeFor("GET", "/users/:id")}
	dir, name := writeTempDoc(t, reconcileFixtureDoc)
	result := ReconcileExistingDocument(routes, dir, name)
	if result == nil {
		t.Fatal("result is nil")
	}
	got := routes[0].ExistingDocument
	if got == nil {
		t.Fatal("route.ExistingDocument is nil, want populated from the matched document operation")
	}
	if got.Summary != "Existing doc summary for GetUser" {
		t.Errorf("Summary = %q", got.Summary)
	}
	if got.Description != "Existing doc description." {
		t.Errorf("Description = %q", got.Description)
	}
	if len(got.Tags) != 2 || got.Tags[0] != "users" || got.Tags[1] != "legacy" {
		t.Errorf("Tags = %+v", got.Tags)
	}
	if got.ParamConflict {
		t.Error("ParamConflict = true, want false: param names agree (\"id\" == \"id\")")
	}
	if got.ParamDescriptions["id"] != "the user id, per the doc" {
		t.Errorf("ParamDescriptions[id] = %q", got.ParamDescriptions["id"])
	}
}

func TestReconcileExistingDocumentParamNameConflictMarksUnrefined(t *testing.T) {
	// Route's own Gin path names the parameter "orderId"; the document's
	// path names it "id" — same shape (so they match), differing name (so
	// they must conflict per ADR 0013's structural-compatibility check).
	routes := []model.Route{routeFor("GET", "/orders/:orderId")}
	dir, name := writeTempDoc(t, reconcileFixtureDoc)
	result := ReconcileExistingDocument(routes, dir, name)
	if result == nil {
		t.Fatal("result is nil")
	}
	got := routes[0].ExistingDocument
	if got == nil {
		t.Fatal("route.ExistingDocument is nil, want populated (summary has no structural conflict to gate on)")
	}
	if got.Summary == "" {
		t.Error("Summary should still be applied despite the parameter conflict — prose is never gated by the structural check")
	}
	if !got.ParamConflict {
		t.Error("ParamConflict = false, want true: \"orderId\" (route) vs \"id\" (document) disagree")
	}
	if len(got.ParamDescriptions) != 0 {
		t.Errorf("ParamDescriptions = %+v, want empty when parameter names conflict", got.ParamDescriptions)
	}

	var conflicts []model.Diagnostic
	for _, d := range result.Diagnostics {
		if d.Code == "openapi-spec-conflict" {
			conflicts = append(conflicts, d)
		}
	}
	if len(conflicts) != 1 {
		t.Fatalf("got %d openapi-spec-conflict diagnostics, want 1: %+v", len(conflicts), result.Diagnostics)
	}
	if conflicts[0].Severity != model.DiagnosticWarning {
		t.Errorf("severity = %q, want warning", conflicts[0].Severity)
	}
}

func TestReconcileExistingDocumentOrphanedOperation(t *testing.T) {
	routes := []model.Route{routeFor("GET", "/users/:id"), routeFor("GET", "/orders/:orderId")}
	dir, name := writeTempDoc(t, reconcileFixtureDoc)
	result := ReconcileExistingDocument(routes, dir, name)
	if result == nil || result.Reconciled == nil {
		t.Fatal("result/Reconciled is nil, want populated (document parsed successfully)")
	}
	if len(result.Reconciled.OrphanedOperations) != 1 {
		t.Fatalf("OrphanedOperations = %+v, want exactly 1 (DELETE /legacy/{id})", result.Reconciled.OrphanedOperations)
	}
	orphan := result.Reconciled.OrphanedOperations[0]
	if orphan.Method != "DELETE" || orphan.Path != "/legacy/{id}" {
		t.Errorf("orphan = %+v, want DELETE /legacy/{id}", orphan)
	}
	if orphan.Summary != "Legacy operation no longer in code" {
		t.Errorf("orphan.Summary = %q", orphan.Summary)
	}

	var orphanDiags []model.Diagnostic
	for _, d := range result.Diagnostics {
		if d.Code == "openapi-spec-orphan-operation" {
			orphanDiags = append(orphanDiags, d)
		}
	}
	if len(orphanDiags) != 1 {
		t.Fatalf("got %d openapi-spec-orphan-operation diagnostics, want 1: %+v", len(orphanDiags), result.Diagnostics)
	}
	if orphanDiags[0].Severity != model.DiagnosticInfo {
		t.Errorf("severity = %q, want info (often normal, not a defect)", orphanDiags[0].Severity)
	}
}

func TestReconcileExistingDocumentNeverTouchesRouteIdentity(t *testing.T) {
	route := routeFor("GET", "/users/:id")
	route.Auth = &model.AuthClassification{AuthStatus: model.AuthProven}
	routes := []model.Route{route}
	dir, name := writeTempDoc(t, reconcileFixtureDoc)
	ReconcileExistingDocument(routes, dir, name)

	if routes[0].Method != "GET" || routes[0].GinPath != "/users/:id" {
		t.Errorf("route identity changed: %+v", routes[0])
	}
	if routes[0].Auth == nil || routes[0].Auth.AuthStatus != model.AuthProven {
		t.Errorf("route.Auth changed: %+v", routes[0].Auth)
	}
}
