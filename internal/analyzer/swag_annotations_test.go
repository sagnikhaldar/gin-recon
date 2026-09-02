package analyzer

import (
	"strings"
	"testing"

	"github.com/sagnikhaldar/gin-recon/internal/format"
	"github.com/sagnikhaldar/gin-recon/internal/model"
	"github.com/sagnikhaldar/gin-recon/internal/report"
)

// TestInventoryAndOpenAPIApplySwagAnnotations exercises the full
// discovery-through-OpenAPI path for docs/adr/0012-swag-annotation-evidence.md
// against testdata/fixtures/swag-annotations (see its manifest.json):
// GetUser's fully-agreeing swag comment enriches its route with zero
// diagnostics, ListUsers' deliberately stale @Router produces
// swag-router-mismatch without losing its Summary, and PlainHandler's
// ordinary prose doc comment leaves Route.Swag nil.
func TestInventoryAndOpenAPIApplySwagAnnotations(t *testing.T) {
	result := loadAndInventory(t, "swag-annotations")

	routes := map[string]*model.Route{}
	for i := range result.Routes {
		r := &result.Routes[i]
		routes[r.Method+" "+r.NormalizedPath] = r
	}

	getUser, ok := routes["GET /users/:id"]
	if !ok {
		t.Fatalf("route GET /users/:id not found; routes: %+v", result.Routes)
	}
	if getUser.Swag == nil {
		t.Fatal("GetUser: Swag is nil, want populated")
	}
	if getUser.Swag.Summary != "Get a user by ID" {
		t.Errorf("GetUser: Summary = %q, want %q", getUser.Swag.Summary, "Get a user by ID")
	}
	wantDesc := "Returns the user record matching the given ID. Requires no authentication in this fixture."
	if getUser.Swag.Description != wantDesc {
		t.Errorf("GetUser: Description = %q, want %q", getUser.Swag.Description, wantDesc)
	}
	if len(getUser.Swag.Tags) != 2 || getUser.Swag.Tags[0] != "users" || getUser.Swag.Tags[1] != "public" {
		t.Errorf("GetUser: Tags = %+v, want [users public]", getUser.Swag.Tags)
	}
	if !getUser.Swag.Deprecated {
		t.Error("GetUser: Deprecated = false, want true")
	}
	if getUser.Swag.RouterPath != "/users/{id}" || getUser.Swag.RouterMethod != "GET" {
		t.Errorf("GetUser: RouterPath/Method = %q/%q, want /users/{id}/GET", getUser.Swag.RouterPath, getUser.Swag.RouterMethod)
	}

	listUsers, ok := routes["GET /users"]
	if !ok {
		t.Fatalf("route GET /users not found; routes: %+v", result.Routes)
	}
	if listUsers.Swag == nil {
		t.Fatal("ListUsers: Swag is nil, want populated despite the stale @Router line")
	}
	if listUsers.Swag.Summary != "List all users" {
		t.Errorf("ListUsers: Summary = %q, want %q (must survive the @Router mismatch)", listUsers.Swag.Summary, "List all users")
	}

	plain, ok := routes["GET /plain"]
	if !ok {
		t.Fatalf("route GET /plain not found; routes: %+v", result.Routes)
	}
	if plain.Swag != nil {
		t.Errorf("PlainHandler: Swag = %+v, want nil (ordinary prose doc comment, no swag directive)", plain.Swag)
	}

	var mismatches []model.Diagnostic
	for _, d := range result.Diagnostics {
		if d.Code == "swag-router-mismatch" {
			mismatches = append(mismatches, d)
		}
	}
	if len(mismatches) != 1 {
		t.Fatalf("got %d swag-router-mismatch diagnostics, want exactly 1: %+v", len(mismatches), result.Diagnostics)
	}
	if mismatches[0].Severity != model.DiagnosticWarning {
		t.Errorf("swag-router-mismatch severity = %q, want warning (documentation hygiene, not an error)", mismatches[0].Severity)
	}

	// The mismatch diagnostic must not affect ScanCoverage.Complete — it is
	// documentation hygiene, not a discovery gap.
	if !result.ScanCoverage.Complete {
		t.Errorf("ScanCoverage.Complete = false, want true: a swag-router-mismatch diagnostic must not affect completeness")
	}

	rep := report.NewInventoryReport(model.ProfileTyped, report.Target{Module: result.Module})
	rep.Routes = result.Routes
	rep.ScanCoverage = result.ScanCoverage
	data, diags, err := format.OpenAPI(rep, nil)
	if err != nil {
		t.Fatalf("OpenAPI: %v", err)
	}
	if len(diags) != 0 {
		t.Errorf("unexpected OpenAPI-format-time diagnostics: %+v", diags)
	}
	for _, want := range []string{
		`"summary": "Get a user by ID"`,
		`"description": "Returns the user record matching the given ID. Requires no authentication in this fixture."`,
		`"deprecated": true`,
		`"summary": "List all users"`,
	} {
		if !strings.Contains(string(data), want) {
			t.Errorf("generated OpenAPI document missing %q:\n%s", want, data)
		}
	}
}
