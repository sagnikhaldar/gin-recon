package format

// Round-trip validation against a real OpenAPI 3.1 parser, per
// docs/openapi-strategy.md: "Validate generated documents against OpenAPI 3.1
// in tests using a pinned test-only github.com/pb33f/libopenapi dependency
// ... Round-trip tests parse the emitted document independently from Gin
// Recon's formatter." libopenapi is deliberately confined to this file (and
// so, via the go.mod "// indirect" -> direct promotion, to a test-only
// dependency edge) rather than imported anywhere the formatter itself runs.

import (
	"testing"

	"github.com/pb33f/libopenapi"
	"github.com/sagnikhaldar/gin-recon/internal/config"
	"github.com/sagnikhaldar/gin-recon/internal/model"
	"github.com/sagnikhaldar/gin-recon/internal/report"
)

// parseWithLibopenapi builds a v3 model from data using a parser wholly
// independent of this package's own encoding/json-based formatter, so a bug
// that produces syntactically-valid-but-semantically-wrong OpenAPI (a
// reference nothing declares, a duplicate operationId, a malformed security
// requirement) is caught by an external authority instead of by re-checking
// the formatter's own assumptions.
func parseWithLibopenapi(t *testing.T, data []byte) {
	t.Helper()
	doc, err := libopenapi.NewDocument(data)
	if err != nil {
		t.Fatalf("libopenapi.NewDocument: %v\n%s", err, data)
	}
	built, err := doc.BuildV3Model()
	if err != nil {
		t.Fatalf("BuildV3Model: %v\n%s", err, data)
	}
	if built.Model.Paths == nil {
		t.Fatalf("expected a non-nil Paths object\n%s", data)
	}
}

func TestOpenAPIRoundTripEmptyDocument(t *testing.T) {
	rep := inventoryWithRoutes()
	data, _, err := OpenAPI(rep, nil)
	if err != nil {
		t.Fatalf("OpenAPI: %v", err)
	}
	parseWithLibopenapi(t, data)
}

func TestOpenAPIRoundTripRichDocument(t *testing.T) {
	cfg := &config.Config{
		Version: 1,
		AuthMiddleware: map[string]config.AuthMiddlewareEntry{
			"example.com/demo/internal/auth.RequireUser": {OpenAPIScheme: "bearerAuth", Roles: []string{"admin"}},
		},
		OpenAPI: &config.OpenAPIConfig{
			Title:   "Demo API",
			Version: "1.2.3",
			SecuritySchemes: map[string]config.SecurityScheme{
				"bearerAuth": {Type: "http", Scheme: "bearer", BearerFormat: "JWT"},
			},
		},
	}

	provenSymbol := "example.com/demo/internal/auth.RequireUser"

	proven := routeAt("GET", "/admin/users/:id")
	proven.Auth = &model.AuthClassification{AuthStatus: model.AuthProven, MatchedEvidence: &provenSymbol, Roles: []string{"admin"}, Confidence: model.ConfidenceHigh}

	public := routeAt("GET", "/health")
	public.Auth = &model.AuthClassification{AuthStatus: model.AuthPublic, Confidence: model.ConfidenceHigh}

	unknown := routeAt("POST", "/webhook")
	unknown.Auth = &model.AuthClassification{AuthStatus: model.AuthUnknown, Confidence: model.ConfidenceLow}

	catchAll := routeAt("GET", "/static/*filepath")

	rep := report.NewAuditReport(model.ProfileTyped, testTarget(), report.Summary{}, nil, report.PolicyEvaluation{}, nil)
	rep.Routes = []model.Route{proven, public, unknown, catchAll}
	rep.ScanCoverage = model.ScanCoverage{AnalyzedPackages: 1, AnalyzedFiles: 1, Complete: true}

	data, diags, err := OpenAPI(rep, cfg)
	if err != nil {
		t.Fatalf("OpenAPI: %v", err)
	}
	if len(diags) != 0 {
		t.Fatalf("unexpected diagnostics: %+v", diags)
	}
	parseWithLibopenapi(t, data)
}

func TestOpenAPIRoundTripNonRepresentableAndConflictingStillProducesValidDocument(t *testing.T) {
	rep := inventoryWithRoutes(
		routeAt("CONNECT", "/tunnel"),
		routeAt("GET", "/dup"),
		routeAt("GET", "/dup"),
		routeAt("GET", "/ok"),
	)
	data, diags, err := OpenAPI(rep, nil)
	if err != nil {
		t.Fatalf("OpenAPI: %v", err)
	}
	if len(diags) != 2 {
		t.Fatalf("expected 2 diagnostics (non-representable + conflict), got %+v", diags)
	}
	parseWithLibopenapi(t, data)
}
