package format

import (
	"encoding/json"
	"testing"

	"github.com/sagnikhaldar/gin-recon/internal/model"
)

func swagEvidence(status string) model.DocumentationEvidence {
	return model.DocumentationEvidence{Source: "swag", Status: status}
}

func TestOpenAPIRendersDocumentedParametersBodyResponsesAndHeaders(t *testing.T) {
	route := routeAt("POST", "/users/:id")
	route.Swag = &model.SwagInfo{Accept: []string{"application/json"}, Produce: []string{"application/json"}, Parameters: []model.SwagParameter{
		{Name: "id", In: "path", Required: true, Schema: &model.SchemaEvidence{Type: "integer", Evidence: swagEvidence("declared")}, Evidence: swagEvidence("declared")},
		{Name: "verbose", In: "query", Schema: &model.SchemaEvidence{Type: "boolean", Default: true, Evidence: swagEvidence("declared")}, Evidence: swagEvidence("declared")},
		{Name: "body", In: "body", Required: true, Schema: &model.SchemaEvidence{Ref: "User_abc", Evidence: swagEvidence("resolved")}, Evidence: swagEvidence("declared")},
	}, Responses: []model.SwagResponse{{Status: "201", Description: "created", Schema: &model.SchemaEvidence{Ref: "User_abc", Evidence: swagEvidence("resolved")}, Headers: []model.SwagHeader{{Name: "X-Trace", Schema: &model.SchemaEvidence{Type: "string", Evidence: swagEvidence("declared")}, Evidence: swagEvidence("declared")}}, Evidence: swagEvidence("declared")}}, Components: map[string]model.SchemaEvidence{"User_abc": {Type: "object", Properties: map[string]model.SchemaEvidence{"name": {Type: "string", Evidence: swagEvidence("resolved")}}, Required: []string{"name"}, Evidence: swagEvidence("resolved")}}}
	data, diags, err := OpenAPI(inventoryWithRoutes(route), nil)
	if err != nil || len(diags) != 0 {
		t.Fatalf("OpenAPI err=%v diags=%+v", err, diags)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	op := doc["paths"].(map[string]any)["/users/{id}"].(map[string]any)["post"].(map[string]any)
	if op["requestBody"] == nil {
		t.Fatal("requestBody omitted")
	}
	params := op["parameters"].([]any)
	if len(params) != 2 {
		t.Fatalf("parameters=%+v", params)
	}
	responses := op["responses"].(map[string]any)
	created := responses["201"].(map[string]any)
	if created["content"] == nil || created["headers"] == nil {
		t.Fatalf("response=%+v", created)
	}
	if doc["components"].(map[string]any)["schemas"] == nil {
		t.Fatal("component schemas omitted")
	}
	parseWithLibopenapi(t, data)
}

func TestOpenAPIFormDataAndUnresolvedSchemas(t *testing.T) {
	route := routeAt("POST", "/upload")
	route.Swag = &model.SwagInfo{Parameters: []model.SwagParameter{{Name: "file", In: "formData", Required: true, Schema: &model.SchemaEvidence{Type: "string", Format: "binary", Evidence: swagEvidence("declared")}, Evidence: swagEvidence("declared")}, {Name: "mystery", In: "query", Schema: &model.SchemaEvidence{GoType: "external.Missing", Evidence: swagEvidence("unresolved")}, Evidence: swagEvidence("declared")}}}
	data, diags, err := OpenAPI(inventoryWithRoutes(route), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(diags) != 1 || diags[0].Code != "swag-schema-unresolved" {
		t.Fatalf("diags=%+v", diags)
	}
	if !json.Valid(data) {
		t.Fatal("invalid JSON")
	}
	var doc map[string]any
	_ = json.Unmarshal(data, &doc)
	op := doc["paths"].(map[string]any)["/upload"].(map[string]any)["post"].(map[string]any)
	content := op["requestBody"].(map[string]any)["content"].(map[string]any)
	if content["multipart/form-data"] == nil {
		t.Fatalf("content=%+v", content)
	}
	parseWithLibopenapi(t, data)
}

func TestDocumentedSecurityNeverCreatesOperationSecurity(t *testing.T) {
	route := routeAt("GET", "/claims")
	route.Swag = &model.SwagInfo{Security: []model.SwagSecurity{{Name: "BearerAuth", Scopes: []string{"read"}, Evidence: swagEvidence("declared")}}}
	data, _, err := OpenAPI(inventoryWithRoutes(route), nil)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	_ = json.Unmarshal(data, &doc)
	op := doc["paths"].(map[string]any)["/claims"].(map[string]any)["get"].(map[string]any)
	if _, ok := op["security"]; ok {
		t.Fatal("documentary @Security became an OpenAPI security assertion")
	}
	ext := op["x-gin-recon"].(map[string]any)
	if ext["documentationSecurity"] == nil {
		t.Fatal("documentary claim was not retained")
	}
}

func TestDanglingDocumentedComponentRefIsDiagnosedAndOmitted(t *testing.T) {
	route := routeAt("GET", "/dangling")
	route.Swag = &model.SwagInfo{Responses: []model.SwagResponse{{Status: "200", Description: "ok", Schema: &model.SchemaEvidence{Ref: "Missing", GoType: "Missing", Evidence: swagEvidence("resolved")}, Evidence: swagEvidence("declared")}}}
	data, diags, err := OpenAPI(inventoryWithRoutes(route), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(diags) != 1 || diags[0].Code != "swag-schema-unresolved" {
		t.Fatalf("diags=%+v", diags)
	}
	parseWithLibopenapi(t, data)
}

func TestOpenAPI31NullableUsesTypeUnion(t *testing.T) {
	route := routeAt("GET", "/nullable")
	route.Swag = &model.SwagInfo{Responses: []model.SwagResponse{{Status: "200", Description: "ok", Schema: &model.SchemaEvidence{Type: "string", Nullable: true, Evidence: swagEvidence("resolved")}, Evidence: swagEvidence("declared")}}}
	data, _, _ := OpenAPI(inventoryWithRoutes(route), nil)
	var doc map[string]any
	_ = json.Unmarshal(data, &doc)
	schema := doc["paths"].(map[string]any)["/nullable"].(map[string]any)["get"].(map[string]any)["responses"].(map[string]any)["200"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any)
	if _, ok := schema["nullable"]; ok {
		t.Fatal("OpenAPI 3.0 nullable keyword emitted in 3.1 document")
	}
	if len(schema["type"].([]any)) != 2 {
		t.Fatalf("type=%+v", schema["type"])
	}
	parseWithLibopenapi(t, data)
}

func TestOpenAPIRendersGlobalMetadataButNotDocumentaryGlobalSecurity(t *testing.T) {
	rep := inventoryWithRoutes(routeAt("GET", "/v1/users"))
	rep.Documentation = &model.APIDocumentation{Title: "Users API", Version: "2.0", Description: "Authored description", Host: "api.example.test", BasePath: "/v1", Schemes: []string{"https", "http"}, Tags: []model.APITagDocumentation{{Name: "users", Description: "User operations", Evidence: swagEvidence("declared")}}, Security: []model.SwagSecurity{{Name: "ApiKey", Evidence: swagEvidence("declared")}}, SecurityDefinitions: map[string]model.DocumentedSecurityScheme{"ApiKey": {Type: "apiKey", Name: "X-Key", In: "header", Evidence: swagEvidence("declared")}}, Evidence: swagEvidence("declared")}
	data, _, err := OpenAPI(rep, nil)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	_ = json.Unmarshal(data, &doc)
	if doc["info"].(map[string]any)["title"] != "Users API" || len(doc["servers"].([]any)) != 2 {
		t.Fatalf("metadata=%+v", doc)
	}
	if _, ok := doc["security"]; ok {
		t.Fatal("global documentary security emitted as assertion")
	}
	if doc["x-gin-recon-documentation"] == nil {
		t.Fatal("global security provenance not retained")
	}
}
