package gin

import (
	"testing"

	"github.com/sagnikhaldar/gin-recon/internal/model"
)

func TestSwagExtendedGrammar(t *testing.T) {
	info := ParseSwagAnnotations(docOf(t, "// @ID getUser\n// @Accept json, mpfd\n// @Produce json\n// @Param id\tpath\tint\tfalse\t\"User identifier\" minimum(1) default(2) example(3)\n// @Param upload formData file true \"payload file\"\n// @Success 200 {object} User \"ok response\"\n// @Header 200 {string} X-Trace-ID \"trace identifier\"\n// @Failure 400 {string} string \"bad request\"\n// @Security OAuth2[read, write]\n// @Router /users/{id} [get]\n// @DeprecatedRouter /v1/users/{id} [get]\nfunc H() {}"))
	if info == nil {
		t.Fatal("nil")
	}
	if info.ID != "getUser" || len(info.Parameters) != 2 || len(info.Responses) != 2 || len(info.Responses[0].Headers) != 1 || len(info.Routers) != 2 || len(info.Security) != 1 {
		t.Fatalf("parsed=%+v", info)
	}
	if !info.Parameters[0].Required {
		t.Error("path parameter must be required regardless of authored false")
	}
	if info.Parameters[0].Schema.Minimum == nil || info.Parameters[0].Schema.Default == nil || info.Parameters[0].Schema.Example == nil {
		t.Fatalf("constraints lost: %+v", info.Parameters[0].Schema)
	}
}

func TestSwagMalformedRecognizedDirectivesProduceIssues(t *testing.T) {
	info := ParseSwagAnnotations(docOf(t, "// @Param only two\n// @Success nope {object}\n// @Security\n// @Header 200\nfunc H() {}"))
	if info == nil || len(info.Issues) != 4 {
		t.Fatalf("issues=%+v", info)
	}
}

func TestRepeatedRouterMatchesAnyObservedRegistration(t *testing.T) {
	doc := docOf(t, "// @Router /a [get]\n// @Router /b [post]\nfunc H() {}")
	routeA := modelRoute("GET", "/a")
	if d := ApplySwagFromDoc(&routeA, doc); d != nil {
		t.Fatalf("matching first router: %+v", d)
	}
	routeB := modelRoute("POST", "/b")
	if d := ApplySwagFromDoc(&routeB, doc); d != nil {
		t.Fatalf("matching second router: %+v", d)
	}
	routeC := modelRoute("GET", "/c")
	if d := ApplySwagFromDoc(&routeC, doc); d == nil {
		t.Fatal("missing mismatch diagnostic")
	}
}

func TestSwagGlobalMetadataAndSecurityDefinitions(t *testing.T) {
	doc := docOf(t, "// @title Accounts API\n// @version 2.1\n// @description Account operations.\n// @host api.example.test\n// @BasePath /v2\n// @schemes https http\n// @tag.name accounts\n// @tag.description Account endpoints\n// @securityDefinitions.apikey ApiKey\n// @in header\n// @name X-API-Key\n// @Security ApiKey\nfunc H() {}")
	api := ParseSwagGlobalAnnotations(doc)
	if api == nil || api.Title != "Accounts API" || api.BasePath != "/v2" || len(api.Tags) != 1 || len(api.Schemes) != 2 {
		t.Fatalf("api=%+v", api)
	}
	if scheme := api.SecurityDefinitions["ApiKey"]; scheme.Type != "apiKey" || scheme.In != "header" || scheme.Name != "X-API-Key" {
		t.Fatalf("scheme=%+v", scheme)
	}
}

func TestOperationDescriptionAloneIsNotGlobalMetadata(t *testing.T) {
	if got := ParseSwagGlobalAnnotations(docOf(t, "// @Description handler prose\n// @Security Bearer\nfunc H() {}")); got != nil {
		t.Fatalf("operation comment misclassified as global: %+v", got)
	}
}

func modelRoute(method, path string) model.Route { return model.Route{Method: method, GinPath: path} }
