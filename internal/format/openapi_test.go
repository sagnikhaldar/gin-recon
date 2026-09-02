package format

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sagnikhaldar/gin-recon/internal/config"
	"github.com/sagnikhaldar/gin-recon/internal/model"
	"github.com/sagnikhaldar/gin-recon/internal/report"
)

func routeAt(method, path string) model.Route {
	return model.Route{
		Method:             method,
		NormalizedPath:     path,
		GinPath:            path,
		SurfaceKind:        model.SurfaceRoute,
		FinalHandler:       model.Middleware{DisplayName: "Handler", CallableKind: model.CallableIdentifier, ResolutionStatus: model.Resolved},
		PathConfidence:     model.ConfidenceHigh,
		AnalysisConfidence: model.ConfidenceHigh,
	}
}

func inventoryWithRoutes(routes ...model.Route) *report.Report {
	rep := report.NewInventoryReport(model.ProfileTyped, testTarget())
	rep.Routes = routes
	rep.ScanCoverage = model.ScanCoverage{AnalyzedPackages: 1, AnalyzedFiles: 1, Complete: true}
	return rep
}

func decodeDoc(t *testing.T, data []byte) document {
	t.Helper()
	var doc document
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal generated document: %v\n%s", err, data)
	}
	return doc
}

func TestConvertGinPath(t *testing.T) {
	cases := []struct {
		in, wantPath string
		wantCatchAll bool
	}{
		{"/users/:id", "/users/{id}", false},
		{"/static/*filepath", "/static/{filepath}", true},
		{"/plain", "/plain", false},
		{"/a/:b/c/:d", "/a/{b}/c/{d}", false},
	}
	for _, c := range cases {
		gotPath, gotCatchAll := convertGinPath(c.in)
		if gotPath != c.wantPath || gotCatchAll != c.wantCatchAll {
			t.Errorf("convertGinPath(%q) = (%q, %v), want (%q, %v)", c.in, gotPath, gotCatchAll, c.wantPath, c.wantCatchAll)
		}
	}
}

func TestOpenAPIPathParametersAreRequiredStrings(t *testing.T) {
	rep := inventoryWithRoutes(routeAt("GET", "/users/:id"))
	data, diags, err := OpenAPI(rep, nil)
	if err != nil {
		t.Fatalf("OpenAPI: %v", err)
	}
	if len(diags) != 0 {
		t.Fatalf("unexpected diagnostics: %+v", diags)
	}
	doc := decodeDoc(t, data)
	item, ok := doc.Paths["/users/{id}"]
	if !ok || item.Get == nil {
		t.Fatalf("expected GET /users/{id}, got paths: %+v", doc.Paths)
	}
	if len(item.Get.Parameters) != 1 {
		t.Fatalf("expected 1 path parameter, got %+v", item.Get.Parameters)
	}
	p := item.Get.Parameters[0]
	if p.Name != "id" || p.In != "path" || !p.Required || p.Schema.Type != "string" {
		t.Errorf("unexpected parameter: %+v", p)
	}
}

func TestOpenAPICatchAllMarkedInExtension(t *testing.T) {
	rep := inventoryWithRoutes(routeAt("GET", "/static/*filepath"))
	data, _, err := OpenAPI(rep, nil)
	if err != nil {
		t.Fatalf("OpenAPI: %v", err)
	}
	if !strings.Contains(string(data), `"catchAll": true`) {
		t.Errorf("expected catchAll: true in x-gin-recon extension; got:\n%s", data)
	}
}

func TestUniqueOperationIDCollisionSuffix(t *testing.T) {
	used := map[string]int{}
	first := uniqueOperationID("GET", "/users/{id}", used)
	second := uniqueOperationID("GET", "/users/{id}", used)
	if first == second {
		t.Fatalf("expected distinct operation IDs on collision, got %q twice", first)
	}
	if first != "getUsersById" {
		t.Errorf("first operationId = %q, want getUsersById", first)
	}
	if second != "getUsersById-2" {
		t.Errorf("second operationId = %q, want getUsersById-2", second)
	}
}

func TestUniqueOperationIDRoot(t *testing.T) {
	used := map[string]int{}
	got := uniqueOperationID("GET", "/", used)
	if got != "getRoot" {
		t.Errorf("uniqueOperationID(GET, /) = %q, want getRoot", got)
	}
}

func TestOpenAPINonRepresentableMethodProducesDiagnostic(t *testing.T) {
	rep := inventoryWithRoutes(routeAt("CONNECT", "/tunnel"))
	data, diags, err := OpenAPI(rep, nil)
	if err != nil {
		t.Fatalf("OpenAPI: %v", err)
	}
	if len(diags) != 1 || diags[0].Code != "openapi-non-representable-method" {
		t.Fatalf("expected one openapi-non-representable-method diagnostic, got %+v", diags)
	}
	doc := decodeDoc(t, data)
	if len(doc.Paths) != 0 {
		t.Errorf("expected no paths for a non-representable method, got %+v", doc.Paths)
	}
}

// TestOpenAPIHandlesFullAnyExpansion is the regression for discover.go's
// anyMethods previously omitting CONNECT and TRACE (verified against
// vendored gin source: Any() genuinely expands to all nine). This proves
// the two methods flow correctly end to end once discovered: CONNECT has
// no OpenAPI 3.1 Path Item field and is diagnosed rather than silently
// dropped or force-fit; TRACE does have one and is emitted normally.
func TestOpenAPIHandlesFullAnyExpansion(t *testing.T) {
	rep := inventoryWithRoutes(
		routeAt("GET", "/wildcard"), routeAt("POST", "/wildcard"), routeAt("PUT", "/wildcard"),
		routeAt("PATCH", "/wildcard"), routeAt("DELETE", "/wildcard"), routeAt("HEAD", "/wildcard"),
		routeAt("OPTIONS", "/wildcard"), routeAt("CONNECT", "/wildcard"), routeAt("TRACE", "/wildcard"),
	)
	data, diags, err := OpenAPI(rep, nil)
	if err != nil {
		t.Fatalf("OpenAPI: %v", err)
	}
	if len(diags) != 1 || diags[0].Code != "openapi-non-representable-method" {
		t.Fatalf("expected exactly one openapi-non-representable-method diagnostic (for CONNECT), got %+v", diags)
	}
	doc := decodeDoc(t, data)
	item := doc.Paths["/wildcard"]
	for name, op := range map[string]*operation{
		"get": item.Get, "post": item.Post, "put": item.Put, "patch": item.Patch,
		"delete": item.Delete, "head": item.Head, "options": item.Options, "trace": item.Trace,
	} {
		if op == nil {
			t.Errorf("expected %s to be present on /wildcard, got nil", name)
		}
	}
}

// TestOpenAPIDuplicateRegistrationWithIdenticalEvidenceIsMerged is the
// las-be-lms regression this feature exists for: two separate route
// registrations at the exact same method+path (e.g. mounted from two
// different routers as build/deployment variants) must both survive in the
// generated document's x-gin-recon.registrations, not have the second one
// silently dropped — while OpenAPI's own one-operation-per-method/path rule
// still holds (exactly one "get" entry on the path item).
func TestOpenAPIDuplicateRegistrationWithIdenticalEvidenceIsMerged(t *testing.T) {
	rep := inventoryWithRoutes(routeAt("GET", "/dup"), routeAt("GET", "/dup"))
	data, diags, err := OpenAPI(rep, nil)
	if err != nil {
		t.Fatalf("OpenAPI: %v", err)
	}
	if len(diags) != 1 || diags[0].Code != "openapi-multiple-registrations" {
		t.Fatalf("expected one openapi-multiple-registrations diagnostic, got %+v", diags)
	}
	if diags[0].Severity != model.DiagnosticInfo {
		t.Errorf("Severity = %q, want info for identical-evidence registrations (consistent with build/deployment variants)", diags[0].Severity)
	}

	doc := decodeDoc(t, data)
	item := doc.Paths["/dup"]
	if item.Get == nil {
		t.Fatal("expected exactly one GET operation on /dup, not a dropped or duplicated Path Item entry")
	}
	registrations := ginReconRegistrations(t, data, "/dup", "get")
	if len(registrations) != 2 {
		t.Fatalf("x-gin-recon.registrations = %+v, want 2 entries (neither registration silently dropped)", registrations)
	}
}

// ginReconRegistrations decodes raw generated document bytes as a bare
// map (rather than through the typed document/operation structs, which
// have no UnmarshalJSON to reconstruct Extensions from the "x-gin-recon"
// key) to read x-gin-recon.registrations for one operation directly.
func ginReconRegistrations(t *testing.T, data []byte, path, method string) []map[string]any {
	t.Helper()
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal raw document: %v", err)
	}
	op, ok := raw["paths"].(map[string]any)[path].(map[string]any)[method].(map[string]any)
	if !ok {
		t.Fatalf("operation %s %s not found in raw document", method, path)
	}
	ext, ok := op["x-gin-recon"].(map[string]any)
	if !ok {
		t.Fatalf("x-gin-recon missing from operation %s %s", method, path)
	}
	regs, _ := ext["registrations"].([]any)
	result := make([]map[string]any, len(regs))
	for i, r := range regs {
		result[i] = r.(map[string]any)
	}
	return result
}

// TestOpenAPIDuplicateRegistrationWithDifferingEvidenceWarns proves the
// other half of the requirement: when two registrations for the same
// operation actually differ (different handler here), the diagnostic must
// escalate to a warning rather than reading identically to the harmless
// build-variant case, and both registrations' own evidence must still be
// individually recoverable from x-gin-recon.registrations.
func TestOpenAPIDuplicateRegistrationWithDifferingEvidenceWarns(t *testing.T) {
	first := routeAt("GET", "/dup")
	second := routeAt("GET", "/dup")
	second.FinalHandler = model.Middleware{DisplayName: "OtherHandler", CallableKind: model.CallableIdentifier, ResolutionStatus: model.Resolved}
	rep := inventoryWithRoutes(first, second)

	data, diags, err := OpenAPI(rep, nil)
	if err != nil {
		t.Fatalf("OpenAPI: %v", err)
	}
	if len(diags) != 1 || diags[0].Code != "openapi-multiple-registrations" {
		t.Fatalf("expected one openapi-multiple-registrations diagnostic, got %+v", diags)
	}
	if diags[0].Severity != model.DiagnosticWarning {
		t.Errorf("Severity = %q, want warning for differing-evidence registrations", diags[0].Severity)
	}

	registrations := ginReconRegistrations(t, data, "/dup", "get")
	if len(registrations) != 2 {
		t.Fatalf("registrations = %+v, want 2", registrations)
	}
	if registrations[0]["handler"] != "Handler" || registrations[1]["handler"] != "OtherHandler" {
		t.Errorf("registrations handlers = [%v, %v], want [Handler, OtherHandler]", registrations[0]["handler"], registrations[1]["handler"])
	}
}

func TestOpenAPIInventoryNeverAssertsSecurity(t *testing.T) {
	route := routeAt("GET", "/whoami")
	route.Auth = &model.AuthClassification{AuthStatus: model.AuthPublic, Confidence: model.ConfidenceHigh}
	rep := inventoryWithRoutes(route)

	// Even though route.Auth is populated (as it would be on a report that
	// happened to carry audit-shaped data), OpenAPI must only be called with
	// inventory data in this test to exercise the "no config" path — see
	// docs/openapi-strategy.md's rule that security is derived from audit
	// evidence plus config, and absent a config no scheme can ever resolve.
	data, _, err := OpenAPI(rep, nil)
	if err != nil {
		t.Fatalf("OpenAPI: %v", err)
	}
	doc := decodeDoc(t, data)
	op := doc.Paths["/whoami"].Get
	if op == nil {
		t.Fatal("expected GET /whoami")
	}
	if op.Security == nil {
		t.Fatal("expected AuthPublic to set an explicit empty security requirement")
	}
	if len(*op.Security) != 0 {
		t.Errorf("expected empty security array for public route, got %+v", *op.Security)
	}
}

func TestOpenAPISecurityMappingByAuthStatus(t *testing.T) {
	cfg := &config.Config{
		Version: 1,
		AuthMiddleware: map[string]config.AuthMiddlewareEntry{
			"example.com/demo/internal/auth.RequireUser": {OpenAPIScheme: "bearerAuth"},
		},
		OpenAPI: &config.OpenAPIConfig{
			SecuritySchemes: map[string]config.SecurityScheme{
				"bearerAuth": {Type: "http", Scheme: "bearer"},
			},
		},
	}

	provenSymbol := "example.com/demo/internal/auth.RequireUser"
	unresolvedSymbol := "example.com/demo/internal/auth.NotConfigured"

	proven := routeAt("GET", "/proven")
	proven.Auth = &model.AuthClassification{AuthStatus: model.AuthProven, MatchedEvidence: &provenSymbol, Confidence: model.ConfidenceHigh}

	public := routeAt("GET", "/public")
	public.Auth = &model.AuthClassification{AuthStatus: model.AuthPublic, Confidence: model.ConfidenceHigh}

	unknown := routeAt("GET", "/unknown")
	unknown.Auth = &model.AuthClassification{AuthStatus: model.AuthUnknown, Confidence: model.ConfidenceLow}

	provenUnresolved := routeAt("GET", "/proven-unresolved")
	provenUnresolved.Auth = &model.AuthClassification{AuthStatus: model.AuthProven, MatchedEvidence: &unresolvedSymbol, Confidence: model.ConfidenceHigh}

	rep := report.NewAuditReport(model.ProfileTyped, testTarget(), report.Summary{}, nil, report.PolicyEvaluation{}, nil)
	rep.Routes = []model.Route{proven, public, unknown, provenUnresolved}
	rep.ScanCoverage = model.ScanCoverage{AnalyzedPackages: 1, AnalyzedFiles: 1, Complete: true}

	data, _, err := OpenAPI(rep, cfg)
	if err != nil {
		t.Fatalf("OpenAPI: %v", err)
	}
	doc := decodeDoc(t, data)

	provenOp := doc.Paths["/proven"].Get
	if provenOp == nil || provenOp.Security == nil || len(*provenOp.Security) != 1 {
		t.Fatalf("expected proven route to get a resolved security requirement, got %+v", provenOp)
	}
	if _, ok := (*provenOp.Security)[0]["bearerAuth"]; !ok {
		t.Errorf("expected bearerAuth scheme, got %+v", *provenOp.Security)
	}

	publicOp := doc.Paths["/public"].Get
	if publicOp == nil || publicOp.Security == nil || len(*publicOp.Security) != 0 {
		t.Fatalf("expected public route to get an empty security requirement, got %+v", publicOp)
	}

	unknownOp := doc.Paths["/unknown"].Get
	if unknownOp == nil || unknownOp.Security != nil {
		t.Fatalf("expected unknown route to omit security entirely, got %+v", unknownOp)
	}
	if !strings.Contains(string(data), `"unrefined": [`) {
		t.Errorf("expected unknown/proven-unresolved routes to be marked unrefined; got:\n%s", data)
	}

	unresolvedOp := doc.Paths["/proven-unresolved"].Get
	if unresolvedOp == nil || unresolvedOp.Security != nil {
		t.Fatalf("expected proven-but-unresolved-scheme route to omit security, got %+v", unresolvedOp)
	}
}

// TestOpenAPIInfoDefaultsToDetectedModule is the regression for comparing
// two real reports side by side with no --config: both showed the identical
// generic "Gin Recon Report" title, giving no clue which service either was
// for without also keeping their output directories around. info.title now
// defaults to the detected module's repo name (its last path segment) —
// not the full module path, which for a real "github.com/org/repo"-style
// module read as an unwanted full URL/path rather than a short name.
func TestOpenAPIInfoDefaultsToDetectedModule(t *testing.T) {
	rep := inventoryWithRoutes()
	data, _, err := OpenAPI(rep, nil)
	if err != nil {
		t.Fatalf("OpenAPI: %v", err)
	}
	doc := decodeDoc(t, data)
	if doc.Info.Title != "demo API" || doc.Info.Version != "0.0.0" {
		t.Errorf("expected repo-name-derived default info, got %+v", doc.Info)
	}
}

func TestRepoNameFromExtractsLastPathSegment(t *testing.T) {
	cases := map[string]string{
		"github.com/smallcase/use-be-api":   "use-be-api",
		"github.com/smallcase/las-be-unity": "las-be-unity",
		"example.com/demo":                  "demo",
		"singlesegment":                     "singlesegment",
		"trailing/slash/":                   "trailing/slash/",
	}
	for module, want := range cases {
		if got := repoNameFrom(module); got != want {
			t.Errorf("repoNameFrom(%q) = %q, want %q", module, got, want)
		}
	}
}

// TestOpenAPIInfoFallsBackToGenericTitleWithNoModule covers the one case
// where the generic title still applies: no module could be resolved at all
// (an already-diagnosed load condition elsewhere in the report).
func TestOpenAPIInfoFallsBackToGenericTitleWithNoModule(t *testing.T) {
	rep := report.NewInventoryReport(model.ProfileTyped, report.Target{})
	data, _, err := OpenAPI(rep, nil)
	if err != nil {
		t.Fatalf("OpenAPI: %v", err)
	}
	doc := decodeDoc(t, data)
	if doc.Info.Title != "Gin Recon Report" || doc.Info.Version != "0.0.0" {
		t.Errorf("expected generic fallback info, got %+v", doc.Info)
	}
}

func TestOpenAPIInfoDefaultsAndOverrides(t *testing.T) {
	rep := inventoryWithRoutes()
	cfg := &config.Config{Version: 1, OpenAPI: &config.OpenAPIConfig{Title: "Demo API", Version: "1.2.3"}}
	data, _, err := OpenAPI(rep, cfg)
	if err != nil {
		t.Fatalf("OpenAPI: %v", err)
	}
	doc := decodeDoc(t, data)
	if doc.Info.Title != "Demo API" || doc.Info.Version != "1.2.3" {
		t.Errorf("expected overridden info, got %+v", doc.Info)
	}
	if doc.OpenAPI != "3.1.0" {
		t.Errorf("expected openapi version 3.1.0, got %q", doc.OpenAPI)
	}
}

func TestOpenAPIOperationsAreTaggedByFirstPathSegment(t *testing.T) {
	rep := inventoryWithRoutes(routeAt("GET", "/api/v1/users/:id"), routeAt("GET", "/"))
	data, _, err := OpenAPI(rep, nil)
	if err != nil {
		t.Fatalf("OpenAPI: %v", err)
	}
	doc := decodeDoc(t, data)

	got := doc.Paths["/api/v1/users/{id}"].Get.Tags
	if len(got) != 1 || got[0] != "api" {
		t.Errorf("tags = %v, want [\"api\"]", got)
	}

	rootTags := doc.Paths["/"].Get.Tags
	if len(rootTags) != 1 || rootTags[0] != "default" {
		t.Errorf("root path tags = %v, want [\"default\"]", rootTags)
	}
}

// TestOpenAPIOperationsHaveSummary is the regression for a real UX gap found
// comparing gin-recon's own openapi.json against a genuinely Redoc-rendered
// spec: without operation.summary, a generic OpenAPI viewer (not gin-recon's
// own HTML output, which always shows method+path itself) falls back to
// displaying just the bare HTTP verb as an operation's heading.
func TestOpenAPIOperationsHaveSummary(t *testing.T) {
	rep := inventoryWithRoutes(routeAt("GET", "/users/:id"))
	data, _, err := OpenAPI(rep, nil)
	if err != nil {
		t.Fatalf("OpenAPI: %v", err)
	}
	doc := decodeDoc(t, data)
	op := doc.Paths["/users/{id}"].Get
	if op == nil || op.Summary == "" {
		t.Fatalf("expected a non-empty summary, got %+v", op)
	}
	if !strings.Contains(op.Summary, "GET") || !strings.Contains(op.Summary, "/users/{id}") || !strings.Contains(op.Summary, "Handler") {
		t.Errorf("summary = %q, want it to identify method, path, and handler", op.Summary)
	}
}

// TestOpenAPISchemaInferenceNoteIsDocumentLevelNotRepeated is the regression
// for a real usability gap: the explanation that request/response body
// schemas are not yet inferred used to be duplicated verbatim in every
// single operation's default response description (real byte cost at scale,
// and clutter in any OpenAPI viewer), and pointed at
// "docs/openapi-strategy.md" — a path meaningless to anyone who receives
// only the generated document, not a gin-recon checkout. The explanation
// must now live once on info.description, and no dead repo-relative path may
// appear anywhere in the document.
func TestOpenAPISchemaInferenceNoteIsDocumentLevelNotRepeated(t *testing.T) {
	rep := inventoryWithRoutes(routeAt("GET", "/a"), routeAt("GET", "/b"), routeAt("GET", "/c"))
	data, _, err := OpenAPI(rep, nil)
	if err != nil {
		t.Fatalf("OpenAPI: %v", err)
	}
	if strings.Contains(string(data), "docs/openapi-strategy.md") {
		t.Errorf("document must not reference a repo-relative doc path unreachable outside a gin-recon checkout:\n%s", data)
	}

	doc := decodeDoc(t, data)
	if !strings.Contains(doc.Info.Description, "does not yet infer") {
		t.Errorf("info.description = %q, want it to explain the schema-inference scoping", doc.Info.Description)
	}

	for path, item := range doc.Paths {
		op := item.Get
		if op == nil {
			continue
		}
		desc := op.Responses["default"].Description
		if strings.Contains(desc, "does not yet infer") {
			t.Errorf("%s: per-operation response description repeats the document-level note verbatim, want it short and reference the document description instead; got %q", path, desc)
		}
	}
}

func TestOpenAPIEmptyReportProducesValidEmptyDocument(t *testing.T) {
	rep := inventoryWithRoutes()
	data, diags, err := OpenAPI(rep, nil)
	if err != nil {
		t.Fatalf("OpenAPI: %v", err)
	}
	if len(diags) != 0 {
		t.Errorf("expected no diagnostics for an empty report, got %+v", diags)
	}
	doc := decodeDoc(t, data)
	if len(doc.Paths) != 0 {
		t.Errorf("expected no paths, got %+v", doc.Paths)
	}
}
