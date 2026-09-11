// Package format's OpenAPI formatter implements docs/openapi-strategy.md.
// v1 deliberately covers only the parts of that contract with zero
// inference risk: route/path/operation conversion (fully derivable from
// already-discovered route identity) and security mapping (fully derivable
// from already-classified audit evidence plus reviewed configuration).
// Request/response body schema inference — parsing ShouldBind*/JSON/XML
// calls inside handler bodies to derive component schemas — is not built
// yet; every operation instead carries a single conservative default
// response and only path parameters, which is the exact fallback
// docs/openapi-strategy.md itself specifies for "the analyzer cannot prove
// exhaustive status behavior" rather than a shortcut around the contract.
package format

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"github.com/sagnikhaldar/gin-recon/internal/config"
	"github.com/sagnikhaldar/gin-recon/internal/model"
	"github.com/sagnikhaldar/gin-recon/internal/report"
)

// document is the OpenAPI 3.1 root object, restricted to the fields this
// formatter actually populates.
type document struct {
	OpenAPI              string                      `json:"openapi"`
	Info                 oaInfo                      `json:"info"`
	Servers              []oaServer                  `json:"servers,omitempty"`
	Tags                 []oaTag                     `json:"tags,omitempty"`
	Paths                map[string]pathItem         `json:"paths"`
	Components           *oaComponents               `json:"components,omitempty"`
	Documentation        *model.APIDocumentation     `json:"x-gin-recon-documentation,omitempty"`
	SourceSpecifications *model.SpecificationCatalog `json:"x-gin-recon-source-specifications,omitempty"`
}

type oaInfo struct {
	Title          string     `json:"title"`
	Version        string     `json:"version"`
	Description    string     `json:"description,omitempty"`
	TermsOfService string     `json:"termsOfService,omitempty"`
	Contact        *oaContact `json:"contact,omitempty"`
	License        *oaLicense `json:"license,omitempty"`
}
type oaContact struct {
	Name  string `json:"name,omitempty"`
	URL   string `json:"url,omitempty"`
	Email string `json:"email,omitempty"`
}
type oaLicense struct {
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
}
type oaServer struct {
	URL         string `json:"url"`
	Description string `json:"description,omitempty"`
}
type oaTag struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// schemaInferenceNote is the single source of truth for gin-recon's v1
// request/response body schema scoping — set once on the document's
// info.description (where every OpenAPI viewer, including a generic one
// with no notion of gin-recon's own extensions, renders it prominently once)
// rather than repeated on every operation's default response, which used to
// duplicate the same sentence across every route (real byte cost at scale:
// ~140 bytes × every route in the report) and cluttered each operation in a
// viewer with a document-level fact, not per-operation content. It
// deliberately does not reference a repo-relative doc path — the previous
// text pointed at "docs/openapi-strategy.md", meaningless and unreachable to
// anyone who receives only the generated document, not a gin-recon checkout.
// format.HTML's footer reads this same field back out of the document it
// wraps rather than keeping a second hardcoded copy, so the two surfaces
// cannot drift out of sync with each other.
const schemaInferenceNote = "gin-recon does not yet infer undocumented request and response schemas from arbitrary handler behavior. Schemas are emitted only when supported static evidence resolves them; annotation-declared schemas remain distinct from observed handler I/O, and unresolved types are diagnosed and omitted rather than rendered as authoritative empty objects. Route identity and configured security evidence remain analyzer-authoritative."

// pathItem uses named fields (not a map) so field order in the Go struct —
// preserved by encoding/json — gives deterministic method ordering matching
// common OpenAPI document convention, rather than depending on alphabetical
// map-key sort for something readers expect in a specific order.
type pathItem struct {
	Get     *operation `json:"get,omitempty"`
	Put     *operation `json:"put,omitempty"`
	Post    *operation `json:"post,omitempty"`
	Delete  *operation `json:"delete,omitempty"`
	Options *operation `json:"options,omitempty"`
	Head    *operation `json:"head,omitempty"`
	Patch   *operation `json:"patch,omitempty"`
	Trace   *operation `json:"trace,omitempty"`
}

// get returns the operation already occupying method's slot, or nil if
// that slot is empty or method is not OpenAPI-representable. Used to detect
// a method/path collision before deciding whether to occupy the slot or
// merge into what is already there.
func (p *pathItem) get(method string) *operation {
	switch method {
	case "GET":
		return p.Get
	case "PUT":
		return p.Put
	case "POST":
		return p.Post
	case "DELETE":
		return p.Delete
	case "OPTIONS":
		return p.Options
	case "HEAD":
		return p.Head
	case "PATCH":
		return p.Patch
	case "TRACE":
		return p.Trace
	default:
		return nil
	}
}

func (p *pathItem) set(method string, op *operation) bool {
	switch method {
	case "GET":
		if p.Get != nil {
			return false
		}
		p.Get = op
	case "PUT":
		if p.Put != nil {
			return false
		}
		p.Put = op
	case "POST":
		if p.Post != nil {
			return false
		}
		p.Post = op
	case "DELETE":
		if p.Delete != nil {
			return false
		}
		p.Delete = op
	case "OPTIONS":
		if p.Options != nil {
			return false
		}
		p.Options = op
	case "HEAD":
		if p.Head != nil {
			return false
		}
		p.Head = op
	case "PATCH":
		if p.Patch != nil {
			return false
		}
		p.Patch = op
	case "TRACE":
		if p.Trace != nil {
			return false
		}
		p.Trace = op
	default:
		return false // not an OpenAPI-representable method at all
	}
	return true
}

// representableMethods are the eight HTTP methods OpenAPI 3.1's Path Item
// object supports. CONNECT is deliberately absent — it has no Path Item
// field — and any other custom method (from Handle with a non-standard
// verb) is equally non-representable; both produce a diagnostic rather than
// being silently dropped or forced into a field that doesn't exist.
var representableMethods = map[string]bool{
	"GET": true, "PUT": true, "POST": true, "DELETE": true,
	"OPTIONS": true, "HEAD": true, "PATCH": true, "TRACE": true,
}

type operation struct {
	OperationID string                 `json:"operationId"`
	Summary     string                 `json:"summary,omitempty"`
	Description string                 `json:"description,omitempty"`
	Tags        []string               `json:"tags,omitempty"`
	Deprecated  bool                   `json:"deprecated,omitempty"`
	Parameters  []oaParameter          `json:"parameters,omitempty"`
	RequestBody *oaRequestBody         `json:"requestBody,omitempty"`
	Responses   map[string]oaResponse  `json:"responses"`
	Security    *[]map[string][]string `json:"security,omitempty"`
	Extensions  map[string]ginReconExt `json:"-"` // flattened into "x-gin-recon" by MarshalJSON
}

// operation needs a custom MarshalJSON only to place the single
// "x-gin-recon" extension object under its literal key, since Go struct
// tags can't express an "x-"-prefixed field name alongside normal ones
// without giving the field itself that exact (non-idiomatic-Go) name.
func (o operation) MarshalJSON() ([]byte, error) {
	type alias operation
	a := alias(o)
	base, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(base, &m); err != nil {
		return nil, err
	}
	ext, err := json.Marshal(o.Extensions["x-gin-recon"])
	if err != nil {
		return nil, err
	}
	m["x-gin-recon"] = ext
	return json.Marshal(m)
}

type oaParameter struct {
	Name        string   `json:"name"`
	In          string   `json:"in"`
	Required    bool     `json:"required"`
	Schema      oaSchema `json:"schema"`
	Description string   `json:"description,omitempty"`
}

type oaSchema struct {
	Ref                  string                       `json:"$ref,omitempty"`
	Type                 any                          `json:"type,omitempty"`
	Format               string                       `json:"format,omitempty"`
	Items                *oaSchema                    `json:"items,omitempty"`
	AdditionalProperties *oaSchema                    `json:"additionalProperties,omitempty"`
	Properties           map[string]oaSchema          `json:"properties,omitempty"`
	Required             []string                     `json:"required,omitempty"`
	Enum                 []any                        `json:"enum,omitempty"`
	Default              any                          `json:"default,omitempty"`
	Example              any                          `json:"example,omitempty"`
	Minimum              *float64                     `json:"minimum,omitempty"`
	Maximum              *float64                     `json:"maximum,omitempty"`
	MinLength            *int                         `json:"minLength,omitempty"`
	MaxLength            *int                         `json:"maxLength,omitempty"`
	Pattern              string                       `json:"pattern,omitempty"`
	Evidence             *model.DocumentationEvidence `json:"x-gin-recon-evidence,omitempty"`
	CustomSerialization  bool                         `json:"x-gin-recon-custom-serialization,omitempty"`
	OmitEmpty            bool                         `json:"x-gin-recon-omitempty,omitempty"`
}

type oaResponse struct {
	Description string                 `json:"description"`
	Headers     map[string]oaHeader    `json:"headers,omitempty"`
	Content     map[string]oaMediaType `json:"content,omitempty"`
}

type oaHeader struct {
	Description string    `json:"description,omitempty"`
	Schema      *oaSchema `json:"schema,omitempty"`
}
type oaMediaType struct {
	Schema  *oaSchema `json:"schema,omitempty"`
	Example any       `json:"example,omitempty"`
}
type oaRequestBody struct {
	Description string                 `json:"description,omitempty"`
	Required    bool                   `json:"required,omitempty"`
	Content     map[string]oaMediaType `json:"content"`
}

type oaComponents struct {
	SecuritySchemes map[string]config.SecurityScheme `json:"securitySchemes,omitempty"`
	Schemas         map[string]oaSchema              `json:"schemas,omitempty"`
}

// ginReconExt is docs/openapi-strategy.md's "Traceability" extension,
// attached to every generated operation. The top-level fields always
// describe the FIRST registration OpenAPI encountered for this exact
// method+path (in report.Routes order, already deterministically sorted —
// see internal/analyzer's normalize) — existing consumers reading
// x-gin-recon.source/.handler/etc. directly keep working unchanged whether
// or not a collision occurred.
//
// Registrations is populated only when more than one gin-recon Route
// registration shares this exact method+path (e.g. two separate routers
// mounted under build/deployment variants that both happen to register the
// same operation, as observed on a real multi-router production service):
// it holds one entry per registration, in encounter order, including the
// first one already mirrored at the top level — so a consumer that wants
// full traceability across every registration reads Registrations, while
// every existing top-level field keeps meaning exactly what it always has.
// OpenAPI's one-operation-per-method/path structure is preserved: this
// never produces a second Path Item entry, only richer metadata on the one
// that exists, and no registration is ever silently dropped to make room
// for another (docs/openapi-strategy.md's OpenAPI collision requirement).
type ginReconExt struct {
	Method             string        `json:"method"`
	GinPath            string        `json:"ginPath"`
	Source             string        `json:"source,omitempty"`
	Handler            string        `json:"handler,omitempty"`
	Middleware         []string      `json:"middleware,omitempty"`
	AuthStatus         string        `json:"authStatus,omitempty"`
	Roles              []string      `json:"roles,omitempty"`
	Scopes             []string      `json:"scopes,omitempty"`
	AnalysisConfidence string        `json:"analysisConfidence,omitempty"`
	RegistrationKind   string        `json:"registrationKind,omitempty"`
	CatchAll           bool          `json:"catchAll,omitempty"`
	Unrefined          []string      `json:"unrefined,omitempty"`
	DiagnosticCodes    []string      `json:"diagnosticCodes,omitempty"`
	Registrations      []ginReconExt `json:"registrations,omitempty"`

	// EvidenceSource records which non-analyzer source, if any, actually
	// supplied this operation's Summary/Description/Tags/Deprecated —
	// currently only "swag" (docs/adr/0012-swag-annotation-evidence.md). It is
	// set by applySwagEvidence only when that source actually replaced this
	// formatter's own generic placeholder for at least one of those fields —
	// never for analyzer-typed evidence (there is none for these prose fields
	// today) and never merely because Route.Swag is present with nothing to
	// contribute. Absent entirely (the common case) when swag won nothing, so
	// a reader can tell "gin-recon's own generic text" from "prose that came
	// from somewhere outside static analysis" — the one piece of provenance
	// the merged Summary/Description strings alone no longer carry.
	EvidenceSource          string                                 `json:"evidenceSource,omitempty"`
	DocumentationSecurity   []model.SwagSecurity                   `json:"documentationSecurity,omitempty"`
	DocumentationIssues     []model.SwagIssue                      `json:"documentationIssues,omitempty"`
	DocumentationExtensions map[string]any                         `json:"documentationExtensions,omitempty"`
	DocumentationFields     map[string]model.DocumentationEvidence `json:"documentationFields,omitempty"`
}

// OpenAPI renders rep as an OpenAPI 3.1 document. cfg supplies title/version
// metadata and configured security schemes; it may be nil (inventory
// reports never assert security regardless of whether a config was loaded,
// per ADR 0007).
//
// The returned diagnostics (non-representable methods, conflicting
// registrations) are discovered only during formatting, not during the
// original scan — report.Report's own Diagnostics slice is immutable
// evidence from that scan (docs/reference.md: "Formatters must not
// mutate... evidence"), so these cannot be spliced back into it. Callers
// are responsible for surfacing them (cmd/gin-recon writes them to stderr).
func OpenAPI(rep *report.Report, cfg *config.Config) ([]byte, []model.Diagnostic, error) {
	doc := document{
		OpenAPI:              "3.1.0",
		Info:                 infoFrom(rep, cfg),
		Servers:              serversFrom(rep),
		Tags:                 tagsFrom(rep),
		Paths:                map[string]pathItem{},
		Documentation:        rep.Documentation,
		SourceSpecifications: rep.Specifications,
	}

	usedOperationIDs := map[string]int{}
	var diagnostics []model.Diagnostic

	for _, route := range rep.Routes {
		diagnostics = append(diagnostics, buildOperation(&doc, route, rep, cfg, usedOperationIDs)...)
	}

	schemes := securitySchemesFrom(cfg)
	schemas, componentDiagnostics := collectSwagComponents(rep)
	diagnostics = append(diagnostics, componentDiagnostics...)
	if len(schemes) > 0 || len(schemas) > 0 {
		doc.Components = &oaComponents{SecuritySchemes: schemes, Schemas: schemas}
	}

	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, diagnostics, err
	}
	return data, diagnostics, nil
}

// infoFrom defaults info.title to the detected module path rather than a
// generic "Gin Recon Report" for every service — found needlessly unhelpful
// comparing reports side by side across two real repositories, where an
// unconfigured openapi.json/api.html gave no clue which service it was for
// without also carrying its output directory along. rep.Target.Module is
// empty only when no module could be resolved at all (an unusual, already-
// diagnosed load condition), in which case the generic fallback still
// applies. A configured title/version always wins, unchanged from before.
func infoFrom(rep *report.Report, cfg *config.Config) oaInfo {
	info := oaInfo{Title: "Gin Recon Report", Version: "0.0.0", Description: schemaInferenceNote}
	if rep.Target.Module != "" {
		info.Title = repoNameFrom(rep.Target.Module) + " API"
	}
	if d := rep.Documentation; d != nil {
		if d.Title != "" {
			info.Title = d.Title
		}
		if d.Version != "" {
			info.Version = d.Version
		}
		if d.Description != "" {
			info.Description = d.Description + "\n\n" + schemaInferenceNote
		}
		info.TermsOfService = d.TermsOfService
		if d.ContactName != "" || d.ContactURL != "" || d.ContactEmail != "" {
			info.Contact = &oaContact{Name: d.ContactName, URL: d.ContactURL, Email: d.ContactEmail}
		}
		if d.LicenseName != "" {
			info.License = &oaLicense{Name: d.LicenseName, URL: d.LicenseURL}
		}
	}
	if cfg != nil && cfg.OpenAPI != nil {
		if cfg.OpenAPI.Title != "" {
			info.Title = cfg.OpenAPI.Title
		}
		if cfg.OpenAPI.Version != "" {
			info.Version = cfg.OpenAPI.Version
		}
	}
	return info
}

func serversFrom(rep *report.Report) []oaServer {
	d := rep.Documentation
	if d == nil {
		return nil
	}
	base := d.BasePath
	if base == "" {
		base = "/"
	}
	if !strings.HasPrefix(base, "/") {
		base = "/" + base
	}
	if d.Host == "" {
		if d.BasePath != "" {
			return []oaServer{{URL: base, Description: "Documented relative base path"}}
		}
		return nil
	}
	schemes := d.Schemes
	if len(schemes) == 0 {
		schemes = []string{"https"}
	}
	out := make([]oaServer, 0, len(schemes))
	for _, scheme := range schemes {
		out = append(out, oaServer{URL: scheme + "://" + d.Host + base, Description: "Derived from authored swag host/basePath/schemes"})
	}
	return out
}
func tagsFrom(rep *report.Report) []oaTag {
	if rep.Documentation == nil {
		return nil
	}
	out := make([]oaTag, 0, len(rep.Documentation.Tags))
	for _, tag := range rep.Documentation.Tags {
		out = append(out, oaTag{Name: tag.Name, Description: tag.Description})
	}
	return out
}

// repoNameFrom returns a Go module path's last slash-separated segment —
// gin-recon has no git integration and cannot know a scanned module's
// actual repository name, so this is deliberately only ever "the module
// path's last segment," not a claim about the real repo. For the
// overwhelmingly common case of one module per repository (module path
// exactly "host/owner/repo", e.g. "github.com/smallcase/use-be-api"), that
// segment IS the repo name, which is what a short, readable title needs —
// the full path was found needlessly long and URL-like for a title
// comparing two real reports side by side.
func repoNameFrom(module string) string {
	if i := strings.LastIndex(module, "/"); i >= 0 && i+1 < len(module) {
		return module[i+1:]
	}
	return module
}

// buildOperation converts one route into an OpenAPI operation and inserts
// it into doc.Paths, or — when another route already registered the exact
// same method+path — merges its evidence into that operation's
// x-gin-recon.registrations instead of dropping it (see ginReconExt's doc
// comment). Either way it returns a diagnostic for anything a human should
// know about: a non-representable method, or multiple registrations for
// one operation.
func buildOperation(doc *document, route model.Route, rep *report.Report, cfg *config.Config, usedIDs map[string]int) []model.Diagnostic {
	if !representableMethods[route.Method] {
		return []model.Diagnostic{{
			Code:     "openapi-non-representable-method",
			Severity: model.DiagnosticWarning,
			Message:  fmt.Sprintf("method %q has no OpenAPI 3.1 Path Item field and cannot be represented", route.Method),
			Source:   route.Source,
		}}
	}

	oapiPath, catchAll := convertGinPath(route.GinPath)

	item, exists := doc.Paths[oapiPath]
	if !exists {
		item = pathItem{}
	}

	// Summary is set from data this formatter already carries in
	// x-gin-recon (method, path, handler) — zero additional inference risk
	// — because a generic OpenAPI viewer (Redoc, Swagger UI, Postman) has no
	// notion of gin-recon's own extension and falls back to showing just the
	// bare HTTP verb as an operation's heading when summary is absent,
	// observed directly comparing a real Redoc-rendered spec against this
	// formatter's own output. Our own HTML viewer already shows method and
	// path in every row regardless, so this is purely for interoperability
	// with tooling other than the one this project ships.
	op := &operation{
		OperationID: uniqueOperationID(route.Method, oapiPath, usedIDs),
		Summary:     fmt.Sprintf("%s %s -> %s", route.Method, oapiPath, route.FinalHandler.DisplayName),
		Tags:        []string{tagFor(oapiPath)},
		Parameters:  pathParameters(oapiPath),
		Responses:   map[string]oaResponse{"default": {Description: "Unspecified response — schema not inferred; see the document description."}},
		Extensions:  map[string]ginReconExt{"x-gin-recon": ginReconExtensionFor(route, rep, cfg, catchAll)},
	}
	diagnostics := applySwagEvidence(op, route)
	if route.Swag != nil && route.Swag.ID != "" {
		op.OperationID = uniqueDocumentedOperationID(route.Swag.ID, usedIDs)
	}
	applySecurity(op, route, cfg)

	if existing := item.get(route.Method); existing != nil {
		diag := mergeRegistration(existing, op, route, oapiPath)
		doc.Paths[oapiPath] = item
		return append(diagnostics, diag...)
	}

	item.set(route.Method, op)
	doc.Paths[oapiPath] = item
	return diagnostics
}

// applySwagEvidence overlays a route's swaggo/swag doc-comment evidence
// (internal/analyzer/gin.ParseSwagAnnotations, attached to route.Swag during
// discovery) onto op's Summary/Description/Tags/Deprecated, per
// docs/adr/0012-swag-annotation-evidence.md: gin-recon has no better source
// for human-readable operation prose than a developer's own swag comment, so
// each of these four fields, if present in the annotation, replaces this
// formatter's own generic placeholder rather than merging with it. Nothing
// else about op is touched — route identity, security, and x-gin-recon
// evidence remain exactly as already computed, matching ADR 0007's
// precedence that analyzer evidence is authoritative for everything except
// prose gin-recon cannot otherwise derive.
func applySwagEvidence(op *operation, route model.Route) []model.Diagnostic {
	if route.Swag == nil {
		return nil
	}
	var diagnostics []model.Diagnostic
	changed := false
	if route.Swag.Summary != "" {
		op.Summary = route.Swag.Summary
		changed = true
	}
	if route.Swag.Description != "" {
		op.Description = route.Swag.Description
		changed = true
	}
	if len(route.Swag.Tags) > 0 {
		op.Tags = route.Swag.Tags
		changed = true
	}
	if route.Swag.Deprecated {
		op.Deprecated = true
		changed = true
	}
	for _, router := range route.Swag.Routers {
		if router.Deprecated && router.Path == swaggerPathForRoute(route.GinPath) && (router.Method == "" || router.Method == route.Method) {
			op.Deprecated = true
			changed = true
			break
		}
	}
	if route.Swag.ID != "" {
		changed = true
	}
	applySwagParameters(op, route.Swag, &diagnostics, route.Source)
	applySwagResponses(op, route.Swag, &diagnostics, route.Source)
	ext := op.Extensions["x-gin-recon"]
	ext.DocumentationSecurity = route.Swag.Security // documentary only: never assigned to operation.security
	ext.DocumentationIssues = route.Swag.Issues
	ext.DocumentationExtensions = route.Swag.Extensions
	ext.DocumentationFields = route.Swag.Fields
	op.Extensions["x-gin-recon"] = ext
	// evidenceSource is a whole-operation marker, not per-field — see
	// ginReconExt.EvidenceSource's doc comment — so it is set once here
	// whenever swag actually replaced anything.
	if changed {
		ext := op.Extensions["x-gin-recon"]
		ext.EvidenceSource = "swag"
		op.Extensions["x-gin-recon"] = ext
	}
	return diagnostics
}

func swaggerPathForRoute(path string) string { converted, _ := convertGinPath(path); return converted }

func applySwagParameters(op *operation, swag *model.SwagInfo, diagnostics *[]model.Diagnostic, source *model.Source) {
	var body *model.SwagParameter
	form := map[string]oaSchema{}
	formRequired := []string{}
	for i := range swag.Parameters {
		p := swag.Parameters[i]
		schema, ok := openAPISchemaForSwag(swag, p.Schema)
		if !ok {
			*diagnostics = append(*diagnostics, unresolvedSwagDiagnostic("parameter "+p.Name, p.Schema, source))
			continue
		}
		switch p.In {
		case "body":
			if body != nil {
				*diagnostics = append(*diagnostics, model.Diagnostic{Code: "swag-request-body-conflict", Severity: model.DiagnosticWarning, Message: "multiple @Param body declarations; first declaration retained", Source: source})
				continue
			}
			body = &p
			content := swag.Accept
			if len(content) == 0 {
				content = []string{"application/json"}
			}
			op.RequestBody = &oaRequestBody{Description: p.Description, Required: p.Required, Content: mediaContent(content, &schema)}
		case "formData":
			form[p.Name] = schema
			if p.Required {
				formRequired = append(formRequired, p.Name)
			}
		default:
			op.Parameters = upsertParameter(op.Parameters, oaParameter{Name: p.Name, In: p.In, Required: p.Required, Schema: schema, Description: p.Description})
		}
	}
	if len(form) > 0 {
		slices.Sort(formRequired)
		s := oaSchema{Type: "object", Properties: form, Required: formRequired}
		content := swag.Accept
		if len(content) == 0 {
			content = []string{"multipart/form-data"}
		}
		if op.RequestBody == nil {
			op.RequestBody = &oaRequestBody{Content: mediaContent(content, &s)}
		} else {
			*diagnostics = append(*diagnostics, model.Diagnostic{Code: "swag-request-body-conflict", Severity: model.DiagnosticWarning, Message: "body and formData parameters cannot both be represented as one OpenAPI requestBody; body retained", Source: source})
		}
	}
}

func applySwagResponses(op *operation, swag *model.SwagInfo, diagnostics *[]model.Diagnostic, source *model.Source) {
	if len(swag.Responses) == 0 {
		return
	}
	op.Responses = map[string]oaResponse{}
	for _, r := range swag.Responses {
		resp := oaResponse{Description: r.Description}
		if resp.Description == "" {
			resp.Description = "Response"
		}
		if r.Schema != nil {
			if schema, ok := openAPISchemaForSwag(swag, r.Schema); ok {
				content := swag.Produce
				if len(content) == 0 {
					content = []string{"application/json"}
				}
				resp.Content = mediaContent(content, &schema)
			} else {
				*diagnostics = append(*diagnostics, unresolvedSwagDiagnostic("response "+r.Status, r.Schema, source))
			}
		}
		for _, h := range r.Headers {
			schema, ok := openAPISchemaForSwag(swag, h.Schema)
			if !ok {
				*diagnostics = append(*diagnostics, unresolvedSwagDiagnostic("response header "+h.Name, h.Schema, source))
				continue
			}
			if resp.Headers == nil {
				resp.Headers = map[string]oaHeader{}
			}
			resp.Headers[h.Name] = oaHeader{Description: h.Description, Schema: &schema}
		}
		if _, exists := op.Responses[r.Status]; exists {
			*diagnostics = append(*diagnostics, model.Diagnostic{Code: "swag-response-conflict", Severity: model.DiagnosticWarning, Message: "duplicate documented response status " + r.Status + "; last declaration retained", Source: source})
		}
		op.Responses[r.Status] = resp
	}
}

func upsertParameter(params []oaParameter, incoming oaParameter) []oaParameter {
	for i := range params {
		if params[i].Name == incoming.Name && params[i].In == incoming.In {
			params[i] = incoming
			return params
		}
	}
	return append(params, incoming)
}
func mediaContent(types []string, schema *oaSchema) map[string]oaMediaType {
	out := map[string]oaMediaType{}
	for _, t := range types {
		out[t] = oaMediaType{Schema: schema}
	}
	return out
}
func unresolvedSwagDiagnostic(subject string, schema *model.SchemaEvidence, source *model.Source) model.Diagnostic {
	status, goType := "unresolved", ""
	if schema != nil {
		status, goType = schema.Evidence.Status, schema.GoType
	}
	return model.Diagnostic{Code: "swag-schema-unresolved", Severity: model.DiagnosticWarning, Message: fmt.Sprintf("%s schema %q is %s; omitted rather than emitted as an authoritative empty object", subject, goType, status), Source: source}
}

func openAPISchema(in *model.SchemaEvidence) (oaSchema, bool) {
	if in == nil {
		return oaSchema{}, false
	}
	if in.Ref == "" && in.Type == "" {
		return oaSchema{}, false
	}
	out := oaSchema{Format: in.Format, Enum: in.Enum, Default: in.Default, Example: in.Example, Minimum: in.Minimum, Maximum: in.Maximum, MinLength: in.MinLength, MaxLength: in.MaxLength, Pattern: in.Pattern, Evidence: &in.Evidence, CustomSerialization: in.CustomSerialization, OmitEmpty: in.OmitEmpty}
	if in.Ref != "" {
		out.Ref = "#/components/schemas/" + in.Ref
	} else if in.Nullable {
		out.Type = []string{in.Type, "null"}
	} else {
		out.Type = in.Type
	}
	if in.Items != nil {
		if v, ok := openAPISchema(in.Items); ok {
			out.Items = &v
		}
	}
	if in.AdditionalProperties != nil {
		if v, ok := openAPISchema(in.AdditionalProperties); ok {
			out.AdditionalProperties = &v
		}
	}
	if len(in.Properties) > 0 {
		out.Properties = map[string]oaSchema{}
		for k, v := range in.Properties {
			if x, ok := openAPISchema(&v); ok {
				out.Properties[k] = x
			}
		}
	}
	out.Required = in.Required
	return out, true
}

func openAPISchemaForSwag(swag *model.SwagInfo, in *model.SchemaEvidence) (oaSchema, bool) {
	if !schemaRefsKnown(in, swag.Components, map[*model.SchemaEvidence]bool{}, 0) {
		return oaSchema{}, false
	}
	return openAPISchema(in)
}

func schemaRefsKnown(in *model.SchemaEvidence, components map[string]model.SchemaEvidence, seen map[*model.SchemaEvidence]bool, depth int) bool {
	if in == nil || depth > 64 {
		return in == nil
	}
	if seen[in] {
		return true
	}
	seen[in] = true
	if in.Ref != "" {
		_, ok := components[in.Ref]
		return ok
	}
	if !schemaRefsKnown(in.Items, components, seen, depth+1) || !schemaRefsKnown(in.AdditionalProperties, components, seen, depth+1) {
		return false
	}
	for _, value := range in.Properties {
		copyValue := value
		if !schemaRefsKnown(&copyValue, components, seen, depth+1) {
			return false
		}
	}
	return true
}

func collectSwagComponents(rep *report.Report) (map[string]oaSchema, []model.Diagnostic) {
	out := map[string]oaSchema{}
	var diagnostics []model.Diagnostic
	for _, route := range rep.Routes {
		if route.Swag == nil {
			continue
		}
		for id, schema := range route.Swag.Components {
			if converted, ok := openAPISchema(&schema); ok {
				if prior, exists := out[id]; exists {
					if !reflect.DeepEqual(prior, converted) {
						diagnostics = append(diagnostics, model.Diagnostic{Code: "swag-component-conflict", Severity: model.DiagnosticWarning, Message: "component " + id + " has conflicting schemas; first deterministic declaration retained", Source: route.Source})
					}
					continue
				}
				out[id] = converted
			}
		}
	}
	return out, diagnostics
}

// mergeRegistration folds incoming's x-gin-recon evidence into existing's
// Registrations list rather than discarding it, and reports whether the
// registrations agree. It never creates a second Path Item entry — OpenAPI
// permits exactly one operation per method+path — so every additional
// registration for the same operation is visible only through
// Registrations, never through a duplicate top-level operation.
func mergeRegistration(existing, incoming *operation, route model.Route, oapiPath string) []model.Diagnostic {
	existingExt := existing.Extensions["x-gin-recon"]
	incomingExt := incoming.Extensions["x-gin-recon"]
	incomingExt.Registrations = nil // never nest a registration's own list

	if len(existingExt.Registrations) == 0 {
		seed := existingExt
		seed.Registrations = nil
		existingExt.Registrations = []ginReconExt{seed}
	}
	existingExt.Registrations = append(existingExt.Registrations, incomingExt)
	existing.Extensions["x-gin-recon"] = existingExt

	n := len(existingExt.Registrations)
	if registrationEvidenceEqual(existingExt.Registrations[0], incomingExt) {
		return []model.Diagnostic{{
			Code:     "openapi-multiple-registrations",
			Severity: model.DiagnosticInfo,
			Message:  fmt.Sprintf("%s %s has %d registrations with identical handler/middleware/auth evidence, consistent with build or deployment variants; see x-gin-recon.registrations", route.Method, oapiPath, n),
			Source:   route.Source,
		}}
	}
	return []model.Diagnostic{{
		Code:     "openapi-multiple-registrations",
		Severity: model.DiagnosticWarning,
		Message:  fmt.Sprintf("%s %s has %d registrations with differing handler/middleware/auth evidence; see x-gin-recon.registrations for each one", route.Method, oapiPath, n),
		Source:   route.Source,
	}}
}

// registrationEvidenceEqual compares only the fields that describe what a
// registration actually does (handler, middleware chain, auth evidence) —
// not Source or AnalysisConfidence, which legitimately differ between two
// otherwise-identical registrations (different file, or resolved through a
// different registrar path) without that difference meaning anything about
// whether the two registrations behave the same way.
func registrationEvidenceEqual(a, b ginReconExt) bool {
	return a.Handler == b.Handler &&
		slices.Equal(a.Middleware, b.Middleware) &&
		a.AuthStatus == b.AuthStatus &&
		slices.Equal(a.Roles, b.Roles) &&
		slices.Equal(a.Scopes, b.Scopes)
}

// convertGinPath converts Gin's :name and *name segments to OpenAPI's
// {name} form, per docs/openapi-strategy.md. It reports whether the path
// contains a catch-all segment, which the caller marks with
// x-gin-recon-catch-all on the resulting operation.
func convertGinPath(ginPath string) (openAPIPath string, catchAll bool) {
	segments := strings.Split(ginPath, "/")
	for i, seg := range segments {
		switch {
		case strings.HasPrefix(seg, ":"):
			segments[i] = "{" + seg[1:] + "}"
		case strings.HasPrefix(seg, "*"):
			segments[i] = "{" + seg[1:] + "}"
			catchAll = true
		}
	}
	return strings.Join(segments, "/"), catchAll
}

// tagFor derives an operation's OpenAPI tag from its already-converted path's
// first non-parameter segment, so operations naturally group by the API's
// own routing structure ("/api/v1/users/{id}" -> "api") with zero configured
// or inferred information — the same low-risk heuristic express-recon's
// formatter and gin-recon's own HTML viewer already use, now computed once
// here so both the raw JSON and every consumer of it (our viewer or a
// third-party one) agree on groupings instead of recomputing it twice.
func tagFor(oapiPath string) string {
	for _, seg := range strings.Split(oapiPath, "/") {
		if seg == "" || strings.HasPrefix(seg, "{") {
			continue
		}
		return seg
	}
	return "default"
}

// pathParameters derives {name} parameters directly from the already-
// converted OpenAPI path — the one request-evidence source with zero
// inference risk, since it comes straight from the URL pattern itself, not
// from analyzing handler code. Path parameters are always required, per
// docs/openapi-strategy.md.
func pathParameters(oapiPath string) []oaParameter {
	var params []oaParameter
	for _, seg := range strings.Split(oapiPath, "/") {
		if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") {
			params = append(params, oaParameter{
				Name:     seg[1 : len(seg)-1],
				In:       "path",
				Required: true,
				Schema:   oaSchema{Type: "string"},
			})
		}
	}
	return params
}

// uniqueOperationID generates a stable, deterministic operationId from
// method and path, appending a numeric suffix on collision — per
// docs/openapi-strategy.md's "adding a deterministic suffix for collisions."
func uniqueOperationID(method, oapiPath string, used map[string]int) string {
	base := strings.ToLower(method)
	for _, seg := range strings.Split(oapiPath, "/") {
		if seg == "" {
			continue
		}
		if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") {
			base += "By" + pascalCase(seg[1:len(seg)-1])
		} else {
			base += pascalCase(seg)
		}
	}
	if base == strings.ToLower(method) {
		base += "Root"
	}

	count := used[base]
	used[base] = count + 1
	if count == 0 {
		return base
	}
	return base + "-" + strconv.Itoa(count+1)
}

func uniqueDocumentedOperationID(documented string, used map[string]int) string {
	base := strings.TrimSpace(documented)
	if base == "" {
		base = "operation"
	}
	count := used[base]
	used[base] = count + 1
	if count == 0 {
		return base
	}
	return base + strconv.Itoa(count+1)
}

// pascalCase capitalizes the first letter of each run of alphanumeric
// characters and discards separators, giving a readable, deterministic
// identifier fragment from an arbitrary path segment.
func pascalCase(s string) string {
	var b strings.Builder
	upperNext := true
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9':
			if upperNext && r >= 'a' && r <= 'z' {
				r -= 'a' - 'A'
			}
			b.WriteRune(r)
			upperNext = false
		default:
			upperNext = true
		}
	}
	return b.String()
}

func ginReconExtensionFor(route model.Route, rep *report.Report, cfg *config.Config, catchAll bool) ginReconExt {
	ext := ginReconExt{
		Method:             route.Method,
		GinPath:            route.GinPath,
		Handler:            route.FinalHandler.DisplayName,
		AnalysisConfidence: string(route.AnalysisConfidence),
		CatchAll:           catchAll,
	}
	if route.Source != nil {
		ext.Source = sourceLabel(route.Source)
	}
	if route.RegistrationKind != nil {
		ext.RegistrationKind = string(*route.RegistrationKind)
	}
	for _, mw := range route.Middleware {
		ext.Middleware = append(ext.Middleware, mw.DisplayName)
	}
	if route.Auth != nil {
		ext.AuthStatus = string(route.Auth.AuthStatus)
	}
	return ext
}
