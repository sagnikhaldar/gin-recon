package analyzer

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pb33f/libopenapi"
	"github.com/pb33f/libopenapi/datamodel"
	v2 "github.com/pb33f/libopenapi/datamodel/high/v2"
	v3 "github.com/pb33f/libopenapi/datamodel/high/v3"
	"github.com/sagnikhaldar/gin-recon/internal/model"
	"github.com/sagnikhaldar/gin-recon/internal/report"
)

// existingSpecMethods are the eight HTTP methods a v3 PathItem exposes as
// named fields (mirrors internal/format's representableMethods) — the only
// methods a pre-existing document can name that gin-recon's own OpenAPI
// formatter could ever have produced in the first place, so these are the
// only ones worth reconciling against.
var existingSpecMethods = []struct {
	name string
	get  func(*v3.PathItem) *v3.Operation
}{
	{"GET", func(p *v3.PathItem) *v3.Operation { return p.Get }},
	{"PUT", func(p *v3.PathItem) *v3.Operation { return p.Put }},
	{"POST", func(p *v3.PathItem) *v3.Operation { return p.Post }},
	{"DELETE", func(p *v3.PathItem) *v3.Operation { return p.Delete }},
	{"OPTIONS", func(p *v3.PathItem) *v3.Operation { return p.Options }},
	{"HEAD", func(p *v3.PathItem) *v3.Operation { return p.Head }},
	{"PATCH", func(p *v3.PathItem) *v3.Operation { return p.Patch }},
	{"TRACE", func(p *v3.PathItem) *v3.Operation { return p.Trace }},
}

// existingSpecMethodsV2 is existingSpecMethods' Swagger 2.0 counterpart.
// Swagger 2.0's PathItem object has no TRACE field at all (it was introduced
// in OpenAPI 3.0), so this list is one entry shorter than existingSpecMethods
// — everything else about the two lists (and how they're used) is identical.
var existingSpecMethodsV2 = []struct {
	name string
	get  func(*v2.PathItem) *v2.Operation
}{
	{"GET", func(p *v2.PathItem) *v2.Operation { return p.Get }},
	{"PUT", func(p *v2.PathItem) *v2.Operation { return p.Put }},
	{"POST", func(p *v2.PathItem) *v2.Operation { return p.Post }},
	{"DELETE", func(p *v2.PathItem) *v2.Operation { return p.Delete }},
	{"OPTIONS", func(p *v2.PathItem) *v2.Operation { return p.Options }},
	{"HEAD", func(p *v2.PathItem) *v2.Operation { return p.Head }},
	{"PATCH", func(p *v2.PathItem) *v2.Operation { return p.Patch }},
}

// docOperation is a format-agnostic view of one matched document operation —
// exactly the fields attachExistingDoc needs off either a v3.Operation or a
// v2.Operation, normalized once at read time so the matching/merge logic in
// reconcileWithModel and attachExistingDoc never has to know or care which
// document format (OpenAPI 3.x or Swagger 2.0) produced it.
type docOperation struct {
	Summary           string
	Description       string
	Tags              []string
	Deprecated        bool
	ParamDescriptions map[string]string
}

// docOperationFromV3 normalizes a v3.Operation into docOperation.
func docOperationFromV3(op *v3.Operation) docOperation {
	out := docOperation{Summary: op.Summary, Description: op.Description, Tags: op.Tags}
	if op.Deprecated != nil {
		out.Deprecated = *op.Deprecated
	}
	for _, p := range op.Parameters {
		if p == nil || p.In != "path" || strings.TrimSpace(p.Description) == "" {
			continue
		}
		if out.ParamDescriptions == nil {
			out.ParamDescriptions = map[string]string{}
		}
		out.ParamDescriptions[p.Name] = p.Description
	}
	return out
}

// docOperationFromV2 normalizes a v2.Operation into docOperation. Swagger
// 2.0's Parameter object uses the same "in"/"name"/"description" shape as
// OpenAPI 3.x's for path parameters (the two formats diverge on parameter
// typing — v2 puts Type/Format directly on Parameter instead of nesting a
// Schema — but that divergence is irrelevant here since this analyzer only
// ever reconciles a path parameter's description, never its type/schema).
func docOperationFromV2(op *v2.Operation) docOperation {
	out := docOperation{Summary: op.Summary, Description: op.Description, Tags: op.Tags, Deprecated: op.Deprecated}
	for _, p := range op.Parameters {
		if p == nil || p.In != "path" || strings.TrimSpace(p.Description) == "" {
			continue
		}
		if out.ParamDescriptions == nil {
			out.ParamDescriptions = map[string]string{}
		}
		out.ParamDescriptions[p.Name] = p.Description
	}
	return out
}

// ExistingSpecResult is ReconcileExistingDocument's outcome. Diagnostics is
// always safe to append to a report's existing Diagnostics slice. Reconciled
// is nil exactly when analysis.existingOpenAPIDocument was empty (feature
// off) — every other outcome, including "file not found" and "failed to
// parse," still returns a non-nil Reconciled with an empty orphan list, per
// ADR 0013's "degrades gracefully... does not corrupt or block the rest of
// the report."
type ExistingSpecResult struct {
	Diagnostics []model.Diagnostic
	Reconciled  *report.ExistingDocumentReconciliation
}

// ReconcileExistingDocument implements
// docs/adr/0013-existing-openapi-document-reconciliation.md end to end: load
// the reviewer-named document, match its operations against routes by
// normalized (method, path), attach best-effort prose/schema evidence to
// model.Route.ExistingDocument on every matched route, and collect every
// unmatched document operation as an orphan rather than ever synthesizing it
// into routes. routes is mutated in place (its elements, never its length or
// order) so callers that already aliased the slice into a report (as
// cmd/gin-recon does) see the attached evidence without reassignment.
//
// src is the resolved --src root; docPath is
// analysis.existingOpenAPIDocument's configured value, relative to src
// unless already absolute. An empty docPath returns nil, nil — the
// overwhelmingly common "feature not configured" case, indistinguishable
// from every scan that predates this feature.
func ReconcileExistingDocument(routes []model.Route, src, docPath string) *ExistingSpecResult {
	if strings.TrimSpace(docPath) == "" {
		return nil
	}

	resolved := docPath
	if !filepath.IsAbs(resolved) {
		resolved = filepath.Join(src, docPath)
	}

	// Reconciled stays nil for both failure outcomes below — ADR 0013's "scan
	// proceeds exactly as it would with no config entry" means the report's
	// existingDocumentReconciliation section itself is absent, not present
	// with an empty orphan list, so a not-found/invalid document is genuinely
	// indistinguishable in report shape from analysis.existingOpenAPIDocument
	// never having been set at all, apart from the one diagnostic.
	doc, notFound, err := loadExistingDocument(resolved)
	if err != nil {
		if notFound {
			return &ExistingSpecResult{Diagnostics: []model.Diagnostic{notFoundDiagnostic(docPath, err)}}
		}
		return &ExistingSpecResult{Diagnostics: []model.Diagnostic{invalidDiagnostic(docPath, err)}}
	}

	return reconcileWithModel(routes, docPath, doc)
}

// ExistingDocumentCandidates is the fixed, ordered list of conventional
// paths (relative to --src) docs/adr/0014-auto-detect-existing-openapi-document.md
// checks for auto-detection when analysis.existingOpenAPIDocument is not
// explicitly configured. Order matters: ResolveAndReconcileExistingDocument
// uses the first candidate that both exists and parses into a document with
// at least one path item. This list is deliberately fixed and exhaustive —
// never a glob or recursive search — per that ADR's rejection of broad
// discovery, and deliberately excludes anything under ".gin-recon/" (gin-
// recon's own output) and any "*.base.*" filename (swaggo's partial-
// template convention) by simply never listing them.
var ExistingDocumentCandidates = []string{
	"openapi.yaml", "openapi.yml", "openapi.json",
	"swagger.yaml", "swagger.yml", "swagger.json",
	"docs/openapi.yaml", "docs/openapi.yml", "docs/openapi.json",
	"docs/swagger.yaml", "docs/swagger.yml", "docs/swagger.json",
	"openapi/openapi.yaml", "openapi/openapi.yml",
	"api/openapi.yaml", "api/openapi.json",
}

// ResolveAndReconcileExistingDocument implements docs/adr/0014-auto-detect-existing-openapi-document.md's
// three-way precedence — explicit config wins outright, then the first
// matching auto-detected candidate, then the feature is off — and then runs
// ADR 0013's reconciliation using whichever path won. explicitDocPath is
// analysis.existingOpenAPIDocument's configured value (possibly empty);
// autoDetectDisabled is analysis.disableExistingOpenAPIAutoDetect. An
// explicit value short-circuits auto-detection entirely, matching ADR 0014's
// "auto-detection never runs when it's set" decision, and is delegated to
// ReconcileExistingDocument unchanged so its behavior (including "not
// found"/"invalid" diagnostics naming the explicit path) is identical to
// ADR 0013's original, pre-0014 behavior. Auto-detection reuses the same
// loadExistingDocument parse already performed while probing each
// candidate, so the winning candidate is never parsed twice.
func ResolveAndReconcileExistingDocument(routes []model.Route, src, explicitDocPath string, autoDetectDisabled bool) *ExistingSpecResult {
	if strings.TrimSpace(explicitDocPath) != "" {
		return ReconcileExistingDocument(routes, src, explicitDocPath)
	}
	if autoDetectDisabled {
		return nil
	}
	for _, candidate := range ExistingDocumentCandidates {
		resolved := filepath.Join(src, candidate)
		doc, _, err := loadExistingDocument(resolved)
		if err != nil || !doc.hasAnyPathItem() {
			continue
		}
		return reconcileWithModel(routes, candidate, doc)
	}
	return nil
}

// existingDocumentModel is the built model for a document resolved from
// either an explicit path or an auto-detection candidate, kept together with
// its build result so a winning candidate found while probing never needs to
// be re-read or re-parsed to actually reconcile it. Exactly one of v3/v2 is
// ever non-nil — loadExistingDocument tries BuildV3Model() first (unchanged
// behavior for the overwhelmingly common OpenAPI 3.x case) and falls back to
// BuildV2Model() only when that fails, so a document is never built both
// ways.
type existingDocumentModel struct {
	v3 *libopenapi.DocumentModel[v3.Document]
	v2 *libopenapi.DocumentModel[v2.Swagger]
}

// hasAnyPathItem reports whether m's document defines at least one non-nil
// path item — ADR 0014's bar for a candidate to "win" auto-detection, so an
// empty or template document (e.g. swaggo's ".base." convention, though
// those never appear in ExistingDocumentCandidates at all) is never selected
// merely for existing and parsing successfully.
func (m *existingDocumentModel) hasAnyPathItem() bool {
	if m == nil {
		return false
	}
	if m.v3 != nil && m.v3.Model.Paths != nil && m.v3.Model.Paths.PathItems != nil {
		for _, item := range m.v3.Model.Paths.PathItems.FromOldest() {
			if item != nil {
				return true
			}
		}
	}
	if m.v2 != nil && m.v2.Model.Paths != nil && m.v2.Model.Paths.PathItems != nil {
		for _, item := range m.v2.Model.Paths.PathItems.FromOldest() {
			if item != nil {
				return true
			}
		}
	}
	return false
}

// existingDocOp is one matched (method, path) operation found while walking
// m's document, already normalized to docOperation regardless of whether m
// holds a v3 or v2 model.
type existingDocOp struct {
	Method string
	Path   string
	Op     docOperation
}

// operations walks m's document — whichever format it was built as — and
// returns every (method, path, operation) triple it defines, normalized via
// docOperationFromV3/docOperationFromV2. This is the one place format
// divergence is resolved; reconcileWithModel below is otherwise identical
// regardless of which format produced the list.
func (m *existingDocumentModel) operations() []existingDocOp {
	var out []existingDocOp
	if m == nil {
		return out
	}
	if m.v3 != nil && m.v3.Model.Paths != nil && m.v3.Model.Paths.PathItems != nil {
		for path, item := range m.v3.Model.Paths.PathItems.FromOldest() {
			if item == nil {
				continue
			}
			for _, spec := range existingSpecMethods {
				op := spec.get(item)
				if op == nil {
					continue
				}
				out = append(out, existingDocOp{Method: spec.name, Path: path, Op: docOperationFromV3(op)})
			}
		}
	}
	if m.v2 != nil && m.v2.Model.Paths != nil && m.v2.Model.Paths.PathItems != nil {
		for path, item := range m.v2.Model.Paths.PathItems.FromOldest() {
			if item == nil {
				continue
			}
			for _, spec := range existingSpecMethodsV2 {
				op := spec.get(item)
				if op == nil {
					continue
				}
				out = append(out, existingDocOp{Method: spec.name, Path: path, Op: docOperationFromV2(op)})
			}
		}
	}
	return out
}

// loadExistingDocument reads and parses resolved (an already-src-joined or
// absolute path) as either an OpenAPI 3.x or a Swagger 2.0 document. It is
// the one place this package calls libopenapi.NewDocumentWithConfiguration,
// so both an explicitly-configured document and every auto-detection
// candidate (docs/adr/0014) get the identical parse configuration. notFound
// is true only when the file itself could not be read (distinguishing
// ADR 0013's "not found" vs. "invalid" diagnostics); a non-nil err with
// notFound false means the file existed but failed to build as either
// format.
//
// BuildV3Model() is tried first and, if it succeeds, used exclusively — this
// preserves ADR 0013's original behavior for the overwhelmingly common
// OpenAPI 3.x case byte-for-byte. BuildV2Model() is only attempted when
// BuildV3Model() fails, so a genuinely Swagger 2.0 document (top-level
// "swagger: 2.0" rather than "openapi: 3.x") is still recognized instead of
// being folded into the "invalid" diagnostic outcome that this analyzer
// produced for such documents before v2 support existed.
func loadExistingDocument(resolved string) (doc *existingDocumentModel, notFound bool, err error) {
	data, readErr := os.ReadFile(resolved)
	if readErr != nil {
		return nil, true, readErr
	}

	// BasePath must be the document's own directory, not the process's
	// working directory (libopenapi's default when no configuration is
	// given): a real multi-file spec's relative $refs (e.g.
	// "schemas/foo.yaml") are siblings of the root document, and without an
	// explicit BasePath the rolodex silently resolves them against whatever
	// directory gin-recon happened to be invoked from instead, failing to
	// open files that genuinely exist right next to the document. Scoping
	// BasePath to the document's own directory (rather than --src's root)
	// also bounds AllowFileReferences' recursive indexing to files actually
	// reachable from the spec, not every YAML/JSON file in the whole repo.
	parsed, parseErr := libopenapi.NewDocumentWithConfiguration(data, &datamodel.DocumentConfiguration{
		BasePath:            filepath.Dir(resolved),
		SpecFilePath:        filepath.Base(resolved),
		AllowFileReferences: true,
	})
	if parseErr != nil {
		return nil, false, parseErr
	}
	builtV3, v3Err := parsed.BuildV3Model()
	// A non-nil error here is treated as an outright parse failure even when
	// libopenapi still returned a partial model (e.g. for a non-fatal
	// circular reference) — ADR 0013 defines exactly two document outcomes,
	// "parses successfully" or "fails to parse," and a document this analyzer
	// cannot fully trust is safer folded into the latter than reconciled
	// partially with no way to say which parts are suspect. The same rule
	// applies below to the BuildV2Model() fallback.
	if v3Err == nil && builtV3 != nil {
		return &existingDocumentModel{v3: builtV3}, false, nil
	}

	// BuildV3Model() rejects a genuinely Swagger 2.0 document outright (it
	// "will throw an error for any other types," per libopenapi's own doc
	// comment on the method), so falling back here is exactly the "not
	// OpenAPI 3.x" case, not a redundant second attempt at the same parse.
	builtV2, v2Err := parsed.BuildV2Model()
	if v2Err == nil && builtV2 != nil {
		return &existingDocumentModel{v2: builtV2}, false, nil
	}

	buildErr := v3Err
	if buildErr == nil {
		buildErr = fmt.Errorf("document produced no usable OpenAPI 3.x model")
	}
	return nil, false, buildErr
}

// reconcileWithModel is ReconcileExistingDocument's matching/merge body,
// factored out so ResolveAndReconcileExistingDocument's auto-detection path
// can reuse an already-parsed candidate instead of parsing the winning file
// a second time through ReconcileExistingDocument. docPath is the path as
// configured or auto-detected (used only for diagnostic/orphan messages);
// doc is the already-built model for that same path.
func reconcileWithModel(routes []model.Route, docPath string, doc *existingDocumentModel) *ExistingSpecResult {
	byKey := map[string][]int{}
	for i := range routes {
		key := matchKey(routes[i].Method, routes[i].GinPath)
		byKey[key] = append(byKey[key], i)
	}

	var diagnostics []model.Diagnostic
	var orphans []report.OrphanedOperation
	matched := map[string]bool{}

	for _, docOp := range doc.operations() {
		key := matchKey(docOp.Method, docOp.Path)
		indexes, ok := byKey[key]
		if !ok {
			orphans = append(orphans, report.OrphanedOperation{
				Method:  docOp.Method,
				Path:    normalizeDocPath(docOp.Path),
				Summary: docOp.Op.Summary,
			})
			continue
		}
		matched[key] = true
		for _, idx := range indexes {
			if diag := attachExistingDoc(&routes[idx], docOp.Path, docOp.Op); diag != nil {
				diagnostics = append(diagnostics, *diag)
			}
		}
	}

	sort.SliceStable(orphans, func(i, j int) bool {
		if orphans[i].Method != orphans[j].Method {
			return orphans[i].Method < orphans[j].Method
		}
		return orphans[i].Path < orphans[j].Path
	})
	for _, orphan := range orphans {
		diagnostics = append(diagnostics, model.Diagnostic{
			Code:     "openapi-spec-orphan-operation",
			Severity: model.DiagnosticInfo,
			Message:  fmt.Sprintf("%s %s is documented in %s but was not discovered in code; often normal (e.g. a deliberately undocumented route), not necessarily a defect", orphan.Method, orphan.Path, docPath),
		})
	}
	sort.SliceStable(diagnostics, func(i, j int) bool {
		if diagnostics[i].Code != diagnostics[j].Code {
			return diagnostics[i].Code < diagnostics[j].Code
		}
		return diagnostics[i].Message < diagnostics[j].Message
	})

	if orphans == nil {
		orphans = []report.OrphanedOperation{}
	}
	return &ExistingSpecResult{
		Diagnostics: diagnostics,
		Reconciled:  &report.ExistingDocumentReconciliation{OrphanedOperations: orphans},
	}
}

// attachExistingDoc merges one matched document operation's evidence onto
// route, per ADR 0013's merge rule: prose (summary/description/tags/
// deprecated) is always attached when present — like swag annotations
// (docs/adr/0012-swag-annotation-evidence.md), there is no analyzer-derived
// prose for these fields to conflict with, so there is nothing to arbitrate.
// Parameter-level content is gated by the structural-compatibility check:
// only when the document's own path parameter names agree, in order, with
// route's own discovered Gin path parameter names is a parameter description
// attached; a disagreement returns an openapi-spec-conflict diagnostic and
// leaves route.ExistingDocument.ParamConflict set so
// internal/format/openapi.go's applyExistingDocEvidence marks the operation
// unrefined for "parameters" — reusing the existing x-gin-recon.unrefined
// mechanism rather than inventing a parallel one — instead of applying any
// parameter content from the document. op is already normalized to
// docOperation (see docOperationFromV3/docOperationFromV2), so this function
// itself has no notion of which document format op came from.
func attachExistingDoc(route *model.Route, docPath string, op docOperation) *model.Diagnostic {
	info := &model.ExistingDocumentInfo{
		Summary:     op.Summary,
		Description: op.Description,
		Tags:        op.Tags,
		Deprecated:  op.Deprecated,
	}

	routeParams := paramNames(route.GinPath)
	docParams := paramNames(docPath)
	var diag *model.Diagnostic
	if paramNamesAgree(routeParams, docParams) {
		if len(op.ParamDescriptions) > 0 {
			info.ParamDescriptions = op.ParamDescriptions
		}
	} else if len(routeParams) > 0 || len(docParams) > 0 {
		info.ParamConflict = true
		diag = &model.Diagnostic{
			Code:     "openapi-spec-conflict",
			Severity: model.DiagnosticWarning,
			Message: fmt.Sprintf(
				"%s %s: existing document's path parameters %v disagree with the discovered route's %v; analyzer evidence remains authoritative and the operation is marked unrefined for parameters per ADR 0007/0013",
				route.Method, route.GinPath, docParams, routeParams,
			),
			Source: route.Source,
			Route:  routeIdentity(route),
		}
	}

	route.ExistingDocument = info
	return diag
}

// routeIdentity returns the "METHOD path" identity string used elsewhere in
// diagnostics/findings for Diagnostic.Route (see internal/analyzer/gin's
// equivalent usages), or nil if route has no path at all (should not
// happen for a discovered route, but defensive rather than panicking).
func routeIdentity(route *model.Route) *string {
	if route == nil {
		return nil
	}
	id := route.Method + " " + route.GinPath
	return &id
}

// normalizeDocPath trims a document path to a leading-slash, no-trailing-
// slash canonical display form for OrphanedOperation.Path, independent of
// whatever incidental slash style the document itself used.
func normalizeDocPath(path string) string {
	segments := pathSegments(path)
	if len(segments) == 0 {
		return "/"
	}
	return "/" + strings.Join(segments, "/")
}

func notFoundDiagnostic(docPath string, err error) model.Diagnostic {
	return model.Diagnostic{
		Code:     "openapi-spec-not-found",
		Severity: model.DiagnosticWarning,
		Message:  fmt.Sprintf("analysis.existingOpenAPIDocument %q could not be read: %v; reconciliation skipped, scan proceeds as if unconfigured", docPath, err),
	}
}

func invalidDiagnostic(docPath string, err error) model.Diagnostic {
	return model.Diagnostic{
		Code:     "openapi-spec-invalid",
		Severity: model.DiagnosticWarning,
		Message:  fmt.Sprintf("analysis.existingOpenAPIDocument %q could not be parsed as an OpenAPI 3.x document: %v; reconciliation skipped, scan proceeds as if unconfigured", docPath, err),
	}
}
