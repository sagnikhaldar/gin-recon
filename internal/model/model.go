// Package model defines the normalized route registry types shared by every
// report. Field names and enums mirror schema/report-1.0.json exactly; the
// schema is the normative contract (see docs/report-contract.md), this
// package is its Go representation.
//
// Several types below implement MarshalJSON solely to default a nil slice
// field to an empty one before encoding. schema/report-1.0.json declares
// these fields "type": "array" with no null alternative, but a nil Go slice
// with a plain struct tag (even without omitempty) still encodes as JSON
// null, not []. Left unguarded, any future construction path that forgets to
// initialize one of these slices would silently emit a report that violates
// its own schema. Normalizing at MarshalJSON time makes that failure mode
// structurally impossible rather than a matter of every call site
// remembering.
package model

import "encoding/json"

// AnalysisProfile is the trust boundary a report's evidence was gathered
// under. See docs/threat-model.md#trust-profiles.
type AnalysisProfile string

const (
	ProfileSyntaxOnly AnalysisProfile = "syntax-only"
	ProfileTyped      AnalysisProfile = "typed"
)

// WorkspaceMode and ModuleMode mirror the CLI's --workspace and --module-mode
// options (docs/cli-contract.md).
type WorkspaceMode string

const (
	WorkspaceOff       WorkspaceMode = "off"
	WorkspaceWorkspace WorkspaceMode = "workspace"
)

type ModuleMode string

const (
	ModuleReadonly ModuleMode = "readonly"
	ModuleVendor   ModuleMode = "vendor"
)

// BuildContext identifies the single GOOS/GOARCH/tag/workspace/module
// combination a report was produced under. One report represents exactly one
// build context (docs/cli-contract.md).
type BuildContext struct {
	GOOS          string          `json:"goos"`
	GOARCH        string          `json:"goarch"`
	Tags          []string        `json:"tags"`
	WorkspaceMode WorkspaceMode   `json:"workspaceMode"`
	ModuleMode    ModuleMode      `json:"moduleMode"`
	Profile       AnalysisProfile `json:"profile"`
}

// MarshalJSON defaults a nil Tags to []; see the package doc comment.
func (b BuildContext) MarshalJSON() ([]byte, error) {
	type alias BuildContext
	a := alias(b)
	if a.Tags == nil {
		a.Tags = []string{}
	}
	return json.Marshal(a)
}

// Source is a file/line location, or nil when the analyzer could not
// establish one. Absolute checkout paths are never stored — File is always
// root-relative and slash-separated (docs/cli-contract.md).
type Source struct {
	File string `json:"file"`
	Line *int   `json:"line"`
}

// CallableKind classifies how a middleware/handler reference was written in
// source, independent of whether it resolved to a canonical symbol.
type CallableKind string

const (
	CallableIdentifier CallableKind = "identifier"
	CallableCall       CallableKind = "call"
	CallableAnonymous  CallableKind = "anonymous"
	CallableUnknown    CallableKind = "unknown"
)

// RegistrationScope records where in the Gin registration hierarchy a
// middleware entry was attached.
type RegistrationScope string

const (
	ScopeGlobal RegistrationScope = "global"
	ScopeGroup  RegistrationScope = "group"
	ScopeRoute  RegistrationScope = "route"
)

// ResolutionStatus records whether a middleware/handler reference resolved to
// a canonical package symbol.
type ResolutionStatus string

const (
	Resolved   ResolutionStatus = "resolved"
	Unresolved ResolutionStatus = "unresolved"
)

// Middleware is one entry in a route's or engine's middleware chain. Raw
// argument values and arbitrary source text are deliberately excluded —
// see docs/threat-model.md#data-handling.
type Middleware struct {
	DisplayName       string            `json:"displayName"`
	CanonicalSymbol   *string           `json:"canonicalSymbol"`
	CallableKind      CallableKind      `json:"callableKind"`
	Source            *Source           `json:"source"`
	RegistrationScope RegistrationScope `json:"registrationScope"`
	OrderingIndex     int               `json:"orderingIndex"`
	ResolutionStatus  ResolutionStatus  `json:"resolutionStatus"`

	// WrappedSymbols is a bounded chain of canonical symbols found by
	// peeling into this middleware call's own arguments — e.g. for
	// "LoggedAuth(RequireAuth)", CanonicalSymbol is LoggedAuth's and
	// WrappedSymbols is ["RequireAuth"]. It is only ever a symbol
	// internal/analyzer/gin already resolves independently, never a
	// literal value or arbitrary expression text — docs/threat-model.md's
	// prohibition on middleware arguments in reports is about values, not
	// about the identity of a nested callable reference. Recording it here
	// does not itself assert anything about authentication: only
	// internal/classify, driven by a reviewer-configured authWrappers
	// entry, ever treats a wrapped symbol as evidence.
	WrappedSymbols []string `json:"wrappedSymbols,omitempty"`
}

// Confidence expresses how much the analyzer trusts a piece of derived
// evidence, independent of authentication assurance (which has its own,
// separate vocabulary — see Assurance and EnforcementAnalysis below).
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// RequestEvidence records best-effort request-shape hints mined from the
// handler AST. It is descriptive only and never used for classification.
type RequestEvidence struct {
	Body    []string `json:"body,omitempty"`
	Query   []string `json:"query,omitempty"`
	Params  []string `json:"params,omitempty"`
	Headers []string `json:"headers,omitempty"`
}

// ResponseEvidence records one observed response variant for a route.
type ResponseEvidence struct {
	Status   any     `json:"status"`
	Type     *string `json:"type,omitempty"`
	Resolved bool    `json:"resolved"`
}

// SwagInfo is best-effort evidence mined from a swaggo/swag-style
// (https://github.com/swaggo/swag) doc comment directly above a route's
// handler function declaration. Per
// docs/adr/0012-swag-annotation-evidence.md, it supplements route prose only
// — analyzer-derived route identity (method, path, handler, middleware,
// auth) always remains authoritative, matching ADR 0007's evidence
// precedence. RouterPath/RouterMethod are the annotation's own claimed
// path/method, carried here only so a consumer can see what the annotation
// said; they are never used to set a route's actual GinPath/Method, and a
// disagreement produces a "swag-router-mismatch" diagnostic rather than
// altering the route. Nil when the handler's doc comment contains no
// recognized swag directive at all — the overwhelmingly common case.
type SwagInfo struct {
	Summary      string   `json:"summary,omitempty"`
	Description  string   `json:"description,omitempty"`
	Tags         []string `json:"tags,omitempty"`
	Deprecated   bool     `json:"deprecated,omitempty"`
	RouterPath   string   `json:"routerPath,omitempty"`
	RouterMethod string   `json:"routerMethod,omitempty"`
}

// IOEvidence is optional, static/hybrid-only request/response shape evidence
// for a route. See docs/report-contract.md#route-evidence.
type IOEvidence struct {
	Request   *RequestEvidence   `json:"request,omitempty"`
	Responses []ResponseEvidence `json:"responses,omitempty"`
}

// AuthStatus is the tri-state classification result. See ADR 0005 for why
// there is no fourth state and no path from unknown to proven without
// configured evidence.
type AuthStatus string

const (
	AuthProven  AuthStatus = "proven"
	AuthPublic  AuthStatus = "public"
	AuthUnknown AuthStatus = "unknown"
)

// Assurance is the reviewer-selected trust mode for a configured
// authMiddleware entry. See docs/configuration-contract.md#canonical-symbols-and-assurance.
type Assurance string

const (
	AssuranceAnalyze  Assurance = "analyze"
	AssuranceAttested Assurance = "attested"
)

// EnforcementAnalysis is the analyzer's independent, bounded judgment of
// whether a matched middleware's control flow can terminate the Gin chain.
// The exact boundary of ConfirmedShape is fixed by
// docs/adr/0008-bounded-enforcement-shape-analysis.md and must not be widened
// without a new ADR and fixtures.
type EnforcementAnalysis string

const (
	EnforcementConfirmedShape EnforcementAnalysis = "confirmed-shape"
	EnforcementUnresolved     EnforcementAnalysis = "unresolved"
	EnforcementContradicted   EnforcementAnalysis = "contradicted"
)

// AuthClassification is a route's audit-only authentication evidence. It is
// nil for inventory reports.
type AuthClassification struct {
	AuthStatus          AuthStatus           `json:"authStatus"`
	ClassificationBasis string               `json:"classificationBasis"`
	Assurance           *Assurance           `json:"assurance,omitempty"`
	EnforcementAnalysis *EnforcementAnalysis `json:"enforcementAnalysis,omitempty"`
	MatchedEvidence     *string              `json:"matchedEvidence"`
	Confidence          Confidence           `json:"confidence"`
	Tags                []string             `json:"tags"`
	Roles               []string             `json:"roles"`
	Scopes              []string             `json:"scopes"`
	Accepted            bool                 `json:"accepted"`
}

// MarshalJSON defaults nil Tags/Roles/Scopes to []; see the package doc comment.
func (a AuthClassification) MarshalJSON() ([]byte, error) {
	type alias AuthClassification
	x := alias(a)
	if x.Tags == nil {
		x.Tags = []string{}
	}
	if x.Roles == nil {
		x.Roles = []string{}
	}
	if x.Scopes == nil {
		x.Scopes = []string{}
	}
	return json.Marshal(x)
}

// SurfaceKind distinguishes ordinary routes from static-file surfaces.
// NoRoute/NoMethod are represented separately as FallbackSurface, not as a
// SurfaceKind, so they cannot collide with normal route identity
// (docs/report-contract.md#route-evidence).
type SurfaceKind string

const (
	SurfaceRoute  SurfaceKind = "route"
	SurfaceStatic SurfaceKind = "static"
)

// RegistrationKind records which Gin API produced a route, for traceability;
// it never affects route identity.
type RegistrationKind string

const (
	RegistrationVerb   RegistrationKind = "verb"
	RegistrationHandle RegistrationKind = "handle"
	RegistrationAny    RegistrationKind = "any"
	RegistrationMatch  RegistrationKind = "match"
	RegistrationStatic RegistrationKind = "static"
)

// Route is one discovered Gin route. Canonical identity is Method plus
// NormalizedPath (docs/report-contract.md#route-evidence); Auth is present
// only in audit reports.
type Route struct {
	Method             string              `json:"method"`
	GinPath            string              `json:"ginPath"`
	NormalizedPath     string              `json:"normalizedPath"`
	SurfaceKind        SurfaceKind         `json:"surfaceKind"`
	RegistrationKind   *RegistrationKind   `json:"registrationKind,omitempty"`
	Middleware         []Middleware        `json:"middleware"`
	FinalHandler       Middleware          `json:"finalHandler"`
	Source             *Source             `json:"source"`
	PathConfidence     Confidence          `json:"pathConfidence"`
	AnalysisConfidence Confidence          `json:"analysisConfidence"`
	BuildContext       BuildContext        `json:"buildContext"`
	EvidenceOrigins    []string            `json:"evidenceOrigins"`
	IO                 *IOEvidence         `json:"io,omitempty"`
	Auth               *AuthClassification `json:"auth,omitempty"`
	Swag               *SwagInfo           `json:"swag,omitempty"`
}

// MarshalJSON defaults nil Middleware/EvidenceOrigins to []; see the package
// doc comment.
func (r Route) MarshalJSON() ([]byte, error) {
	type alias Route
	x := alias(r)
	if x.Middleware == nil {
		x.Middleware = []Middleware{}
	}
	if x.EvidenceOrigins == nil {
		x.EvidenceOrigins = []string{}
	}
	return json.Marshal(x)
}

// FallbackSurfaceKind distinguishes Gin's two fallback registrations.
type FallbackSurfaceKind string

const (
	FallbackNoRoute  FallbackSurfaceKind = "no-route"
	FallbackNoMethod FallbackSurfaceKind = "no-method"
)

// FallbackSurface represents a NoRoute/NoMethod registration, kept separate
// from Route so it cannot collide with ordinary route identity.
type FallbackSurface struct {
	Kind         FallbackSurfaceKind `json:"kind"`
	Middleware   []Middleware        `json:"middleware"`
	FinalHandler Middleware          `json:"finalHandler"`
	Source       *Source             `json:"source"`
}

// MarshalJSON defaults a nil Middleware to []; see the package doc comment.
func (f FallbackSurface) MarshalJSON() ([]byte, error) {
	type alias FallbackSurface
	x := alias(f)
	if x.Middleware == nil {
		x.Middleware = []Middleware{}
	}
	return json.Marshal(x)
}

// ScanCoverage records what the analyzer discovered, analyzed, and could not
// resolve. Complete is scoped strictly to the recorded BuildContext and never
// claims coverage of other platforms/tags (docs/report-contract.md#coverage-and-diagnostics).
type ScanCoverage struct {
	DiscoveredPackages      int             `json:"discoveredPackages"`
	AnalyzedPackages        int             `json:"analyzedPackages"`
	FailedPackages          int             `json:"failedPackages"`
	DiscoveredFiles         int             `json:"discoveredFiles"`
	AnalyzedFiles           int             `json:"analyzedFiles"`
	FailedFiles             int             `json:"failedFiles"`
	UnresolvedRegistrations int             `json:"unresolvedRegistrations"`
	ReachedLimits           []string        `json:"reachedLimits"`
	BuildContext            BuildContext    `json:"buildContext"`
	Profile                 AnalysisProfile `json:"profile"`
	Complete                bool            `json:"complete"`
}

// MarshalJSON defaults a nil ReachedLimits to []; see the package doc comment.
func (s ScanCoverage) MarshalJSON() ([]byte, error) {
	type alias ScanCoverage
	x := alias(s)
	if x.ReachedLimits == nil {
		x.ReachedLimits = []string{}
	}
	return json.Marshal(x)
}

// DiagnosticSeverity is independent of finding Severity: diagnostics describe
// analysis quality, findings describe security/policy outcomes.
type DiagnosticSeverity string

const (
	DiagnosticError   DiagnosticSeverity = "error"
	DiagnosticWarning DiagnosticSeverity = "warning"
	DiagnosticInfo    DiagnosticSeverity = "info"
)

// Diagnostic is a stable-coded, bounded note about analysis quality or
// coverage. Diagnostics must never be used to imply a security outcome — that
// is what Finding is for.
type Diagnostic struct {
	Code     string             `json:"code"`
	Severity DiagnosticSeverity `json:"severity"`
	Message  string             `json:"message"`
	Source   *Source            `json:"source,omitempty"`
	Route    *string            `json:"route,omitempty"`
	Package  *string            `json:"package,omitempty"`
}
