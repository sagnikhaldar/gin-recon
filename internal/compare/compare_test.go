package compare

import (
	"testing"

	"github.com/sagnikhaldar/gin-recon/internal/model"
	"github.com/sagnikhaldar/gin-recon/internal/report"
)

func baseReport() *report.Report {
	return &report.Report{
		SchemaVersion:   report.SchemaVersion,
		Command:         report.CommandAudit,
		AnalysisProfile: model.ProfileTyped,
		Target: report.Target{
			BuildContext: model.BuildContext{GOOS: "linux", GOARCH: "amd64"},
		},
	}
}

func routeWithAuth(method, path string, status model.AuthStatus) model.Route {
	return model.Route{
		Method:         method,
		NormalizedPath: path,
		Auth:           &model.AuthClassification{AuthStatus: status, Confidence: model.ConfidenceHigh},
	}
}

func TestCompatibleAcceptsMatchingReports(t *testing.T) {
	a, b := baseReport(), baseReport()
	if err := Compatible(a, b); err != nil {
		t.Errorf("Compatible() = %v, want nil", err)
	}
}

func TestCompatibleRejectsMismatchedSchemaMajor(t *testing.T) {
	a, b := baseReport(), baseReport()
	a.SchemaVersion = "2.0"
	if err := Compatible(a, b); err == nil {
		t.Error("Compatible() = nil, want error for mismatched schema major")
	}
}

func TestCompatibleRejectsInventoryReports(t *testing.T) {
	a, b := baseReport(), baseReport()
	a.Command = report.CommandInventory
	if err := Compatible(a, b); err == nil {
		t.Error("Compatible() = nil, want error when baseline is an inventory report")
	}
}

func TestCompatibleRejectsMismatchedAnalysisProfile(t *testing.T) {
	a, b := baseReport(), baseReport()
	a.AnalysisProfile = model.ProfileSyntaxOnly
	if err := Compatible(a, b); err == nil {
		t.Error("Compatible() = nil, want error for mismatched analysis profile")
	}
}

func TestCompatibleRejectsMismatchedBuildContext(t *testing.T) {
	a, b := baseReport(), baseReport()
	a.Target.BuildContext.GOOS = "windows"
	if err := Compatible(a, b); err == nil {
		t.Error("Compatible() = nil, want error for mismatched build context")
	}
}

func TestCompareDetectsAddedAndRemovedRoutes(t *testing.T) {
	baseline := baseReport()
	baseline.Routes = []model.Route{routeWithAuth("GET", "/old", model.AuthPublic)}
	current := baseReport()
	current.Routes = []model.Route{routeWithAuth("GET", "/new", model.AuthPublic)}

	delta := Compare(baseline, current)
	if len(delta.AddedRoutes) != 1 || delta.AddedRoutes[0] != "GET /new" {
		t.Errorf("AddedRoutes = %v, want [\"GET /new\"]", delta.AddedRoutes)
	}
	if len(delta.RemovedRoutes) != 1 || delta.RemovedRoutes[0] != "GET /old" {
		t.Errorf("RemovedRoutes = %v, want [\"GET /old\"]", delta.RemovedRoutes)
	}
}

// TestCompareRiskOrderingMatchesExpressRecon locks in the AUTH_RISK ordering
// ported from express-recon's compare.js: proven (0) is least risky, unknown
// (1) is in between, public (2) is most risky. A regression is risk
// increasing; an improvement is risk decreasing.
func TestCompareRiskOrderingMatchesExpressRecon(t *testing.T) {
	cases := []struct {
		name           string
		from, to       model.AuthStatus
		wantRegression bool
	}{
		{"proven to public is a regression", model.AuthProven, model.AuthPublic, true},
		{"proven to unknown is a regression", model.AuthProven, model.AuthUnknown, true},
		{"unknown to public is a regression", model.AuthUnknown, model.AuthPublic, true},
		{"public to proven is an improvement", model.AuthPublic, model.AuthProven, false},
		{"public to unknown is an improvement", model.AuthPublic, model.AuthUnknown, false},
		{"unknown to proven is an improvement", model.AuthUnknown, model.AuthProven, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			baseline := baseReport()
			baseline.Routes = []model.Route{routeWithAuth("GET", "/r", tc.from)}
			current := baseReport()
			current.Routes = []model.Route{routeWithAuth("GET", "/r", tc.to)}

			delta := Compare(baseline, current)
			if tc.wantRegression {
				if len(delta.AuthRegressions) != 1 {
					t.Fatalf("AuthRegressions = %v, want exactly 1", delta.AuthRegressions)
				}
				if len(delta.AuthImprovements) != 0 {
					t.Errorf("AuthImprovements = %v, want none", delta.AuthImprovements)
				}
				if delta.AuthRegressions[0].From != tc.from || delta.AuthRegressions[0].To != tc.to {
					t.Errorf("AuthRegressions[0] = %+v, want from=%s to=%s", delta.AuthRegressions[0], tc.from, tc.to)
				}
			} else {
				if len(delta.AuthImprovements) != 1 {
					t.Fatalf("AuthImprovements = %v, want exactly 1", delta.AuthImprovements)
				}
				if len(delta.AuthRegressions) != 0 {
					t.Errorf("AuthRegressions = %v, want none", delta.AuthRegressions)
				}
			}
		})
	}
}

func TestCompareIgnoresUnchangedAuthStatus(t *testing.T) {
	baseline := baseReport()
	baseline.Routes = []model.Route{routeWithAuth("GET", "/r", model.AuthProven)}
	current := baseReport()
	current.Routes = []model.Route{routeWithAuth("GET", "/r", model.AuthProven)}

	delta := Compare(baseline, current)
	if len(delta.AuthRegressions) != 0 || len(delta.AuthImprovements) != 0 {
		t.Errorf("expected no auth changes for an unchanged route, got regressions=%v improvements=%v", delta.AuthRegressions, delta.AuthImprovements)
	}
}

// TestCompareCollapsesDuplicateRouteKeysToLeastSafeView mirrors
// express-recon's routeMap exactly: gin-recon itself can legitimately
// register the same method+path twice (e.g. las-be-lms's Hero/SIB mount
// collision), and a baseline/current diff must never let a safer duplicate
// registration mask a riskier one at the same key.
func TestCompareCollapsesDuplicateRouteKeysToLeastSafeView(t *testing.T) {
	baseline := baseReport()
	baseline.Routes = []model.Route{routeWithAuth("GET", "/dup", model.AuthProven)}
	current := baseReport()
	current.Routes = []model.Route{
		routeWithAuth("GET", "/dup", model.AuthProven),
		routeWithAuth("GET", "/dup", model.AuthPublic), // riskier duplicate registration
	}

	delta := Compare(baseline, current)
	if len(delta.AuthRegressions) != 1 {
		t.Fatalf("AuthRegressions = %v, want 1 — the riskier duplicate registration must win the collapse", delta.AuthRegressions)
	}
	if delta.AuthRegressions[0].To != model.AuthPublic {
		t.Errorf("AuthRegressions[0].To = %q, want public (the least-safe view)", delta.AuthRegressions[0].To)
	}
}

func TestCompareDetectsNewAndResolvedFindings(t *testing.T) {
	baseline := baseReport()
	baseline.Findings = []report.Finding{{Fingerprint: "fp-old"}}
	current := baseReport()
	current.Findings = []report.Finding{{Fingerprint: "fp-new"}}

	delta := Compare(baseline, current)
	if len(delta.NewFindings) != 1 || delta.NewFindings[0] != "fp-new" {
		t.Errorf("NewFindings = %v, want [\"fp-new\"]", delta.NewFindings)
	}
	if len(delta.ResolvedFindings) != 1 || delta.ResolvedFindings[0] != "fp-old" {
		t.Errorf("ResolvedFindings = %v, want [\"fp-old\"]", delta.ResolvedFindings)
	}
}

func routeWithEvidence(path string, status model.AuthStatus, tags, roles, scopes []string, middlewareNames ...string) model.Route {
	mw := make([]model.Middleware, len(middlewareNames))
	for i, name := range middlewareNames {
		mw[i] = model.Middleware{DisplayName: name}
	}
	return model.Route{
		Method:         "GET",
		NormalizedPath: path,
		Middleware:     mw,
		Auth: &model.AuthClassification{
			AuthStatus: status,
			Confidence: model.ConfidenceHigh,
			Tags:       tags,
			Roles:      roles,
			Scopes:     scopes,
		},
	}
}

func regressionExplanation(t *testing.T, before, after model.Route) string {
	t.Helper()
	baseline := baseReport()
	baseline.Routes = []model.Route{before}
	current := baseReport()
	current.Routes = []model.Route{after}
	delta := Compare(baseline, current)
	if len(delta.AuthRegressions) != 1 {
		t.Fatalf("expected exactly 1 regression, got %v", delta.AuthRegressions)
	}
	return delta.AuthRegressions[0].Explanation
}

func TestExplainAuthChangePrioritizesRemovedTags(t *testing.T) {
	before := routeWithEvidence("/r", model.AuthProven, []string{"internal-only"}, nil, nil, "RequireAuth")
	after := routeWithEvidence("/r", model.AuthPublic, nil, nil, nil)
	got := regressionExplanation(t, before, after)
	if got != "Recognized auth tag(s) removed: internal-only." {
		t.Errorf("Explanation = %q", got)
	}
}

func TestExplainAuthChangeDetectsRemovedGrants(t *testing.T) {
	before := routeWithEvidence("/r", model.AuthProven, nil, []string{"admin"}, nil, "RequireAuth")
	after := routeWithEvidence("/r", model.AuthPublic, nil, nil, nil)
	got := regressionExplanation(t, before, after)
	if got != "Authorization grant(s) removed: admin." {
		t.Errorf("Explanation = %q", got)
	}
}

func TestExplainAuthChangeDetectsRemovedMiddleware(t *testing.T) {
	before := routeWithEvidence("/r", model.AuthProven, nil, nil, nil, "RequireAuth")
	after := routeWithEvidence("/r", model.AuthPublic, nil, nil, nil)
	got := regressionExplanation(t, before, after)
	if got != "Middleware removed from the route chain: RequireAuth." {
		t.Errorf("Explanation = %q", got)
	}
}

func TestExplainAuthChangeDetectsNewlyUnknown(t *testing.T) {
	before := routeWithEvidence("/r", model.AuthProven, nil, nil, nil, "RequireAuth")
	after := routeWithEvidence("/r", model.AuthUnknown, nil, nil, nil, "RequireAuth")
	got := regressionExplanation(t, before, after)
	if got != "The route is now guarded only by middleware whose enforcement could not be confirmed." {
		t.Errorf("Explanation = %q", got)
	}
}

func TestExplainAuthChangeDetectsMiddlewareOrderChange(t *testing.T) {
	before := routeWithEvidence("/r", model.AuthProven, nil, nil, nil, "A", "B")
	after := routeWithEvidence("/r", model.AuthPublic, nil, nil, nil, "B", "A")
	got := regressionExplanation(t, before, after)
	if got != "The middleware chain order changed alongside the authentication classification." {
		t.Errorf("Explanation = %q", got)
	}
}

// TestExplainAuthChangeFallsBackToGenericExplanation exercises the case
// where none of the structural checks apply: no evidence differences and
// the "before" status was already unknown, so the "newly unknown" branch
// cannot fire either.
func TestExplainAuthChangeFallsBackToGenericExplanation(t *testing.T) {
	before := routeWithEvidence("/r", model.AuthUnknown, nil, nil, nil)
	after := routeWithEvidence("/r", model.AuthPublic, nil, nil, nil)
	got := regressionExplanation(t, before, after)
	if got != "Authentication classification changed without a visible route-level middleware difference; check authMiddleware configuration or shared mount wiring." {
		t.Errorf("Explanation = %q", got)
	}
}

func TestCompareIsDeterministicallySorted(t *testing.T) {
	baseline := baseReport()
	baseline.Routes = []model.Route{
		routeWithAuth("GET", "/b", model.AuthProven),
		routeWithAuth("GET", "/a", model.AuthProven),
	}
	current := baseReport()
	current.Routes = []model.Route{
		routeWithAuth("GET", "/b", model.AuthPublic),
		routeWithAuth("GET", "/a", model.AuthPublic),
	}

	delta := Compare(baseline, current)
	if len(delta.AuthRegressions) != 2 {
		t.Fatalf("expected 2 regressions, got %v", delta.AuthRegressions)
	}
	if delta.AuthRegressions[0].Path != "/a" || delta.AuthRegressions[1].Path != "/b" {
		t.Errorf("AuthRegressions not sorted by path: %v", delta.AuthRegressions)
	}
}
