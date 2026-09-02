package report

import (
	"encoding/json"
	"testing"

	"github.com/sagnikhaldar/gin-recon/internal/model"
)

func testTarget() Target {
	return Target{
		Module: "example.com/demo",
		BuildContext: model.BuildContext{
			GOOS:          "linux",
			GOARCH:        "amd64",
			Tags:          []string{},
			WorkspaceMode: model.WorkspaceOff,
			ModuleMode:    model.ModuleReadonly,
			Profile:       model.ProfileTyped,
		},
	}
}

func decode(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal into map: %v", err)
	}
	return m
}

// TestInventoryReportOmitsAuditFields is the regression test for the exact
// schema hole fixed in schema/report-1.0.json: an inventory report must not
// carry summary/findings/policyEvaluation/activeExceptions at all, not even
// one of them alone.
func TestInventoryReportOmitsAuditFields(t *testing.T) {
	r := NewInventoryReport(model.ProfileTyped, testTarget())
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	m := decode(t, data)
	for _, forbidden := range []string{"summary", "findings", "policyEvaluation", "activeExceptions"} {
		if _, present := m[forbidden]; present {
			t.Errorf("inventory report must not contain %q, got: %s", forbidden, data)
		}
	}
	if m["command"] != "inventory" {
		t.Errorf("command = %v, want inventory", m["command"])
	}
}

// TestAuditReportWithNoFindingsStillEmitsEmptyArrays is the regression test
// for the nil-slice trap: encoding/json's default omitempty behavior would
// drop a genuinely-empty Findings/ActiveExceptions slice on a zero-finding
// audit (the common case), which schema/report-1.0.json forbids — both are
// required array-typed keys under command "audit".
func TestAuditReportWithNoFindingsStillEmitsEmptyArrays(t *testing.T) {
	r := NewAuditReport(
		model.ProfileTyped,
		testTarget(),
		Summary{FindingsBySeverity: map[Severity]int{}},
		nil, // no findings — the common, unremarkable case
		PolicyEvaluation{EvaluatedPolicies: []string{}},
		nil, // no active exceptions
	)
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	m := decode(t, data)

	findings, ok := m["findings"].([]any)
	if !ok {
		t.Fatalf("findings = %#v, want a JSON array (possibly empty), not null or absent", m["findings"])
	}
	if len(findings) != 0 {
		t.Errorf("findings = %v, want empty", findings)
	}

	activeExceptions, ok := m["activeExceptions"].([]any)
	if !ok {
		t.Fatalf("activeExceptions = %#v, want a JSON array (possibly empty), not null or absent", m["activeExceptions"])
	}
	if len(activeExceptions) != 0 {
		t.Errorf("activeExceptions = %v, want empty", activeExceptions)
	}

	if _, ok := m["summary"].(map[string]any); !ok {
		t.Errorf("summary = %#v, want an object", m["summary"])
	}
	if _, ok := m["policyEvaluation"].(map[string]any); !ok {
		t.Errorf("policyEvaluation = %#v, want an object", m["policyEvaluation"])
	}
}

// TestAuditReportRoundTrip proves MarshalJSON/UnmarshalJSON are inverses for
// a populated audit report, since --baseline depends on decoding a
// previously emitted report back into the same Report type.
func TestAuditReportRoundTrip(t *testing.T) {
	route := "GET /admin"
	original := NewAuditReport(
		model.ProfileTyped,
		testTarget(),
		Summary{
			TotalRoutes:            1,
			ProvenByConfirmedShape: 1,
			Public:                 0,
			Unknown:                0,
			FindingsBySeverity:     map[Severity]int{SeverityLow: 1},
		},
		[]Finding{{
			ID:          "f1",
			RuleID:      RulePublicRoute,
			Fingerprint: "abc123",
			Severity:    SeverityLow,
			Confidence:  model.ConfidenceHigh,
			Route:       &route,
			Detail:      "no auth middleware matched",
		}},
		PolicyEvaluation{EvaluatedPolicies: []string{"admin-routes-need-role"}},
		[]ExceptionRef{{ID: "exc-1", Reason: "reviewed", Expires: "2026-12-31"}},
	)

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded Report
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Command != CommandAudit {
		t.Errorf("Command = %v, want audit", decoded.Command)
	}
	if decoded.Summary == nil || decoded.Summary.TotalRoutes != 1 {
		t.Errorf("Summary = %#v, want TotalRoutes 1", decoded.Summary)
	}
	if len(decoded.Findings) != 1 || decoded.Findings[0].Fingerprint != "abc123" {
		t.Errorf("Findings = %#v, want one finding with fingerprint abc123", decoded.Findings)
	}
	if decoded.PolicyEvaluation == nil || len(decoded.PolicyEvaluation.EvaluatedPolicies) != 1 {
		t.Errorf("PolicyEvaluation = %#v, want one evaluated policy", decoded.PolicyEvaluation)
	}
	if len(decoded.ActiveExceptions) != 1 || decoded.ActiveExceptions[0].ID != "exc-1" {
		t.Errorf("ActiveExceptions = %#v, want one exception exc-1", decoded.ActiveExceptions)
	}
}

// TestOverwritingTopLevelSlicesWithNilStillMarshalsAsEmptyArrays is the
// regression test for a real bug: cmd/gin-recon's first wiring of the
// inventory command did `rep.GlobalMiddleware = result.GlobalMiddleware`
// after constructing rep with NewInventoryReport, and analyzer.Inventory's
// result slice was nil when no global middleware existed — silently
// overwriting the constructor's safe empty-slice default with nil, which
// then marshaled as JSON null and failed schema/report-1.0.json validation.
// Discovered by validating real CLI output against the actual schema file,
// not by any unit test — this test exists so it can never regress silently
// again.
func TestOverwritingTopLevelSlicesWithNilStillMarshalsAsEmptyArrays(t *testing.T) {
	r := NewInventoryReport(model.ProfileTyped, testTarget())
	// Simulate exactly what happened: assign nil slices over the
	// constructor's defaults, as any caller assembling a Report from
	// another package's (possibly-nil) result slices might do.
	r.Routes = nil
	r.GlobalMiddleware = nil
	r.FallbackSurfaces = nil
	r.Diagnostics = nil

	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	m := decode(t, data)
	for _, field := range []string{"routes", "globalMiddleware", "fallbackSurfaces", "diagnostics"} {
		arr, ok := m[field].([]any)
		if !ok {
			t.Errorf("%s = %#v, want a JSON array even when the Go field is nil", field, m[field])
			continue
		}
		if len(arr) != 0 {
			t.Errorf("%s = %v, want empty", field, arr)
		}
	}
}

// TestDeltaOmittedWithoutBaseline confirms delta only appears when a baseline
// comparison actually produced one, per docs/report-contract.md.
func TestDeltaOmittedWithoutBaseline(t *testing.T) {
	r := NewInventoryReport(model.ProfileTyped, testTarget())
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	m := decode(t, data)
	if _, present := m["delta"]; present {
		t.Errorf("delta must be absent without a baseline, got: %s", data)
	}
}

// TestDeltaRoundTripsThroughReport confirms internal/compare's output
// survives Report's Marshal/Unmarshal, the same envelope --baseline reports
// pass through in cmd/gin-recon.
func TestDeltaRoundTripsThroughReport(t *testing.T) {
	r := NewInventoryReport(model.ProfileTyped, testTarget())
	r.Delta = &Delta{
		AddedRoutes:   []string{"GET /new"},
		RemovedRoutes: []string{"GET /old"},
		AuthRegressions: []AuthChange{
			{Method: "GET", Path: "/admin", From: model.AuthProven, To: model.AuthPublic, Explanation: "middleware removed"},
		},
		NewFindings: []string{"fp-1"},
	}

	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded Report
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Delta == nil {
		t.Fatal("Delta = nil, want the round-tripped delta")
	}
	if len(decoded.Delta.AuthRegressions) != 1 || decoded.Delta.AuthRegressions[0].From != model.AuthProven {
		t.Errorf("AuthRegressions = %#v, want one regression from proven", decoded.Delta.AuthRegressions)
	}
}

// TestDeltaMarshalDefaultsNilSlicesToEmptyArrays confirms schema/report-1.0.json's
// non-nullable delta array fields (added/removed routes, auth regressions/
// improvements, new/resolved findings) never encode as null, matching the
// same discipline every other slice-bearing type in this package and
// internal/model follows.
func TestDeltaMarshalDefaultsNilSlicesToEmptyArrays(t *testing.T) {
	data, err := json.Marshal(Delta{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	m := decode(t, data)
	for _, field := range []string{"addedRoutes", "removedRoutes", "authRegressions", "authImprovements", "newFindings", "resolvedFindings"} {
		arr, ok := m[field].([]any)
		if !ok {
			t.Errorf("%s = %#v, want a JSON array even when the Go field is nil", field, m[field])
			continue
		}
		if len(arr) != 0 {
			t.Errorf("%s = %v, want empty", field, arr)
		}
	}
}
