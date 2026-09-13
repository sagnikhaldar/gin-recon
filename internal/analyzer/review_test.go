package analyzer

import (
	"strings"
	"testing"

	"github.com/sagnikhaldar/gin-recon/internal/config"
)

// candidateBy returns the bundle's own candidate matching suffix, failing
// the test if it is not found — every test below needs the bundle's real
// ID/Fingerprint values, not invented ones, since ImportReview validates
// both.
func candidateBy(t *testing.T, bundle *SuggestAuthResult, suffix string) AuthCandidate {
	t.Helper()
	for _, c := range bundle.Candidates {
		if hasSuffix(c.CanonicalSymbol, suffix) {
			return c
		}
	}
	t.Fatalf("no candidate with suffix %q in bundle: %+v", suffix, bundle.Candidates)
	return AuthCandidate{}
}

// TestDraftAssessmentIncludesOnlyNameHintAndConfirmedShapeIntersection
// guards docs/adr/0042-static-analysis-drafts-assessments.md's own boundary,
// empirically validated across 39 real repositories: only the intersection
// of NameHint and confirmed-shape is auto-drafted. RequireAuthDirect/
// RequireAuthFactory (both name-hinted and confirmed-shape) must be
// included; a confirmed-shape candidate with no name hint, and a
// name-hinted candidate that is not confirmed-shape, must both be excluded
// — the exact false-positive shapes (a validator, a provably-inert guard)
// this boundary exists to keep out of an auto-generated assessment.
func TestDraftAssessmentIncludesOnlyNameHintAndConfirmedShapeIntersection(t *testing.T) {
	bundle := loadAndSuggestAuth(t, "enforcement-shapes")
	assessment := DraftAssessment(bundle)

	if assessment.BundleFingerprint != bundle.BundleFingerprint {
		t.Errorf("BundleFingerprint = %q, want %q", assessment.BundleFingerprint, bundle.BundleFingerprint)
	}

	byID := make(map[string]AuthCandidate, len(bundle.Candidates))
	for _, c := range bundle.Candidates {
		byID[c.ID] = c
	}
	drafted := make(map[string]bool, len(assessment.Decisions))
	for _, d := range assessment.Decisions {
		if !d.IsAuthGuard || d.Assurance != config.AssuranceAnalyze || strings.TrimSpace(d.Rationale) == "" {
			t.Errorf("decision for %q = %+v, want isAuthGuard:true assurance:analyze non-empty rationale", d.CandidateID, d)
		}
		drafted[byID[d.CandidateID].CanonicalSymbol] = true
	}

	for _, want := range []string{".RequireAuthDirect", ".RequireAuthFactory"} {
		c := candidateFor(bundle, want)
		if c == nil {
			t.Fatalf("candidate %s not found", want)
		}
		if !drafted[c.CanonicalSymbol] {
			t.Errorf("%s (nameHint=%v, shape=%q) should be drafted", want, c.NameHint, c.EnforcementShape)
		}
	}
	// RequireAuthAlwaysPasses is name-hinted but contradicted (provably
	// never aborts) — must never be drafted despite the name.
	for _, avoid := range []string{".RequireAuthAlwaysPasses", ".RequireAuthCrossPackage"} {
		c := candidateFor(bundle, avoid)
		if c == nil {
			t.Fatalf("candidate %s not found", avoid)
		}
		if drafted[c.CanonicalSymbol] {
			t.Errorf("%s (nameHint=%v, shape=%q) must not be drafted", avoid, c.NameHint, c.EnforcementShape)
		}
	}
}

// TestDraftAssessmentExcludesConfirmedShapeWithoutNameHint guards the other
// half of the same boundary using the real-world-mirroring mw-shape-signal
// fixture: CheckHeaderPresence is a genuine confirmed-shape guard but has no
// name hint at all (the exact shape BindAndValidate/ValidateUserFileUpload
// took in the real use-be-api false positives) — it must never be
// auto-drafted, only ever surfaced via suggest-auth's own ranking or ADR
// 0041's unconfigured-guard finding for a human/AI to actually look at.
func TestDraftAssessmentExcludesConfirmedShapeWithoutNameHint(t *testing.T) {
	bundle := loadAndSuggestAuth(t, "mw-shape-signal")
	assessment := DraftAssessment(bundle)
	if len(assessment.Decisions) != 0 {
		t.Errorf("Decisions = %+v, want none (neither candidate in this fixture is in the nameHint-and-confirmed-shape intersection)", assessment.Decisions)
	}
}

func TestImportReviewEmitsConfigSuggestionForApprovedGuardOnly(t *testing.T) {
	bundle := loadAndSuggestAuth(t, "mw-shape-signal")
	header := candidateBy(t, bundle, ".CheckHeaderPresence")
	logger := candidateBy(t, bundle, ".AuthLogger")

	assessment := &ReviewAssessment{
		SchemaVersion:     "1.0",
		BundleFingerprint: bundle.BundleFingerprint,
		Decisions: []CandidateDecision{
			{
				CandidateID:          header.ID,
				CandidateFingerprint: header.Fingerprint,
				IsAuthGuard:          true,
				Assurance:            config.AssuranceAnalyze,
				Tags:                 []string{"internal"},
				Rationale:            "Aborts with 403 when X-Internal header is absent; confirmed-shape backs this up.",
			},
			{
				CandidateID:          logger.ID,
				CandidateFingerprint: logger.Fingerprint,
				IsAuthGuard:          false,
				Rationale:            "Only sets a context value and calls Next; confirmed-shape analysis proved it never aborts.",
			},
		},
	}

	got, err := ImportReview(bundle, assessment)
	if err != nil {
		t.Fatalf("ImportReview: %v", err)
	}
	if !got.Advisory {
		t.Error("Advisory = false, want true")
	}
	if got.Summary.Assessed != 2 || got.Summary.TotalCandidates != len(bundle.Candidates) || got.Summary.ConfigSuggestions != 1 {
		t.Errorf("Summary = %+v, want Assessed=2 ConfigSuggestions=1 TotalCandidates=%d", got.Summary, len(bundle.Candidates))
	}
	entry, ok := got.ReviewedConfigSuggestions.AuthMiddleware[header.CanonicalSymbol]
	if !ok {
		t.Fatalf("authMiddleware missing %q; got %+v", header.CanonicalSymbol, got.ReviewedConfigSuggestions.AuthMiddleware)
	}
	if entry.Assurance != config.AssuranceAnalyze || len(entry.Tags) != 1 || entry.Tags[0] != "internal" {
		t.Errorf("authMiddleware[%q] = %+v, want assurance=analyze tags=[internal]", header.CanonicalSymbol, entry)
	}
	if _, ok := got.ReviewedConfigSuggestions.AuthMiddleware[logger.CanonicalSymbol]; ok {
		t.Errorf("authMiddleware must not contain %q — reviewer marked it not an auth guard", logger.CanonicalSymbol)
	}

	// Validate the config fragment gin-recon would actually accept.
	real := &config.Config{Version: 1, AuthMiddleware: got.ReviewedConfigSuggestions.AuthMiddleware, AuthWrappers: got.ReviewedConfigSuggestions.AuthWrappers}
	if err := config.Validate(real); err != nil {
		t.Errorf("emitted config suggestions failed real config.Validate: %v", err)
	}
}

func TestImportReviewRejectsStaleBundleFingerprint(t *testing.T) {
	bundle := loadAndSuggestAuth(t, "mw-shape-signal")
	header := candidateBy(t, bundle, ".CheckHeaderPresence")
	assessment := &ReviewAssessment{
		SchemaVersion:     "1.0",
		BundleFingerprint: "0000000000000000000000000000000000000000000000000000000000000000",
		Decisions: []CandidateDecision{
			{CandidateID: header.ID, CandidateFingerprint: header.Fingerprint, IsAuthGuard: true, Assurance: config.AssuranceAnalyze, Rationale: "x"},
		},
	}
	if _, err := ImportReview(bundle, assessment); err == nil || !strings.Contains(err.Error(), "bundleFingerprint mismatch") {
		t.Errorf("ImportReview error = %v, want a bundleFingerprint mismatch error", err)
	}
}

func TestImportReviewRejectsStaleCandidateFingerprint(t *testing.T) {
	bundle := loadAndSuggestAuth(t, "mw-shape-signal")
	header := candidateBy(t, bundle, ".CheckHeaderPresence")
	assessment := &ReviewAssessment{
		SchemaVersion:     "1.0",
		BundleFingerprint: bundle.BundleFingerprint,
		Decisions: []CandidateDecision{
			{CandidateID: header.ID, CandidateFingerprint: "0000000000000000000000000000000000000000000000000000000000000000", IsAuthGuard: true, Assurance: config.AssuranceAnalyze, Rationale: "x"},
		},
	}
	if _, err := ImportReview(bundle, assessment); err == nil || !strings.Contains(err.Error(), "is stale") {
		t.Errorf("ImportReview error = %v, want a stale-candidate-fingerprint error", err)
	}
}

func TestImportReviewRejectsUnknownCandidateID(t *testing.T) {
	bundle := loadAndSuggestAuth(t, "mw-shape-signal")
	assessment := &ReviewAssessment{
		SchemaVersion:     "1.0",
		BundleFingerprint: bundle.BundleFingerprint,
		Decisions: []CandidateDecision{
			{CandidateID: "mw-does-not-exist", CandidateFingerprint: "x", IsAuthGuard: true, Assurance: config.AssuranceAnalyze, Rationale: "x"},
		},
	}
	if _, err := ImportReview(bundle, assessment); err == nil || !strings.Contains(err.Error(), "unknown candidate") {
		t.Errorf("ImportReview error = %v, want an unknown-candidate error", err)
	}
}

func TestImportReviewRequiresNonEmptyRationale(t *testing.T) {
	bundle := loadAndSuggestAuth(t, "mw-shape-signal")
	header := candidateBy(t, bundle, ".CheckHeaderPresence")
	assessment := &ReviewAssessment{
		SchemaVersion:     "1.0",
		BundleFingerprint: bundle.BundleFingerprint,
		Decisions: []CandidateDecision{
			{CandidateID: header.ID, CandidateFingerprint: header.Fingerprint, IsAuthGuard: true, Assurance: config.AssuranceAnalyze, Rationale: "   "},
		},
	}
	if _, err := ImportReview(bundle, assessment); err == nil || !strings.Contains(err.Error(), "non-empty rationale") {
		t.Errorf("ImportReview error = %v, want a non-empty-rationale error", err)
	}
}

func TestImportReviewRequiresValidAssuranceWhenAuthGuard(t *testing.T) {
	bundle := loadAndSuggestAuth(t, "mw-shape-signal")
	header := candidateBy(t, bundle, ".CheckHeaderPresence")
	assessment := &ReviewAssessment{
		SchemaVersion:     "1.0",
		BundleFingerprint: bundle.BundleFingerprint,
		Decisions: []CandidateDecision{
			{CandidateID: header.ID, CandidateFingerprint: header.Fingerprint, IsAuthGuard: true, Rationale: "looks like a guard"},
		},
	}
	if _, err := ImportReview(bundle, assessment); err == nil || !strings.Contains(err.Error(), "assurance must be") {
		t.Errorf("ImportReview error = %v, want an assurance-required error", err)
	}
}

func TestImportReviewRejectsDuplicateDecisionForSameCandidate(t *testing.T) {
	bundle := loadAndSuggestAuth(t, "mw-shape-signal")
	header := candidateBy(t, bundle, ".CheckHeaderPresence")
	decision := CandidateDecision{CandidateID: header.ID, CandidateFingerprint: header.Fingerprint, IsAuthGuard: false, Rationale: "x"}
	assessment := &ReviewAssessment{
		SchemaVersion:     "1.0",
		BundleFingerprint: bundle.BundleFingerprint,
		Decisions:         []CandidateDecision{decision, decision},
	}
	if _, err := ImportReview(bundle, assessment); err == nil || !strings.Contains(err.Error(), "duplicate decision") {
		t.Errorf("ImportReview error = %v, want a duplicate-decision error", err)
	}
}

// TestSuggestAuthBundleFingerprintChangesWithCandidateSet guards the real
// staleness mechanism import-review relies on: re-scanning after a
// candidate's own reviewed code changes must change that candidate's own
// Fingerprint and the bundle's own BundleFingerprint, so a decision made
// against the old code is provably rejected rather than silently reused.
func TestSuggestAuthBundleFingerprintChangesWithCandidateSet(t *testing.T) {
	a := loadAndSuggestAuth(t, "mw-shape-signal")
	b := loadAndSuggestAuth(t, "middleware-order")
	if a.BundleFingerprint == "" || b.BundleFingerprint == "" {
		t.Fatal("expected both bundles to carry a non-empty BundleFingerprint")
	}
	if a.BundleFingerprint == b.BundleFingerprint {
		t.Error("two fixtures with entirely different candidate sets must not share a BundleFingerprint")
	}
}
