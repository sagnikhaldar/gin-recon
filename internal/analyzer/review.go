// Package analyzer's ImportReview implements the `import-review` command's
// own logic: mechanically turning a reviewer's (human or AI) decisions about
// suggest-auth's own candidates into ready-to-copy authMiddleware/
// authWrappers config entries — never applying anything to a real --config
// file itself. docs/adr/0005-conservative-classification.md's separation of
// reviewer judgment from control-flow evidence stays in full force: a
// decision's own IsAuthGuard/Assurance fields are what make a candidate
// eligible, never NameHint or EnforcementShape by themselves — those two
// only ever informed suggest-auth's own ranking, exactly as before.
package analyzer

import (
	"fmt"
	"sort"
	"strings"

	"github.com/sagnikhaldar/gin-recon/internal/config"
	"github.com/sagnikhaldar/gin-recon/internal/model"
)

// ReviewAssessment is import-review's own input, alongside a
// SuggestAuthResult bundle: a reviewer's decision for each candidate they
// actually assessed. BundleFingerprint binds the whole assessment to the
// exact bundle it was reviewed against.
type ReviewAssessment struct {
	SchemaVersion     string              `json:"schemaVersion"`
	BundleFingerprint string              `json:"bundleFingerprint"`
	Decisions         []CandidateDecision `json:"decisions"`
}

// CandidateDecision is one reviewer's judgment about one candidate — never
// itself derived from static analysis. CandidateFingerprint binds this one
// decision to the exact candidate record it was reviewed against, the same
// way BundleFingerprint binds the whole assessment. Rationale is required
// so a decision is always self-explaining, not a bare yes/no a later reader
// has no way to check.
type CandidateDecision struct {
	CandidateID          string           `json:"candidateId"`
	CandidateFingerprint string           `json:"candidateFingerprint"`
	IsAuthGuard          bool             `json:"isAuthGuard"`
	Assurance            config.Assurance `json:"assurance,omitempty"`
	Tags                 []string         `json:"tags,omitempty"`
	Roles                []string         `json:"roles,omitempty"`
	Scopes               []string         `json:"scopes,omitempty"`
	OpenAPIScheme        string           `json:"openapiScheme,omitempty"`
	TransparentWrapper   bool             `json:"transparentWrapper,omitempty"`
	Rationale            string           `json:"rationale"`
}

// DecisionOutcome records what happened to one decision after validation:
// whether it became a config suggestion, and why not when it didn't.
type DecisionOutcome struct {
	CandidateID                 string `json:"candidateId"`
	CanonicalSymbol             string `json:"canonicalSymbol"`
	IsAuthGuard                 bool   `json:"isAuthGuard"`
	Rationale                   string `json:"rationale"`
	EligibleForConfigSuggestion bool   `json:"eligibleForConfigSuggestion"`
	Reason                      string `json:"reason,omitempty"`
}

// ReviewSummary tallies ReviewSuggestions.Decisions for a quick read
// without counting the array by hand.
type ReviewSummary struct {
	Assessed          int `json:"assessed"`
	TotalCandidates   int `json:"totalCandidates"`
	ConfigSuggestions int `json:"configSuggestions"`
}

// ReviewedConfigSuggestions is exactly the shape a reviewer copies into a
// real --config file's own top-level authMiddleware/authWrappers fields —
// never merged into an existing --config automatically, since that file may
// already hold other entries or hand edits this package has no evidence
// about. cmd/gin-recon's own import-review command does write it out as a
// second, standalone, directly --config-usable file when --out is given
// (never merged into anything existing) — the purely mechanical part of
// "make this a real config file," as opposed to deciding what belongs in
// one, which stays a human's decision entirely.
type ReviewedConfigSuggestions struct {
	AuthMiddleware map[string]config.AuthMiddlewareEntry `json:"authMiddleware,omitempty"`
	AuthWrappers   []string                              `json:"authWrappers,omitempty"`
}

// ReviewSuggestions is import-review's own JSON output. Advisory is always
// true and Notice always says so explicitly: nothing here is ever applied
// to a real --config automatically, per
// docs/adr/0005-conservative-classification.md.
type ReviewSuggestions struct {
	SchemaVersion             string                    `json:"schemaVersion"`
	Kind                      string                    `json:"kind"`
	Tool                      string                    `json:"tool"`
	ToolVersion               string                    `json:"toolVersion"`
	Advisory                  bool                      `json:"advisory"`
	Notice                    string                    `json:"notice"`
	SourceBundleFingerprint   string                    `json:"sourceBundleFingerprint"`
	Summary                   ReviewSummary             `json:"summary"`
	Decisions                 []DecisionOutcome         `json:"decisions"`
	ReviewedConfigSuggestions ReviewedConfigSuggestions `json:"reviewedConfigSuggestions"`
	Warnings                  []string                  `json:"warnings,omitempty"`
}

const reviewSuggestionsNotice = "These are untrusted advisory suggestions. gin-recon did not alter audit results or configuration; review each rationale and copy approved entries into --config explicitly."

// draftRationale is copied verbatim into every DraftAssessment decision so
// review-suggestions.json always makes plain, to any later reader, that
// this particular entry was machine-generated, not human-attested — see
// docs/adr/0042-static-analysis-drafts-assessments.md.
const draftRationale = "Auto-drafted by gin-recon (docs/adr/0042-static-analysis-drafts-assessments.md): this candidate's own name matches a known auth-related pattern AND its control flow independently confirms an abort-under-some-condition shape — the intersection of two signals empirically validated across 39 real repositories with zero false positives, never either signal alone. Not human- or AI-verified; review before relying on this in production."

// DraftAssessment generates a ReviewAssessment from bundle's own combined
// static-analysis signals alone, with no human or AI input: for every
// candidate where NameHint and EnforcementShape == confirmed-shape both
// hold (which already implies !KnownNonAuth, since NameHint's own
// computation excludes it), it drafts isAuthGuard: true, assurance:
// analyze. Every other candidate — including the common case of
// confirmed-shape with no name hint, where real production code was found
// to be a validator or rate limiter just as often as a real guard — is
// left out of the draft entirely, never defaulted either way; it remains
// exactly what it already was: an unconfigured-guard finding awaiting real
// review, or ordinary suggest-auth output. AI/human review stays fully
// possible and is not replaced: import-review's own --assessment, when
// given, is used exactly as before and can extend, override, or replace
// anything DraftAssessment would have produced.
func DraftAssessment(bundle *SuggestAuthResult) *ReviewAssessment {
	assessment := &ReviewAssessment{
		SchemaVersion:     "1.0",
		BundleFingerprint: bundle.BundleFingerprint,
	}
	for _, c := range bundle.Candidates {
		if !c.NameHint || c.EnforcementShape != model.EnforcementConfirmedShape {
			continue
		}
		assessment.Decisions = append(assessment.Decisions, CandidateDecision{
			CandidateID:          c.ID,
			CandidateFingerprint: c.Fingerprint,
			IsAuthGuard:          true,
			Assurance:            config.AssuranceAnalyze,
			Rationale:            draftRationale,
		})
	}
	return assessment
}

// ImportReview validates assessment against bundle's own exact evidence —
// every candidateId must exist in bundle, and every candidateFingerprint
// must match that candidate's own current Fingerprint — then mechanically
// computes ready-to-copy authMiddleware/authWrappers config entries for
// eligible decisions. It never applies anything to a real config file
// itself; the caller (cmd/gin-recon's import-review command) only ever
// writes this result, not a merged --config.
func ImportReview(bundle *SuggestAuthResult, assessment *ReviewAssessment) (*ReviewSuggestions, error) {
	if bundle == nil {
		return nil, fmt.Errorf("import-review: bundle is required")
	}
	if assessment == nil {
		return nil, fmt.Errorf("import-review: assessment is required")
	}
	if assessment.BundleFingerprint != bundle.BundleFingerprint {
		return nil, fmt.Errorf("import-review: assessment was produced against a different or stale bundle (bundleFingerprint mismatch) — re-export the bundle and re-assess")
	}

	byID := make(map[string]AuthCandidate, len(bundle.Candidates))
	for _, c := range bundle.Candidates {
		byID[c.ID] = c
	}

	seen := make(map[string]bool, len(assessment.Decisions))
	authMiddleware := map[string]config.AuthMiddlewareEntry{}
	var authWrappers []string
	var outcomes []DecisionOutcome

	for _, d := range assessment.Decisions {
		if seen[d.CandidateID] {
			return nil, fmt.Errorf("import-review: duplicate decision for candidate %q", d.CandidateID)
		}
		seen[d.CandidateID] = true

		candidate, ok := byID[d.CandidateID]
		if !ok {
			return nil, fmt.Errorf("import-review: decision references unknown candidate %q", d.CandidateID)
		}
		if d.CandidateFingerprint != candidate.Fingerprint {
			return nil, fmt.Errorf("import-review: decision for %q is stale — its candidateFingerprint no longer matches this bundle's candidate; re-export and re-assess", d.CandidateID)
		}
		if strings.TrimSpace(d.Rationale) == "" {
			return nil, fmt.Errorf("import-review: decision for %q must carry a non-empty rationale", d.CandidateID)
		}
		if d.IsAuthGuard && d.Assurance != config.AssuranceAnalyze && d.Assurance != config.AssuranceAttested {
			return nil, fmt.Errorf("import-review: decision for %q: assurance must be %q or %q when isAuthGuard is true, got %q", d.CandidateID, config.AssuranceAnalyze, config.AssuranceAttested, d.Assurance)
		}

		outcome := DecisionOutcome{
			CandidateID:     d.CandidateID,
			CanonicalSymbol: candidate.CanonicalSymbol,
			IsAuthGuard:     d.IsAuthGuard,
			Rationale:       d.Rationale,
		}
		switch {
		case !d.IsAuthGuard:
			outcome.Reason = "reviewer marked this candidate as not an auth guard"
		case candidate.CanonicalSymbol == "":
			outcome.Reason = "candidate has no canonical symbol to key a config entry by"
		default:
			outcome.EligibleForConfigSuggestion = true
			authMiddleware[candidate.CanonicalSymbol] = config.AuthMiddlewareEntry{
				Assurance:     d.Assurance,
				Tags:          d.Tags,
				Roles:         d.Roles,
				Scopes:        d.Scopes,
				OpenAPIScheme: d.OpenAPIScheme,
			}
			if d.TransparentWrapper {
				authWrappers = append(authWrappers, candidate.CanonicalSymbol)
			}
		}
		outcomes = append(outcomes, outcome)
	}

	sort.Slice(outcomes, func(i, j int) bool { return outcomes[i].CandidateID < outcomes[j].CandidateID })
	sort.Strings(authWrappers)

	// The emitted fragment must itself be a valid gin-recon config — if it
	// were not, that is a bug in this function, not something that should
	// ever reach a reviewer.
	if len(authMiddleware) > 0 || len(authWrappers) > 0 {
		check := &config.Config{Version: 1, AuthMiddleware: authMiddleware, AuthWrappers: authWrappers}
		if err := config.Validate(check); err != nil {
			return nil, fmt.Errorf("import-review: internal error: generated config suggestions failed validation: %w", err)
		}
	}

	configSuggestionCount := 0
	for _, o := range outcomes {
		if o.EligibleForConfigSuggestion {
			configSuggestionCount++
		}
	}

	return &ReviewSuggestions{
		SchemaVersion:           "1.0",
		Kind:                    "middleware-review-suggestions",
		Advisory:                true,
		Notice:                  reviewSuggestionsNotice,
		SourceBundleFingerprint: bundle.BundleFingerprint,
		Summary: ReviewSummary{
			Assessed:          len(outcomes),
			TotalCandidates:   len(bundle.Candidates),
			ConfigSuggestions: configSuggestionCount,
		},
		Decisions: outcomes,
		ReviewedConfigSuggestions: ReviewedConfigSuggestions{
			AuthMiddleware: authMiddleware,
			AuthWrappers:   authWrappers,
		},
	}, nil
}
