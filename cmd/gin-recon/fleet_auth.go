// fleet_auth.go implements fleet --suggest-auth's aggregation pass: every
// successfully-scanned module also ran `suggest-auth` (internal/fleet's
// runSuggestAuthEnrichment, alongside its own audit subprocess), writing
// suggestions.json into the same published directory routes.json already
// lives in. This file reads every one of those already-published documents
// back and merges them into one fleet-wide ranked candidate list — building
// a reviewed authMiddleware allowlist for an organization should mean
// reading one document, not running suggest-auth by hand against every
// repository individually.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sort"

	"github.com/sagnikhaldar/gin-recon/internal/analyzer"
	"github.com/sagnikhaldar/gin-recon/internal/fleet"
	"github.com/sagnikhaldar/gin-recon/internal/report"
)

// fleetAuthSampleCap and fleetAuthRepoCap bound how many sample routes and
// repository names one candidate's JSON entry can list — a canonical symbol
// genuinely shared by hundreds of repositories (a common internal auth
// package, exactly the case most worth surfacing) must not make the
// aggregate document's size scale with the whole organization.
const (
	fleetAuthSampleCap = 5
	fleetAuthRepoCap   = 20
)

// fleetAuthCandidateFilename is fleet --suggest-auth's own output file,
// alongside fleet.json.
const fleetAuthCandidateFilename = "fleet-auth-candidates.json"

// FleetAuthCandidate is one canonical middleware symbol's aggregated
// presence across every target/module a --suggest-auth fleet run scanned —
// never authentication evidence itself, same as suggest-auth's own
// AuthCandidate; a candidate for a human/AI reviewer to check against real
// source before adding to authMiddleware.
type FleetAuthCandidate struct {
	CanonicalSymbol string   `json:"canonicalSymbol"`
	RouteCount      int      `json:"routeCount"`
	RepoCount       int      `json:"repoCount"`
	Repos           []string `json:"repos"`
	RepoCountTotal  int      `json:"repoCountTotal,omitempty"` // set only when Repos was capped
	NameHint        bool     `json:"nameHint"`
	KnownNonAuth    bool     `json:"knownNonAuth"`
	SampleRoutes    []string `json:"sampleRoutes"`
}

// FleetAuthSuggestions is fleet-auth-candidates.json's shape.
type FleetAuthSuggestions struct {
	Tool               string               `json:"tool"`
	ToolVersion        string               `json:"toolVersion"`
	Kind               string               `json:"kind"`
	TargetsScanned     int                  `json:"targetsScanned"`
	TargetsContributed int                  `json:"targetsContributed"` // ok/complete AND actually produced a suggestions.json
	Candidates         []FleetAuthCandidate `json:"candidates"`
}

// aggregateFleetAuthSuggestions reads every successfully-scanned module's
// own already-published suggestions.json (derived from its routes.json path
// by substituting the filename — the same published location, no separate
// path logic of its own) and merges candidates by canonical symbol.
// A target/module missing its suggestions.json (its own suggest-auth pass
// failed, or the target was reused from --update/--resume rather than
// freshly scanned) simply contributes nothing — identical in effect to one
// that was never asked for, never an error for the aggregate as a whole.
func aggregateFleetAuthSuggestions(agg *fleet.Aggregate, outDir string) (*FleetAuthSuggestions, error) {
	type accumulator struct {
		routeCount   int
		repos        map[string]bool
		repoOrder    []string
		nameHint     bool
		knownNonAuth bool
		samples      map[string]bool
		sampleOrder  []string
	}
	bySymbol := map[string]*accumulator{}
	targetsScanned := 0
	targetsContributed := 0

	for _, t := range agg.Targets {
		if t.Status != fleet.StatusOK {
			continue
		}
		targetsScanned++
		modules := t.Modules
		if len(modules) == 0 {
			modules = []fleet.ModuleResult{{Report: t.Report, Status: t.Status, Complete: t.Complete}}
		}
		contributedForTarget := false
		for _, m := range modules {
			if m.Status != fleet.StatusOK || m.Report == "" {
				continue
			}
			suggestionsRel := filepath.Join(filepath.Dir(m.Report), "suggestions.json")
			data, err := fleet.ReadBoundedFile(filepath.Join(outDir, suggestionsRel))
			if err != nil {
				continue // that module's own suggest-auth pass never produced one
			}
			var result analyzer.SuggestAuthResult
			if err := json.Unmarshal(data, &result); err != nil {
				return nil, fmt.Errorf("target %q: decoding %s: %w", t.Name, suggestionsRel, err)
			}
			contributedForTarget = true
			for _, c := range result.Candidates {
				acc, ok := bySymbol[c.CanonicalSymbol]
				if !ok {
					acc = &accumulator{repos: map[string]bool{}, samples: map[string]bool{}}
					bySymbol[c.CanonicalSymbol] = acc
				}
				acc.routeCount += c.RouteCount
				acc.nameHint = acc.nameHint || c.NameHint
				acc.knownNonAuth = acc.knownNonAuth || c.KnownNonAuth
				if !acc.repos[t.Name] {
					acc.repos[t.Name] = true
					acc.repoOrder = append(acc.repoOrder, t.Name)
				}
				for _, sample := range c.SampleRoutes {
					labeled := t.Name + ": " + sample
					if !acc.samples[labeled] {
						acc.samples[labeled] = true
						acc.sampleOrder = append(acc.sampleOrder, labeled)
					}
				}
			}
		}
		if contributedForTarget {
			targetsContributed++
		}
	}

	candidates := make([]FleetAuthCandidate, 0, len(bySymbol))
	for symbol, acc := range bySymbol {
		repos := append([]string{}, acc.repoOrder...)
		sort.Strings(repos)
		repoCountTotal := 0
		if len(repos) > fleetAuthRepoCap {
			repoCountTotal = len(repos)
			repos = repos[:fleetAuthRepoCap]
		}
		samples := append([]string{}, acc.sampleOrder...)
		sort.Strings(samples)
		if len(samples) > fleetAuthSampleCap {
			samples = samples[:fleetAuthSampleCap]
		}
		candidates = append(candidates, FleetAuthCandidate{
			CanonicalSymbol: symbol,
			RouteCount:      acc.routeCount,
			RepoCount:       len(acc.repoOrder),
			Repos:           repos,
			RepoCountTotal:  repoCountTotal,
			NameHint:        acc.nameHint,
			KnownNonAuth:    acc.knownNonAuth,
			SampleRoutes:    samples,
		})
	}
	sort.Slice(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		if a.RepoCount != b.RepoCount {
			return a.RepoCount > b.RepoCount
		}
		if a.RouteCount != b.RouteCount {
			return a.RouteCount > b.RouteCount
		}
		return a.CanonicalSymbol < b.CanonicalSymbol
	})

	return &FleetAuthSuggestions{
		Tool:               "gin-recon",
		ToolVersion:        report.ToolVersion,
		Kind:               "fleet-auth-suggestions",
		TargetsScanned:     targetsScanned,
		TargetsContributed: targetsContributed,
		Candidates:         candidates,
	}, nil
}

// writeFleetAuthSuggestions is best-effort: a failure here never fails the
// fleet run itself (docs comment on RunOptions.SuggestAuth) — it only means
// this one companion document didn't get produced this time, reported to
// stderr so it's visible rather than silent.
func writeFleetAuthSuggestions(agg *fleet.Aggregate, outDir string, stderr io.Writer) {
	suggestions, err := aggregateFleetAuthSuggestions(agg, outDir)
	if err != nil {
		fmt.Fprintf(stderr, "gin-recon: fleet: aggregating %s: %v\n", fleetAuthCandidateFilename, err)
		return
	}
	data, err := json.MarshalIndent(suggestions, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "gin-recon: fleet: encoding %s: %v\n", fleetAuthCandidateFilename, err)
		return
	}
	if err := fleet.WriteFileAtomic(filepath.Join(outDir, fleetAuthCandidateFilename), data, 0o644); err != nil {
		fmt.Fprintf(stderr, "gin-recon: fleet: writing %s: %v\n", fleetAuthCandidateFilename, err)
	}
}
