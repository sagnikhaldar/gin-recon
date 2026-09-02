package model

import (
	"encoding/json"
	"testing"
)

// TestNilSlicesMarshalAsEmptyArrays is the regression test for the schema
// hole described in this package's doc comment: schema/report-1.0.json
// declares these fields as non-nullable arrays/objects, but a bare nil Go
// slice/map with no MarshalJSON guard would otherwise encode as JSON null and
// silently produce a report that violates its own schema. Each subtest
// leaves the relevant field at its zero value (nil) to prove the guard
// actually fires, not just that a populated value round-trips.
func TestNilSlicesMarshalAsEmptyArrays(t *testing.T) {
	assertArray := func(t *testing.T, data []byte, path ...string) {
		t.Helper()
		var m map[string]any
		if err := json.Unmarshal(data, &m); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		var cur any = m
		for _, p := range path {
			obj, ok := cur.(map[string]any)
			if !ok {
				t.Fatalf("path %v: %q is not an object in %s", path, p, data)
			}
			cur = obj[p]
		}
		if _, ok := cur.([]any); !ok {
			t.Errorf("path %v = %#v (from %s), want a JSON array, not null", path, cur, data)
		}
	}

	t.Run("BuildContext.Tags", func(t *testing.T) {
		data, err := json.Marshal(BuildContext{GOOS: "linux", GOARCH: "amd64"})
		if err != nil {
			t.Fatal(err)
		}
		assertArray(t, data, "tags")
	})

	t.Run("Route.Middleware and EvidenceOrigins", func(t *testing.T) {
		data, err := json.Marshal(Route{Method: "GET", NormalizedPath: "/x"})
		if err != nil {
			t.Fatal(err)
		}
		assertArray(t, data, "middleware")
		assertArray(t, data, "evidenceOrigins")
	})

	t.Run("FallbackSurface.Middleware", func(t *testing.T) {
		data, err := json.Marshal(FallbackSurface{Kind: FallbackNoRoute})
		if err != nil {
			t.Fatal(err)
		}
		assertArray(t, data, "middleware")
	})

	t.Run("ScanCoverage.ReachedLimits", func(t *testing.T) {
		data, err := json.Marshal(ScanCoverage{Complete: true})
		if err != nil {
			t.Fatal(err)
		}
		assertArray(t, data, "reachedLimits")
	})

	t.Run("AuthClassification.Tags Roles Scopes", func(t *testing.T) {
		data, err := json.Marshal(AuthClassification{AuthStatus: AuthPublic})
		if err != nil {
			t.Fatal(err)
		}
		assertArray(t, data, "tags")
		assertArray(t, data, "roles")
		assertArray(t, data, "scopes")
	})
}
