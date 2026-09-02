package config

import (
	"fmt"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func mustDecode(t *testing.T, format Format, data string) *Config {
	t.Helper()
	cfg, err := Decode(format, []byte(data))
	if err != nil {
		t.Fatalf("Decode(%s) unexpected error: %v\ninput: %s", format, err, data)
	}
	return cfg
}

func expectDecodeError(t *testing.T, format Format, data string, wantSubstring string) {
	t.Helper()
	_, err := Decode(format, []byte(data))
	if err == nil {
		t.Fatalf("Decode(%s) succeeded, want an error containing %q\ninput: %s", format, wantSubstring, data)
	}
	if !strings.Contains(err.Error(), wantSubstring) {
		t.Fatalf("Decode(%s) error = %q, want it to contain %q", format, err.Error(), wantSubstring)
	}
}

func TestDecodeMinimalConfig(t *testing.T) {
	for _, tc := range []struct {
		format Format
		data   string
	}{
		{FormatJSON, `{"version": 1}`},
		{FormatYAML, "version: 1\n"},
	} {
		cfg := mustDecode(t, tc.format, tc.data)
		if cfg.Version != 1 {
			t.Errorf("%s: Version = %d, want 1", tc.format, cfg.Version)
		}
	}
}

func TestDecodeRejectsMissingVersion(t *testing.T) {
	expectDecodeError(t, FormatJSON, `{}`, "version")
	expectDecodeError(t, FormatYAML, "{}\n", "version")
}

func TestDecodeRejectsWrongVersion(t *testing.T) {
	expectDecodeError(t, FormatJSON, `{"version": 2}`, "version")
}

func TestDecodeRejectsUnknownFields(t *testing.T) {
	expectDecodeError(t, FormatJSON, `{"version": 1, "totallyUnknownField": true}`, "unknown field")
	expectDecodeError(t, FormatYAML, "version: 1\ntotallyUnknownField: true\n", "not found")
}

func TestDecodeRejectsUnknownNestedFields(t *testing.T) {
	expectDecodeError(t, FormatJSON, `{"version": 1, "limits": {"maxFiles": 10, "bogus": 1}}`, "unknown field")
}

func TestDecodeRejectsDuplicateYAMLKeys(t *testing.T) {
	expectDecodeError(t, FormatYAML, "version: 1\nversion: 1\n", "already defined")
}

func TestDecodeRejectsCustomYAMLTags(t *testing.T) {
	expectDecodeError(t, FormatYAML, "version: 1\nauthWrappers: !!python/object:foo []\n", "custom tag")
	expectDecodeError(t, FormatYAML, "version: !mytag 1\n", "custom tag")
}

func TestDecodeRejectsMultiDocumentYAML(t *testing.T) {
	expectDecodeError(t, FormatYAML, "version: 1\n---\nversion: 1\n", "only one document")
}

func TestDecodeRejectsTrailingJSONContent(t *testing.T) {
	expectDecodeError(t, FormatJSON, `{"version": 1}{"version": 1}`, "trailing content")
}

func TestDecodeRejectsMalformedJSON(t *testing.T) {
	expectDecodeError(t, FormatJSON, `{"version": 1,}`, "invalid JSON")
}

// TestUnderlyingYAMLLibraryRejectsExcessiveAliasing does not exercise Decode
// at all. It documents and pins down a safety property Decode relies on but
// does not implement itself: go.yaml.in/yaml/v3 refuses to materialize a
// YAML "alias bomb" (nested anchors each referencing the previous layer many
// times, expanding exponentially) once expansion crosses an internal
// threshold. docs/threat-model.md requires defending against "excessive
// memory/CPU use" from untrusted configuration, and this is where that
// requirement is actually satisfied for YAML — a version bump of this
// dependency that silently dropped the protection should fail this test
// before it ever reaches a real Decode call.
//
// This only fires when a destination actually has to expand and copy the
// aliased values (here, map[string]any) — Decode's own two-pass strict
// decode additionally benefits from a cheaper first line of defense for
// unrecognized structure: KnownFields(true) rejects a bomb hidden under an
// unknown field name via "field not found" without needing to expand it at
// all, since a value bound for a nonexistent field is skipped rather than
// materialized.
func TestUnderlyingYAMLLibraryRejectsExcessiveAliasing(t *testing.T) {
	var b strings.Builder
	fmt.Fprintln(&b, `a0: &a0 ["x","x","x","x","x","x","x","x","x","x"]`)
	for i := 1; i < 12; i++ {
		refs := make([]string, 10)
		for j := range refs {
			refs[j] = fmt.Sprintf("*a%d", i-1)
		}
		fmt.Fprintf(&b, "a%d: &a%d [%s]\n", i, i, strings.Join(refs, ","))
	}

	var out map[string]any
	err := yaml.Unmarshal([]byte(b.String()), &out)
	if err == nil {
		t.Fatal("expected an error decoding an exponential YAML alias bomb, got nil")
	}
	if !strings.Contains(err.Error(), "aliasing") {
		t.Fatalf("error = %q, want it to mention aliasing", err.Error())
	}
}

func TestDecodeAcceptsCoreYAMLTagsExplicitly(t *testing.T) {
	// Explicit core-schema tags (as opposed to implicit/plain scalars) must
	// still be accepted — rejectNonCoreTags allowlists them, it does not
	// merely tolerate an empty Tag.
	mustDecode(t, FormatYAML, "version: !!int 1\nauthWrappers: !!seq [\"a\"]\n")
}
