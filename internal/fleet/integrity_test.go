package fleet

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestReusableTargetRejectsTamperedArtifact(t *testing.T) {
	root := t.TempDir()
	rel := filepath.Join("targets", "service", "routes.json")
	path := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("before"), 0o644); err != nil {
		t.Fatal(err)
	}
	artifact, err := artifactForFile(root, rel)
	if err != nil {
		t.Fatal(err)
	}
	result := TargetResult{
		Name: "service", Status: StatusOK, Complete: true, SourceFingerprint: "source",
		Artifacts: []Artifact{artifact},
		Modules: []ModuleResult{{
			ID: "root", Path: ".", Kind: ModuleGo, Status: StatusOK, Complete: true,
			Report: filepath.ToSlash(rel), Artifacts: []Artifact{artifact},
		}},
	}
	if err := os.WriteFile(path, []byte("after"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := reusableTarget(root, "", result, "source", []string{"json"}, false); err == nil {
		t.Fatal("tampered artifact was accepted for reuse")
	}
}

func TestReusableTargetRejectsIncompleteResult(t *testing.T) {
	result := TargetResult{Status: StatusNotGoModule, Complete: false, SourceFingerprint: "source"}
	if err := reusableTarget(t.TempDir(), "", result, "source", []string{"json"}, false); err == nil {
		t.Fatal("incomplete result was accepted for reuse")
	}
}

func TestSuggestionReuseRejectsNonCanonicalOrTamperedArtifact(t *testing.T) {
	root := t.TempDir()
	canonical := filepath.Join("targets", "service", "suggestions.json")
	path := filepath.Join(root, canonical)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"candidates":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	artifact, err := artifactForFile(root, canonical)
	if err != nil {
		t.Fatal(err)
	}
	result := TargetResult{Name: "service", Status: StatusOK, Complete: true, Modules: []ModuleResult{{
		ID: "root", Status: StatusOK, Complete: true,
		Report: filepath.Join("targets", "service", "routes.json"), SuggestionArtifact: &artifact,
	}}}
	wrong := artifact
	wrong.Path = filepath.Join("targets", "other", "suggestions.json")
	result.Modules[0].SuggestionArtifact = &wrong
	if err := validateSuggestionArtifacts(root, result); err == nil {
		t.Fatal("non-canonical suggestion path accepted")
	}
	result.Modules[0].SuggestionArtifact = &artifact
	if err := os.WriteFile(path, []byte(`{"candidates":[1]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := validateSuggestionArtifacts(root, result); err == nil {
		t.Fatal("tampered suggestion artifact accepted")
	}
}

func TestTargetFingerprintIgnoresGitHubProvenanceButNotSource(t *testing.T) {
	first := Target{
		Name: "service", Git: &GitSource{URL: "https://github.com/acme/service.git", Ref: "main"},
		GitHub: &GitHubMeta{PushedAt: "2026-01-01T00:00:00Z", Visibility: "private"},
	}
	second := first
	second.GitHub = &GitHubMeta{PushedAt: "2026-09-01T00:00:00Z", Visibility: "public"}
	if targetFingerprint(first) != targetFingerprint(second) {
		t.Fatal("GitHub provenance drift changed the source-resolution fingerprint")
	}
	second.Git = &GitSource{URL: first.Git.URL, Ref: "release"}
	if targetFingerprint(first) == targetFingerprint(second) {
		t.Fatal("Git ref change did not change the source-resolution fingerprint")
	}
}

func TestReusableTargetRejectsMissingAdvertisedFormatArtifact(t *testing.T) {
	root := t.TempDir()
	rel := filepath.Join("targets", "service", "routes.json")
	path := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	artifact, err := artifactForFile(root, rel)
	if err != nil {
		t.Fatal(err)
	}
	result := TargetResult{
		Name: "service", Status: StatusOK, Complete: true, SourceFingerprint: "source",
		Artifacts: []Artifact{artifact},
		Modules: []ModuleResult{{
			ID: "root", Path: ".", Kind: ModuleGo, Status: StatusOK, Complete: true,
			Report: filepath.ToSlash(rel), Artifacts: []Artifact{artifact},
		}},
	}
	if err := reusableTarget(root, "", result, "source", []string{"json", "openapi"}, false); err == nil {
		t.Fatal("result missing advertised openapi.json was accepted for reuse")
	}
}

func TestPublishDirectoriesRollsBackEveryTree(t *testing.T) {
	rawParent := t.TempDir()
	htmlParent := t.TempDir()
	rawStage, rawDestination := filepath.Join(rawParent, "raw-stage"), filepath.Join(rawParent, "service")
	htmlStage, htmlDestination := filepath.Join(htmlParent, "html-stage"), filepath.Join(htmlParent, "service")
	for _, fixture := range []struct {
		dir, contents string
	}{
		{rawDestination, "old raw"}, {htmlDestination, "old html"},
		{rawStage, "new raw"}, {htmlStage, "new html"},
	} {
		if err := os.MkdirAll(fixture.dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(fixture.dir, "artifact"), []byte(fixture.contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	renamer := func(oldPath, newPath string) error {
		if oldPath == htmlStage && newPath == htmlDestination {
			return errors.New("injected HTML publication failure")
		}
		return os.Rename(oldPath, newPath)
	}
	err := publishDirectoriesWithRename(renamer,
		directoryPublication{staged: rawStage, destination: rawDestination},
		directoryPublication{staged: htmlStage, destination: htmlDestination},
	)
	if err == nil {
		t.Fatal("publication unexpectedly succeeded")
	}
	for _, fixture := range []struct {
		dir, want string
	}{{rawDestination, "old raw"}, {htmlDestination, "old html"}} {
		got, readErr := os.ReadFile(filepath.Join(fixture.dir, "artifact"))
		if readErr != nil {
			t.Fatal(readErr)
		}
		if string(got) != fixture.want {
			t.Fatalf("%s contains %q, want restored %q", fixture.dir, got, fixture.want)
		}
	}
}
