package format

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLogoAssetsAreSafeAndResponsive(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not locate repository root")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	responsive := []string{
		"assets/favicon.svg",
		"assets/logo/lockup.svg",
		"assets/logo/mark.svg",
		"assets/logo/tile.svg",
	}
	static := []string{
		"assets/logo/lockup-dark.svg",
		"assets/logo/lockup-light.svg",
		"assets/logo/mark-dark.svg",
		"assets/logo/mark-light.svg",
	}

	for _, name := range append(append([]string{}, responsive...), static...) {
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		text := string(data)
		var document struct {
			XMLName xml.Name
		}
		if err := xml.Unmarshal(data, &document); err != nil {
			t.Errorf("%s is not valid XML: %v", name, err)
			continue
		}
		if document.XMLName.Local != "svg" {
			t.Errorf("%s root is %q, want svg", name, document.XMLName.Local)
		}
		for _, forbidden := range []string{"<script", "<!DOCTYPE", "<image", "<use", " href=", "xlink:href", "url("} {
			if strings.Contains(text, forbidden) {
				t.Errorf("%s contains forbidden external or executable content %q", name, forbidden)
			}
		}
		if !strings.Contains(text, `viewBox="0 0 64 64"`) && !strings.Contains(text, `viewBox="0 0 220 72"`) {
			t.Errorf("%s is missing the expected scalable viewBox", name)
		}
	}

	for _, name := range responsive {
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if !strings.Contains(string(data), "prefers-color-scheme: dark") {
			t.Errorf("%s is not color-scheme responsive", name)
		}
	}
	for _, name := range static {
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		text := string(data)
		if strings.Contains(text, "<style") || strings.Contains(text, "@media") || strings.Contains(text, ` class=`) {
			t.Errorf("%s must be a fully inlined static variant", name)
		}
	}

	readme, err := os.ReadFile(filepath.Join(root, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"assets/logo/lockup-dark.svg", "assets/logo/lockup-light.svg"} {
		if !strings.Contains(string(readme), name) {
			t.Errorf("README does not use %s", name)
		}
	}
}

func TestGeneratedHTMLUsesProjectLogoGeometry(t *testing.T) {
	const scanPath = "M49 15.5A24 24 0 1 0 49 48.5"
	if !strings.Contains(brandMarkHTML, scanPath) {
		t.Fatalf("generated-page mark has drifted from assets/logo/mark.svg")
	}
	asset, err := os.ReadFile(filepath.Join("..", "..", "assets", "logo", "mark.svg"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(asset), scanPath) {
		t.Fatalf("public logo has drifted from generated-page mark")
	}
}
