package analyzer

import (
	"context"
	"runtime"
	"testing"

	"github.com/sagnikhaldar/gin-recon/internal/model"
)

func TestBuildPseudoConstIndexExcludesReassignedVar(t *testing.T) {
	loaded, err := Load(context.Background(), LoadOptions{
		Src:            fixtureDir(t, "struct-literal-registrar"),
		GOOS:           runtime.GOOS,
		GOARCH:         runtime.GOARCH,
		ModuleMode:     model.ModuleReadonly,
		AllowDownloads: true,
	})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	index := buildPseudoConstIndex(loaded.Packages)

	foundGET, foundPOST, foundMutable := false, false, false
	for obj, value := range index {
		switch obj.Name() {
		case "GET":
			foundGET = true
			if value != "GET" {
				t.Errorf("GET = %q, want \"GET\"", value)
			}
		case "POST":
			foundPOST = true
			if value != "POST" {
				t.Errorf("POST = %q, want \"POST\"", value)
			}
		case "Mutable":
			foundMutable = true
		}
	}
	if !foundGET || !foundPOST {
		t.Errorf("expected GET and POST to be indexed as pseudo-consts, found GET=%v POST=%v", foundGET, foundPOST)
	}
	if foundMutable {
		t.Error("Mutable was indexed as a pseudo-const, but it is reassigned elsewhere in its package — must never be trusted")
	}
}
