package analyzer

import (
	"context"
	"runtime"
	"strings"
	"testing"

	"github.com/sagnikhaldar/gin-recon/internal/model"
)

// TestInventoryDetectsUncalledLibraryEntryPointButNotCalledOne is the
// regression test for a real completeness gap found scanning several
// production services: a module that never calls gin.New()/gin.Default()
// anywhere, and instead exposes an "Init(router *gin.RouterGroup, ...)"
// function meant to be wired up by a host application, previously produced
// zero routes AND zero diagnostics — indistinguishable in the report from a
// module that genuinely has no HTTP surface at all. This is a materially
// different, and in practice common, gap from diagnoseUntrackedRouterValue's
// (which requires an existing legitimate entry point in the same function to
// even run) and from tryFollowRegistrarCall's (which requires an actual call
// site passing a tracked value) — neither fires when nothing in the whole
// module ever calls the function at all.
func TestInventoryDetectsUncalledLibraryEntryPointButNotCalledOne(t *testing.T) {
	loaded, err := Load(context.Background(), LoadOptions{
		Src:            fixtureDir(t, "library-entry-point"),
		GOOS:           runtime.GOOS,
		GOARCH:         runtime.GOARCH,
		ModuleMode:     model.ModuleReadonly,
		AllowDownloads: true,
	})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	result := Inventory(loaded)

	foundCalled := false
	for _, r := range result.Routes {
		if r.NormalizedPath == "/api/called" && r.Method == "POST" {
			foundCalled = true
		}
		if r.NormalizedPath == "/webhooks/uncalled" {
			t.Errorf("route %s was discovered, want it to stay unresolved — nothing in this module ever calls UncalledInit", r.NormalizedPath)
		}
	}
	if !foundCalled {
		t.Errorf("expected POST /api/called to be discovered (reached via WiredUp's gin.New()), got routes: %+v", result.Routes)
	}

	var libraryEntryPointDiags []model.Diagnostic
	for _, d := range result.Diagnostics {
		if d.Code == "gin-library-entry-point" {
			libraryEntryPointDiags = append(libraryEntryPointDiags, d)
		}
	}
	if len(libraryEntryPointDiags) != 1 {
		t.Fatalf("gin-library-entry-point diagnostics = %+v, want exactly 1 (for UncalledInit only, never CalledInit)", libraryEntryPointDiags)
	}
	if !strings.Contains(libraryEntryPointDiags[0].Message, "UncalledInit") {
		t.Errorf("diagnostic message = %q, want it to name UncalledInit", libraryEntryPointDiags[0].Message)
	}

	if result.ScanCoverage.Complete {
		t.Error("ScanCoverage.Complete = true, want false — a route genuinely could not be resolved")
	}
}
