package analyzer

import (
	"context"
	"runtime"
	"strings"
	"testing"

	"github.com/sagnikhaldar/gin-recon/internal/model"
)

// Real, confirmed case, not hypothetical: auditing a live organization's
// fleet turned up a "tools" go.mod with only go.mod/go.sum and zero .go
// files (a common Go idiom for pinning tool versions that, here, never got
// its own tools.go committed). packages.Load's "./..." then matches no
// packages at all, and allPackagesFailed(nil) is correctly true — but
// joinPackageErrors has nothing to visit and returns "", so before this fix
// the resulting error read "loading packages under X: " with nothing after
// the colon, telling a reader nothing about what actually went wrong.
func TestLoadEmptyModuleReportsClearError(t *testing.T) {
	_, err := Load(context.Background(), LoadOptions{
		Src:        fixtureDir(t, "empty-module"),
		GOOS:       runtime.GOOS,
		GOARCH:     runtime.GOARCH,
		ModuleMode: model.ModuleReadonly,
	})
	if err == nil {
		t.Fatal("Load(empty-module) = nil error, want a clear fatal-load error")
	}
	if !strings.Contains(err.Error(), "matched no packages") {
		t.Errorf("Load(empty-module) error = %q, want it to explain that \"./...\" matched no packages", err.Error())
	}
}
