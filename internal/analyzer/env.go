package analyzer

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sagnikhaldar/gin-recon/internal/model"
)

// sanitizedEnv builds the allowlisted environment the typed profile invokes
// the Go toolchain under, per docs/threat-model.md#trust-profiles: construct
// an allowlisted environment rather than inherit arbitrary variables, disable
// CGO and toolchain auto-download, default to offline module resolution, and
// never let the analyzer write into the scanned checkout.
//
// cacheDir is a tool-owned directory outside the target tree (never the
// checkout itself) used for GOCACHE/GOMODCACHE, satisfying "use tool-owned
// bounded caches outside the target tree and never write into the checkout."
func sanitizedEnv(opts LoadOptions, cacheDir string) []string {
	modFlag := "-mod=readonly"
	if opts.ModuleMode == model.ModuleVendor {
		modFlag = "-mod=vendor"
	}
	goflags := modFlag
	if len(opts.Tags) > 0 {
		goflags += " -tags=" + strings.Join(opts.Tags, ",")
	}

	env := []string{
		"PATH=" + os.Getenv("PATH"), // required to locate the go tool itself
		"HOME=" + os.Getenv("HOME"), // the go tool and its subprocesses (e.g. git) may need it for config lookup
		"GOOS=" + opts.GOOS,
		"GOARCH=" + opts.GOARCH,
		"GOFLAGS=" + goflags,
		"GOCACHE=" + filepath.Join(cacheDir, "gocache"),
		"GOMODCACHE=" + filepath.Join(cacheDir, "gomodcache"),
		"GOPACKAGESDRIVER=off",
		"GOTOOLCHAIN=local",
		"GO111MODULE=on",
		"CGO_ENABLED=0",
		"GOPRIVATE=",
		"GONOPROXY=",
		"GONOSUMDB=",
	}

	if opts.Workspace != "" && opts.Workspace != "off" {
		env = append(env, "GOWORK="+opts.Workspace)
	} else {
		env = append(env, "GOWORK=off")
	}

	if opts.AllowDownloads {
		env = append(env, "GOPROXY=https://proxy.golang.org,direct", "GOSUMDB=sum.golang.org")
	} else {
		env = append(env, "GOPROXY=off", "GOSUMDB=off")
	}

	return env
}

// prepareCacheDir returns a persistent, tool-owned cache directory under the
// OS user cache directory (e.g. ~/.cache/gin-recon on Linux) — never inside
// the scanned checkout, and never the arbitrary environment-inherited
// GOMODCACHE/GOCACHE a hostile target's environment could otherwise
// influence. It is deliberately persistent across invocations, not a fresh
// directory per run: with the offline-by-default GOPROXY=off, a
// once-per-run cache would force a network fetch (or fail outright) on
// every single scan, which defeats the purpose of a cache and is not what
// docs/threat-model.md's "bounded" caching is asking for — "bounded" means
// resource/size-bounded, not single-use.
func prepareCacheDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("resolving user cache directory: %w", err)
	}
	dir := filepath.Join(base, "gin-recon")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("creating tool-owned cache directory: %w", err)
	}
	return dir, nil
}
