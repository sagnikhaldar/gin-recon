package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sagnikhaldar/gin-recon/internal/cli"
	"github.com/sagnikhaldar/gin-recon/internal/fleet"
)

const fleetDefaultConfigFilename = "fleet-config.json"

// The default authorizes only GitHub discovery and cloning. Credentials stay
// in the environment, and authentication classification still needs review.
const fleetDefaultConfig = `{
  "version": 1,
  "fleet": {
    "allowedRemoteHosts": [
      {"host": "api.github.com", "tokenEnv": "GH_TOKEN"},
      {"host": "github.com", "tokenEnv": "GH_TOKEN"}
    ]
  }
}
`

// Resolve the standard GitHub variables without copying credential values
// into configuration. Empty GH_TOKEN must not hide a usable GITHUB_TOKEN.
func fleetGitHubTokenEnv() string {
	if strings.TrimSpace(os.Getenv("GH_TOKEN")) != "" {
		return "GH_TOKEN"
	}
	if strings.TrimSpace(os.Getenv("GITHUB_TOKEN")) != "" {
		return "GITHUB_TOKEN"
	}
	return "GH_TOKEN"
}

// ensureFleetOrgConfig bootstraps an org's own output directory when no
// config was supplied. Reuse existing configuration without rewriting it,
// including on force/resume/update. Explicit paths retain normal validation.
func ensureFleetOrgConfig(opts *cli.Options) error {
	if opts.Org == "" || opts.ConfigPath != "" {
		return nil
	}
	path := filepath.Join(opts.OutDir, fleetDefaultConfigFilename)
	info, err := os.Lstat(path)
	switch {
	case os.IsNotExist(err):
		if err := fleet.WriteFileAtomic(path, []byte(fleetDefaultConfig), 0o600); err != nil {
			return fmt.Errorf("creating default org config %s: %w", path, err)
		}
	case err != nil:
		return fmt.Errorf("reading default org config %s: %w", path, err)
	case !info.Mode().IsRegular():
		return fmt.Errorf("default org config %s must be a regular file", path)
	default:
		data, err := fleet.ReadBoundedFile(path)
		if err != nil {
			return fmt.Errorf("reading default org config %s: %w", path, err)
		}
		// Migrate only the exact old generated template; preserve all operator
		// edits. This name is recognized for migration, never read as a token.
		legacy := strings.ReplaceAll(fleetDefaultConfig, "GH_TOKEN", "GIN_RECON_GITHUB_TOKEN")
		if string(data) == legacy {
			if err := fleet.WriteFileAtomic(path, []byte(fleetDefaultConfig), 0o600); err != nil {
				return fmt.Errorf("updating default org config %s: %w", path, err)
			}
		}
	}
	opts.ConfigPath = path
	return nil
}
