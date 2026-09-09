package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sagnikhaldar/gin-recon/internal/cli"
)

func TestDefaultOrgConfigUsesStandardGitHubTokenVariables(t *testing.T) {
	for _, tc := range []struct {
		name, ghToken, githubToken, want string
	}{
		{"gh-only", "gh-value", "", "GH_TOKEN"},
		{"github-only", "", "github-value", "GITHUB_TOKEN"},
		{"both", "gh-value", "github-value", "GH_TOKEN"},
		{"empty-gh", "  ", "github-value", "GITHUB_TOKEN"},
		{"neither", "", "", "GH_TOKEN"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("GH_TOKEN", tc.ghToken)
			t.Setenv("GITHUB_TOKEN", tc.githubToken)
			opts := &cli.Options{Org: "example", OutDir: t.TempDir()}
			if err := ensureFleetOrgConfig(opts); err != nil {
				t.Fatal(err)
			}
			cfg, err := loadConfig(opts.ConfigPath)
			if err != nil {
				t.Fatal(err)
			}
			hosts := buildFleetAllowedHosts(cfg)
			if len(hosts) != 2 {
				t.Fatalf("hosts = %+v", hosts)
			}
			for _, host := range hosts {
				if host.TokenEnv != tc.want {
					t.Errorf("%s uses %s, want %s", host.Host, host.TokenEnv, tc.want)
				}
			}
			data, _ := os.ReadFile(opts.ConfigPath)
			if string(data) != fleetDefaultConfig {
				t.Fatal("generated config changed with credential values")
			}
		})
	}
}

func TestDefaultOrgConfigMigratesOldGeneratedTokenReference(t *testing.T) {
	out := t.TempDir()
	path := filepath.Join(out, fleetDefaultConfigFilename)
	legacy := strings.ReplaceAll(fleetDefaultConfig, "GH_TOKEN", "GIN_RECON_GITHUB_TOKEN")
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ensureFleetOrgConfig(&cli.Options{Org: "example", OutDir: out}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != fleetDefaultConfig {
		t.Fatalf("old generated config was not migrated: %v", err)
	}
}

func TestDefaultOrgConfigPreservesOperatorEdits(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out")
	opts := &cli.Options{Org: "example", OutDir: out}
	if err := ensureFleetOrgConfig(opts); err != nil {
		t.Fatal(err)
	}
	want := []byte(`{"version":1,"authMiddleware":{"example.RequireAuth":{}},"fleet":{"allowedRemoteHosts":[]}}`)
	if err := os.WriteFile(opts.ConfigPath, want, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"plain", "force", "resume", "update"} {
		opts := &cli.Options{Org: "example", OutDir: out, Force: mode == "force", Resume: mode == "resume", Update: mode == "update"}
		if err := ensureFleetOrgConfig(opts); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(opts.ConfigPath)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("%s changed existing config: %v", mode, err)
		}
	}
}

func TestDefaultOrgConfigDoesNotReplaceExplicitMissingConfig(t *testing.T) {
	root := t.TempDir()
	out := filepath.Join(root, "out")
	missing := filepath.Join(root, "missing.json")
	var stdout, stderr bytes.Buffer
	code := run([]string{"fleet", "--org", "example", "--allow-remote-targets", "--config", missing, "--out", out}, &stdout, &stderr)
	if code != cli.ExitOperationalError || !bytes.Contains(stderr.Bytes(), []byte(missing)) {
		t.Fatalf("explicit missing config: code=%d stderr=%s", code, stderr.String())
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("explicit config unexpectedly created output: %v", err)
	}
}

func TestDefaultOrgConfigOnlyAppliesToOrgAndRejectsSymlinks(t *testing.T) {
	root := t.TempDir()
	for _, opts := range []*cli.Options{
		{TargetsPath: "targets.json", OutDir: filepath.Join(root, "targets")},
		{Repo: "org/repo", OutDir: filepath.Join(root, "repo")},
	} {
		if err := ensureFleetOrgConfig(opts); err != nil || opts.ConfigPath != "" {
			t.Fatalf("non-org config changed: %+v, %v", opts, err)
		}
		if _, err := os.Stat(opts.OutDir); !os.IsNotExist(err) {
			t.Fatalf("non-org output created: %v", err)
		}
	}
	operatorFile := filepath.Join(root, "operator.json")
	if err := os.WriteFile(operatorFile, []byte("operator-owned"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(operatorFile, filepath.Join(root, fleetDefaultConfigFilename)); err != nil {
		t.Fatal(err)
	}
	if err := ensureFleetOrgConfig(&cli.Options{Org: "example", OutDir: root}); err == nil {
		t.Fatal("symlink config accepted")
	}
	got, _ := os.ReadFile(operatorFile)
	if string(got) != "operator-owned" {
		t.Fatal("symlink target changed")
	}
}
