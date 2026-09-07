package fleet

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/mod/modfile"
)

// RepositoryKind describes what bounded repository discovery found before
// fleet starts any analyzer subprocess. It deliberately describes repository
// shape, not analyzer success: Status and Complete remain the processing and
// evidence-coverage signals respectively.
type RepositoryKind string

const (
	RepositoryNoGo        RepositoryKind = "no-go"
	RepositoryGoNoModule  RepositoryKind = "go-no-module"
	RepositoryGoModule    RepositoryKind = "go-module"
	RepositoryMultiModule RepositoryKind = "multi-module"
)

// These limits bound repository inventory independently of the analyzer's
// own output limits. WalkDir never follows directory symlinks; the counters
// also stop a hostile checkout from turning discovery into unbounded work.
const (
	maxDiscoveryDirectories       = 50_000
	maxDiscoveryFiles             = 250_000
	maxDiscoveryBytes       int64 = 2 << 30
)

type moduleRoot struct {
	ID         string
	RelPath    string
	ModulePath string
	AbsPath    string
	UsesGin    bool
}

type repositoryDiscovery struct {
	Kind        RepositoryKind
	Modules     []moduleRoot
	GoFiles     int
	Directories int
	Files       int
	Bytes       int64
	HasGoWork   bool
	Fingerprint string
}

var ignoredDiscoveryDirectories = map[string]bool{
	".git": true, ".hg": true, ".svn": true,
	".gin-recon": true,
}

func discoverRepository(root string) (repositoryDiscovery, error) {
	return discoverRepositoryContext(context.Background(), root)
}

func discoverRepositoryContext(ctx context.Context, root string) (repositoryDiscovery, error) {
	var found repositoryDiscovery
	sourceHash := sha256.New()
	var workFiles []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if walkErr != nil {
			return walkErr
		}
		if path != root && entry.IsDir() && ignoredDiscoveryDirectories[entry.Name()] {
			return filepath.SkipDir
		}
		if entry.Type()&os.ModeSymlink != 0 {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			found.Directories++
			if found.Directories > maxDiscoveryDirectories {
				return fmt.Errorf("repository contains more than %d directories", maxDiscoveryDirectories)
			}
			return nil
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		found.Files++
		if found.Files > maxDiscoveryFiles {
			return fmt.Errorf("repository contains more than %d files", maxDiscoveryFiles)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		found.Bytes += info.Size()
		if found.Bytes > maxDiscoveryBytes {
			return fmt.Errorf("repository contains more than %d bytes", maxDiscoveryBytes)
		}
		dependencyTree := isDependencyTree(root, path)
		if isSourceIdentityFile(entry.Name()) && !isNodeModulesTree(root, path) {
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			fileHash := sha256.New()
			written, copyErr := io.Copy(fileHash, io.LimitReader(file, maxDiscoveryBytes+1))
			closeErr := file.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
			if written > maxDiscoveryBytes {
				return fmt.Errorf("source identity file %s exceeds %d bytes", path, maxDiscoveryBytes)
			}
			fmt.Fprintf(sourceHash, "%s\x00%d\x00%s\n", filepath.ToSlash(rel), written, hex.EncodeToString(fileHash.Sum(nil)))
		}

		switch entry.Name() {
		case "go.work":
			if dependencyTree {
				break
			}
			found.HasGoWork = true
			workFiles = append(workFiles, path)
		case "go.mod":
			if dependencyTree {
				break
			}
			relDir, err := filepath.Rel(root, filepath.Dir(path))
			if err != nil {
				return err
			}
			relDir = filepath.ToSlash(relDir)
			if relDir == "" {
				relDir = "."
			}
			modulePath, usesGin, err := readModuleDeclaration(path)
			if err != nil {
				return fmt.Errorf("%s: %w", filepath.ToSlash(path), err)
			}
			found.Modules = append(found.Modules, moduleRoot{
				ID: stableModuleID(relDir), RelPath: relDir,
				ModulePath: modulePath, AbsPath: filepath.Dir(path), UsesGin: usesGin,
			})
		default:
			if !dependencyTree && strings.HasSuffix(entry.Name(), ".go") {
				found.GoFiles++
			}
		}
		return nil
	})
	if err != nil {
		return found, fmt.Errorf("bounded repository discovery under %s: %w", root, err)
	}
	found.Fingerprint = hex.EncodeToString(sourceHash.Sum(nil))
	if err := validateWorkspaceUses(root, workFiles, found.Modules); err != nil {
		return found, fmt.Errorf("bounded repository discovery under %s: %w", root, err)
	}

	sort.Slice(found.Modules, func(i, j int) bool { return found.Modules[i].RelPath < found.Modules[j].RelPath })
	switch len(found.Modules) {
	case 0:
		if found.GoFiles == 0 {
			found.Kind = RepositoryNoGo
		} else {
			found.Kind = RepositoryGoNoModule
		}
	case 1:
		found.Kind = RepositoryGoModule
	default:
		found.Kind = RepositoryMultiModule
	}
	return found, nil
}

func validateWorkspaceUses(root string, workFiles []string, modules []moduleRoot) error {
	discovered := make(map[string]bool, len(modules))
	for _, module := range modules {
		discovered[filepath.Clean(module.AbsPath)] = true
	}
	cleanRoot, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	for _, workPath := range workFiles {
		data, err := ReadBoundedFile(workPath)
		if err != nil {
			return fmt.Errorf("reading %s: %w", filepath.ToSlash(workPath), err)
		}
		work, err := modfile.ParseWork(workPath, data, nil)
		if err != nil {
			return fmt.Errorf("parsing %s: %w", filepath.ToSlash(workPath), err)
		}
		for _, use := range work.Use {
			moduleDir := use.Path
			if !filepath.IsAbs(moduleDir) {
				moduleDir = filepath.Join(filepath.Dir(workPath), moduleDir)
			}
			moduleDir, err = filepath.Abs(moduleDir)
			if err != nil {
				return err
			}
			moduleDir = filepath.Clean(moduleDir)
			rel, err := filepath.Rel(cleanRoot, moduleDir)
			if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				return fmt.Errorf("%s use %q escapes the repository", filepath.ToSlash(workPath), use.Path)
			}
			if !discovered[moduleDir] {
				return fmt.Errorf("%s use %q does not name a discovered module", filepath.ToSlash(workPath), use.Path)
			}
		}
	}
	return nil
}

func readModuleDeclaration(goModPath string) (string, bool, error) {
	data, err := os.ReadFile(goModPath)
	if err != nil {
		return "", false, fmt.Errorf("reading go.mod: %w", err)
	}
	parsed, err := modfile.ParseLax(goModPath, data, nil)
	if err != nil {
		return "", false, fmt.Errorf("parsing go.mod: %w", err)
	}
	if parsed.Module == nil || strings.TrimSpace(parsed.Module.Mod.Path) == "" {
		return "", false, fmt.Errorf("go.mod has no module directive")
	}
	usesGin := false
	for _, requirement := range parsed.Require {
		if requirement.Mod.Path == "github.com/gin-gonic/gin" {
			usesGin = true
			break
		}
	}
	return parsed.Module.Mod.Path, usesGin, nil
}

func isSourceIdentityFile(name string) bool {
	ext := filepath.Ext(name)
	return ext == ".go" || ext == ".c" || ext == ".h" || ext == ".s" || ext == ".S" || ext == ".syso" ||
		name == "go.mod" || name == "go.sum" || name == "go.work" || name == "go.work.sum" ||
		name == "modules.txt" || name == ".gin-reconignore" || name == targetConfigFilename
}

func isDependencyTree(root, path string) bool {
	return pathHasComponent(root, path, "vendor") || isNodeModulesTree(root, path)
}

func isNodeModulesTree(root, path string) bool {
	return pathHasComponent(root, path, "node_modules")
}

func pathHasComponent(root, path, component string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	for _, part := range strings.Split(filepath.Clean(rel), string(filepath.Separator)) {
		if part == component {
			return true
		}
	}
	return false
}

func stableModuleID(relPath string) string {
	if relPath == "." {
		return "root"
	}
	sum := sha256.Sum256([]byte(filepath.ToSlash(relPath)))
	return "module-" + hex.EncodeToString(sum[:8])
}

// ValidModuleID validates the stable, path-safe identifier emitted by
// repository discovery. Fleet render treats a saved aggregate as untrusted
// input, so it must validate IDs before using them as directory components.
func ValidModuleID(id string) error {
	if id == "root" {
		return nil
	}
	const prefix = "module-"
	if !strings.HasPrefix(id, prefix) || len(id) != len(prefix)+16 {
		return fmt.Errorf("invalid module id %q", id)
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(id, prefix)); err != nil {
		return fmt.Errorf("invalid module id %q", id)
	}
	return nil
}
