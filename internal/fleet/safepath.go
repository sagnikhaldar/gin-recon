package fleet

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/sagnikhaldar/gin-recon/internal/config"
)

// SafeTargetDir resolves root/"targets"/name for a target Name sourced from
// untrusted fleet.json data (a --baseline file or a render --report file —
// see ValidTargetName's doc comment for why those two skip the validation a
// hand-written manifest or --org discovery already get). First rejects name
// via ValidTargetName's character allowlist, then confirms the cleaned,
// joined result is still exactly root/targets/name — belt-and-suspenders
// against a path oddity the allowlist didn't anticipate, not a substitute
// for it. docs/threat-model.md treats every scanned-repo/report input as
// adversarial; an external fleet.json is no exception.
func SafeTargetDir(root, name string) (string, error) {
	if err := ValidTargetName(name); err != nil {
		return "", err
	}
	base := filepath.Join(root, "targets")
	dir := filepath.Join(base, name)
	rel, err := filepath.Rel(base, dir)
	if err != nil || rel != name {
		return "", fmt.Errorf("fleet: target name %q escapes the targets directory", name)
	}
	return dir, nil
}

// ReadBoundedFile reads path for an external, untrusted gin-recon artifact —
// a --baseline file (LoadBaseline) or a render --report file (cmd/gin-recon's
// runRender/runFleetRender). Rejects a symlink or non-regular file outright
// (RegularFileNoSymlink), and refuses anything larger than
// config.HardCapMaxOutputBytes — the same ceiling gin-recon itself already
// enforces on what it will ever legitimately write as one of its own
// reports, so a file claiming to be one but larger than that is refused
// before it is ever read fully into memory.
func ReadBoundedFile(path string) ([]byte, error) {
	if err := RegularFileNoSymlink(path); err != nil {
		return nil, err
	}
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Size() > config.HardCapMaxOutputBytes {
		return nil, fmt.Errorf("%s is %d bytes, exceeding the %d byte limit for a gin-recon artifact", path, fi.Size(), config.HardCapMaxOutputBytes)
	}
	return os.ReadFile(path)
}

// RegularFileNoSymlink lstat's path and rejects anything but a plain regular
// file — a symlink (which could point outside the intended output root
// entirely) or a device/fifo/socket, either planted ahead of time at a path
// this target's own name resolves to. Never follows the symlink to check
// what it points to; Lstat alone is enough to refuse it outright.
func RegularFileNoSymlink(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink, refusing to follow it", path)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	return nil
}
