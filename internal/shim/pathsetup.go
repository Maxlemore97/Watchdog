package shim

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// pathSetupMarker is the sentinel line we write around the PATH export
// so the block can be located and rewritten or removed without
// touching surrounding user edits. The exact string is part of the
// on-disk contract — do not change it without a migration.
const pathSetupMarker = "# >>> watchdog shim PATH (managed) >>>"
const pathSetupMarkerEnd = "# <<< watchdog shim PATH (managed) <<<"

// ShellRC describes the user's interactive shell config target.
type ShellRC struct {
	Path  string // absolute path to the rc file (~/.zshrc, ~/.bashrc, ...)
	Shell string // "zsh", "bash", "fish"; "" if unknown
}

// DetectShellRC picks the rc file to edit. Order of preference:
//
//  1. $WATCHDOG_RC if set (escape hatch for users with custom layouts)
//  2. $SHELL basename → ~/.zshrc | ~/.bashrc | ~/.config/fish/config.fish
//  3. Walk a fallback list of common rc files and pick the first that
//     exists. This catches users whose $SHELL doesn't match their
//     interactive shell (e.g. tmux launching bash inside a zsh login).
//
// Returns ok=false on Windows — PATH there lives in the registry, not
// rc files, and a simple text append would not survive a reboot.
func DetectShellRC() (ShellRC, bool) {
	if runtime.GOOS == "windows" {
		return ShellRC{}, false
	}
	if v := os.Getenv("WATCHDOG_RC"); v != "" {
		return ShellRC{Path: v, Shell: shellFromPath(v)}, true
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ShellRC{}, false
	}
	switch filepath.Base(os.Getenv("SHELL")) {
	case "zsh":
		return ShellRC{Path: filepath.Join(home, ".zshrc"), Shell: "zsh"}, true
	case "bash":
		return ShellRC{Path: filepath.Join(home, ".bashrc"), Shell: "bash"}, true
	case "fish":
		return ShellRC{Path: filepath.Join(home, ".config", "fish", "config.fish"), Shell: "fish"}, true
	}
	for _, cand := range []struct {
		path  string
		shell string
	}{
		{filepath.Join(home, ".zshrc"), "zsh"},
		{filepath.Join(home, ".bashrc"), "bash"},
		{filepath.Join(home, ".bash_profile"), "bash"},
		{filepath.Join(home, ".profile"), "sh"},
		{filepath.Join(home, ".config", "fish", "config.fish"), "fish"},
	} {
		if _, err := os.Stat(cand.path); err == nil {
			return ShellRC{Path: cand.path, Shell: cand.shell}, true
		}
	}
	return ShellRC{}, false
}

func shellFromPath(p string) string {
	base := filepath.Base(p)
	switch {
	case strings.Contains(base, "zsh"):
		return "zsh"
	case strings.Contains(base, "bash"):
		return "bash"
	case strings.Contains(base, "fish"):
		return "fish"
	}
	return ""
}

// EnsurePathExport idempotently writes a managed block to rc that
// prepends shimDir to PATH. Returns added=true if the block was
// written or refreshed, added=false if rc already had a matching
// block. Errors propagate I/O failures only.
//
// The block is delimited by sentinel comments so a subsequent call
// can locate and rewrite it (e.g. after the user moves the shim
// directory) without disturbing the user's own additions to rc.
// Writing is atomic via a same-directory tempfile + rename, so a
// crash mid-write cannot corrupt the user's rc.
func EnsurePathExport(rc ShellRC, shimDir string) (bool, error) {
	if rc.Path == "" || shimDir == "" {
		return false, fmt.Errorf("rc path and shim dir are required")
	}

	block := renderBlock(rc.Shell, shimDir)

	existing, err := os.ReadFile(rc.Path)
	if err != nil && !os.IsNotExist(err) {
		return false, fmt.Errorf("read %s: %w", rc.Path, err)
	}

	updated, changed := spliceBlock(string(existing), block)
	if !changed {
		return false, nil
	}

	if err := os.MkdirAll(filepath.Dir(rc.Path), 0o755); err != nil {
		return false, fmt.Errorf("mkdir %s: %w", filepath.Dir(rc.Path), err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(rc.Path), ".watchdog-rc-*")
	if err != nil {
		return false, fmt.Errorf("tempfile: %w", err)
	}
	cleanup := tmp.Name()
	defer func() {
		if cleanup != "" {
			_ = os.Remove(cleanup)
		}
	}()
	if _, err := tmp.WriteString(updated); err != nil {
		tmp.Close()
		return false, fmt.Errorf("write: %w", err)
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return false, fmt.Errorf("chmod: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return false, fmt.Errorf("close: %w", err)
	}
	if err := os.Rename(tmp.Name(), rc.Path); err != nil {
		return false, fmt.Errorf("rename: %w", err)
	}
	cleanup = ""
	return true, nil
}

// RemovePathExport strips a previously-written managed block from rc.
// No-op if the block is absent. Used by `watchdog-shim uninstall` so
// uninstalling cleans up after itself.
func RemovePathExport(rc ShellRC) (bool, error) {
	if rc.Path == "" {
		return false, nil
	}
	existing, err := os.ReadFile(rc.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	updated, changed := spliceBlock(string(existing), "")
	if !changed {
		return false, nil
	}
	return true, os.WriteFile(rc.Path, []byte(updated), 0o644)
}

func renderBlock(shell, shimDir string) string {
	var line string
	switch shell {
	case "fish":
		line = fmt.Sprintf("fish_add_path --prepend %s", shimDir)
	default:
		line = fmt.Sprintf("export PATH=%q:$PATH", shimDir)
	}
	return pathSetupMarker + "\n" +
		"# Added by `watchdog-shim install --add-to-path`. To remove, run\n" +
		"# `watchdog-shim uninstall` or delete this block manually.\n" +
		line + "\n" +
		pathSetupMarkerEnd + "\n"
}

// spliceBlock returns the new rc contents with the managed block
// replaced (or removed if newBlock == ""). The second return value is
// true if the file content changed. If no existing marker is found
// and newBlock is non-empty, the block is appended.
func spliceBlock(existing, newBlock string) (string, bool) {
	startIdx := strings.Index(existing, pathSetupMarker)
	if startIdx < 0 {
		if newBlock == "" {
			return existing, false
		}
		sep := ""
		if len(existing) > 0 && !strings.HasSuffix(existing, "\n") {
			sep = "\n"
		}
		spacer := "\n"
		if existing == "" {
			spacer = ""
		}
		return existing + sep + spacer + newBlock, true
	}
	endMarker := pathSetupMarkerEnd
	endIdx := strings.Index(existing[startIdx:], endMarker)
	if endIdx < 0 {
		// Corrupted block — fall back to appending; preserve original.
		if newBlock == "" {
			return existing, false
		}
		sep := ""
		if !strings.HasSuffix(existing, "\n") {
			sep = "\n"
		}
		return existing + sep + newBlock, true
	}
	endAbs := startIdx + endIdx + len(endMarker)
	if endAbs < len(existing) && existing[endAbs] == '\n' {
		endAbs++
	}
	before := existing[:startIdx]
	after := existing[endAbs:]
	updated := before + newBlock + after
	if updated == existing {
		return existing, false
	}
	return updated, true
}