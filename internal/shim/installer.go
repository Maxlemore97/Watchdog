package shim

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// InstallOpts tweaks an install call.
type InstallOpts struct {
	ShimDir   string // empty → DefaultShimDir
	ExecPath  string // path baked into the wrapper; empty → resolve `watchdog-shim-exec` on PATH or fall back to "watchdog-shim-exec"
	Tools     []string
	Overwrite bool
}

func (o InstallOpts) dir() string {
	if o.ShimDir != "" {
		return o.ShimDir
	}
	return DefaultShimDir()
}

func (o InstallOpts) tools() []string {
	if len(o.Tools) > 0 {
		return o.Tools
	}
	tools, err := EffectiveShimmedToolsFromEnv()
	if err != nil {
		return DefaultShimmedTools
	}
	return tools
}

func (o InstallOpts) execPath() string {
	if o.ExecPath != "" {
		return o.ExecPath
	}
	if p, err := os.Executable(); err == nil {
		// Default to the sibling `watchdog-shim-exec` binary next to
		// the watchdog-shim binary the user just invoked.
		bin := "watchdog-shim-exec"
		if runtime.GOOS == "windows" {
			bin += ".exe"
		}
		sibling := filepath.Join(filepath.Dir(p), bin)
		if _, err := os.Stat(sibling); err == nil {
			return sibling
		}
	}
	return "watchdog-shim-exec"
}

// Install writes wrapper scripts for every tool. Returns list of
// written paths.
func Install(opts InstallOpts) ([]string, error) {
	dir := opts.dir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	exec := opts.execPath()
	var written []string
	for _, tool := range opts.tools() {
		paths := wrapperPaths(dir, tool)
		for _, p := range paths {
			if _, err := os.Stat(p); err == nil && !opts.Overwrite {
				continue
			}
			content := renderWrapper(p, tool, exec)
			if err := os.WriteFile(p, []byte(content), 0o755); err != nil {
				return written, fmt.Errorf("write %s: %w", p, err)
			}
			written = append(written, p)
		}
	}
	return written, nil
}

// Uninstall removes Watchdog-authored wrappers. Walks the shim dir
// and deletes every file bearing the "Watchdog shim" marker — files
// without the marker (user-authored binaries) are left alone. This
// shape is orphan-safe: if a tool was previously shimmed but is no
// longer in the effective set (e.g. operator added WATCHDOG_SHIMMED
// _TOOLS_SKIP=go after install), its wrapper is still cleaned up.
func Uninstall(opts InstallOpts) ([]string, error) {
	dir := opts.dir()
	if _, err := os.Stat(dir); err != nil {
		return nil, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var removed []string
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		p := filepath.Join(dir, ent.Name())
		head, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		snippet := string(head)
		if len(snippet) > 400 {
			snippet = snippet[:400]
		}
		if !strings.Contains(snippet, "Watchdog shim") {
			continue
		}
		if err := os.Remove(p); err != nil {
			continue
		}
		removed = append(removed, p)
	}
	return removed, nil
}

// Status returns {tool: installed}.
func Status(opts InstallOpts) map[string]bool {
	dir := opts.dir()
	out := map[string]bool{}
	for _, tool := range opts.tools() {
		installed := false
		for _, p := range wrapperPaths(dir, tool) {
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				installed = true
				break
			}
		}
		out[tool] = installed
	}
	return out
}

// wrapperPaths returns one wrapper path on Unix and a .cmd
// counterpart on Windows. Both forms are written on Windows so cmd.exe
// finds the wrapper; the POSIX form remains useful for Git Bash users.
func wrapperPaths(dir, tool string) []string {
	if runtime.GOOS == "windows" {
		return []string{
			filepath.Join(dir, tool),
			filepath.Join(dir, tool+".cmd"),
		}
	}
	return []string{filepath.Join(dir, tool)}
}

func renderWrapper(path, tool, execBin string) string {
	if strings.HasSuffix(path, ".cmd") {
		return fmt.Sprintf(WindowsWrapperTemplate, tool, execBin, tool)
	}
	return fmt.Sprintf(PosixWrapperTemplate, tool, execBin, tool)
}
