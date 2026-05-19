package shim

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestIsShimmed(t *testing.T) {
	for _, tool := range []string{"npm", "pip", "cargo", "gem", "composer"} {
		if !IsShimmed(tool) {
			t.Errorf("%q should be shimmed", tool)
		}
	}
	for _, tool := range []string{"ls", "git", "make", "node"} {
		if IsShimmed(tool) {
			t.Errorf("%q should NOT be shimmed", tool)
		}
	}
}

func TestDefaultShimmedTools_HasAllExpected(t *testing.T) {
	want := []string{
		"npm", "pnpm", "yarn", "bun",
		"pip", "pip3", "pipx", "uv", "poetry",
		"cargo", "gem", "composer",
		"brew", "go", "dotnet",
	}
	for _, w := range want {
		found := false
		for _, t2 := range DefaultShimmedTools {
			if t2 == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("DefaultShimmedTools missing %q", w)
		}
	}
}

func TestEffectiveShimmedTools_Defaults(t *testing.T) {
	got, err := EffectiveShimmedTools(nil, nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(got) != len(DefaultShimmedTools) {
		t.Errorf("default len=%d, want %d", len(got), len(DefaultShimmedTools))
	}
}

func TestEffectiveShimmedTools_SkipRemoves(t *testing.T) {
	got, err := EffectiveShimmedTools(nil, []string{"go", "brew"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	for _, name := range got {
		if name == "go" || name == "brew" {
			t.Errorf("%q should be skipped", name)
		}
	}
}

func TestEffectiveShimmedTools_AddIsIdempotent(t *testing.T) {
	// Adding a tool already in the default set is a no-op.
	got, err := EffectiveShimmedTools([]string{"npm"}, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	count := 0
	for _, name := range got {
		if name == "npm" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("npm appears %d times, want 1", count)
	}
}

func TestEffectiveShimmedTools_UnknownNameErrors(t *testing.T) {
	if _, err := EffectiveShimmedTools([]string{"not-a-real-pm"}, nil); err == nil {
		t.Errorf("expected error for unknown ADD entry")
	}
	if _, err := EffectiveShimmedTools(nil, []string{"also-unknown"}); err == nil {
		t.Errorf("expected error for unknown SKIP entry")
	}
}

func TestEffectiveShimmedTools_SkipBeatsAdd(t *testing.T) {
	got, err := EffectiveShimmedTools([]string{"brew"}, []string{"brew"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	for _, name := range got {
		if name == "brew" {
			t.Errorf("brew in both ADD and SKIP should be omitted, got %v", got)
		}
	}
}

func TestInstall_WritesWrappersWithMarker(t *testing.T) {
	tmp := t.TempDir()
	written, err := Install(InstallOpts{
		ShimDir:   tmp,
		ExecPath:  "/usr/local/bin/watchdog-shim-exec",
		Tools:     []string{"npm"},
		Overwrite: true,
	})
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if len(written) == 0 {
		t.Fatal("no wrappers written")
	}
	for _, p := range written {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		s := string(data)
		if !strings.Contains(s, "Watchdog shim") {
			t.Errorf("%s missing Watchdog marker", p)
		}
		if !strings.Contains(s, "/usr/local/bin/watchdog-shim-exec") {
			t.Errorf("%s missing exec path", p)
		}
	}
}

func TestInstall_NoOverwriteSkipsExisting(t *testing.T) {
	tmp := t.TempDir()
	// First pass writes the wrapper.
	_, err := Install(InstallOpts{
		ShimDir: tmp, ExecPath: "/exec", Tools: []string{"npm"}, Overwrite: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Mark with custom content.
	target := filepath.Join(tmp, "npm")
	if err := os.WriteFile(target, []byte("# Watchdog shim custom\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	written2, _ := Install(InstallOpts{
		ShimDir: tmp, ExecPath: "/exec", Tools: []string{"npm"}, Overwrite: false,
	})
	if len(written2) != 0 {
		t.Errorf("no-overwrite should not write; wrote %v", written2)
	}
	data, _ := os.ReadFile(target)
	if !strings.Contains(string(data), "custom") {
		t.Errorf("existing file overwritten: %q", data)
	}
}

func TestUninstall_OnlyRemovesWatchdogMarked(t *testing.T) {
	tmp := t.TempDir()
	// Install a real wrapper.
	_, _ = Install(InstallOpts{
		ShimDir: tmp, ExecPath: "/x", Tools: []string{"npm"}, Overwrite: true,
	})
	// Plant a foreign binary at the same path as another tool.
	foreign := filepath.Join(tmp, "pip")
	if err := os.WriteFile(foreign, []byte("#!/bin/sh\necho user-script\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	removed, err := Uninstall(InstallOpts{ShimDir: tmp, Tools: []string{"npm", "pip"}})
	if err != nil {
		t.Fatal(err)
	}
	// npm wrapper removed; pip foreign script untouched.
	for _, r := range removed {
		if filepath.Base(r) == "pip" {
			t.Errorf("uninstall removed user-authored pip: %s", r)
		}
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Errorf("user-authored pip file should still exist")
	}
	if _, err := os.Stat(filepath.Join(tmp, "npm")); err == nil {
		t.Errorf("npm wrapper should be removed")
	}
}

func TestStatus(t *testing.T) {
	tmp := t.TempDir()
	_, _ = Install(InstallOpts{
		ShimDir: tmp, ExecPath: "/x", Tools: []string{"npm", "pip"}, Overwrite: true,
	})
	st := Status(InstallOpts{ShimDir: tmp})
	if !st["npm"] || !st["pip"] {
		t.Errorf("installed tools should report ok: %v", st)
	}
	if st["cargo"] {
		t.Errorf("uninstalled cargo should report false")
	}
}

func TestFindRealBinary_ExcludesShimDir(t *testing.T) {
	shimDir := t.TempDir()
	realDir := t.TempDir()
	// Plant a shim and a real binary, both called `npm`.
	shimPath := filepath.Join(shimDir, "npm")
	if err := os.WriteFile(shimPath, []byte("#!/bin/sh\necho shim"), 0o755); err != nil {
		t.Fatal(err)
	}
	realPath := filepath.Join(realDir, "npm")
	if err := os.WriteFile(realPath, []byte("#!/bin/sh\necho real"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", shimDir+string(os.PathListSeparator)+realDir)
	got := FindRealBinary("npm", []string{shimDir})
	want, _ := filepath.Abs(realPath)
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestFindRealBinary_ReturnsEmptyWhenNoneFound(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if got := FindRealBinary("nonexistent-tool-xyz", nil); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

// TestIsShimDirFirstOnPath_FirstWhenPrepended pins the doctor-style
// PATH check: when the shim dir is the first PATH entry, install
// commands hit the wrapper. Anything else means installs may bypass
// scanning — the shim-exec dispatcher warns on a TTY in that case.
func TestIsShimDirFirstOnPath_FirstWhenPrepended(t *testing.T) {
	shimDir := t.TempDir()
	other := t.TempDir()
	t.Setenv("PATH", shimDir+string(os.PathListSeparator)+other)
	if !IsShimDirFirstOnPath(shimDir) {
		t.Errorf("shim dir at front of PATH not detected")
	}
}

func TestIsShimDirFirstOnPath_NotFirstWhenAppended(t *testing.T) {
	shimDir := t.TempDir()
	other := t.TempDir()
	t.Setenv("PATH", other+string(os.PathListSeparator)+shimDir)
	if IsShimDirFirstOnPath(shimDir) {
		t.Errorf("shim dir mid-PATH must NOT be reported as first")
	}
}

// TestFindRealBinary_StillResolvesWhenShimNotFirst verifies the
// dispatcher locates the real binary even when the shim dir is not
// the first PATH entry. Hot-path for the "user forgot to prepend"
// misconfig: resolution must still succeed; only the PATH-order
// warning fires elsewhere.
func TestFindRealBinary_StillResolvesWhenShimNotFirst(t *testing.T) {
	realDir := t.TempDir()
	shimDir := t.TempDir()
	realPath := filepath.Join(realDir, "npm")
	if err := os.WriteFile(realPath, []byte("#!/bin/sh\necho real"), 0o755); err != nil {
		t.Fatal(err)
	}
	shimPath := filepath.Join(shimDir, "npm")
	if err := os.WriteFile(shimPath, []byte("#!/bin/sh\necho shim"), 0o755); err != nil {
		t.Fatal(err)
	}
	// realDir first, shimDir second — opposite of the intended order.
	t.Setenv("PATH", realDir+string(os.PathListSeparator)+shimDir)
	got := FindRealBinary("npm", []string{shimDir})
	want, _ := filepath.Abs(realPath)
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestWindowsWrapperOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific")
	}
	tmp := t.TempDir()
	written, err := Install(InstallOpts{
		ShimDir: tmp, ExecPath: "C:\\watchdog\\watchdog-shim-exec.exe",
		Tools: []string{"npm"}, Overwrite: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	hasCmd := false
	for _, p := range written {
		if filepath.Ext(p) == ".cmd" {
			hasCmd = true
		}
	}
	if !hasCmd {
		t.Error("Windows install should write .cmd wrapper")
	}
}
