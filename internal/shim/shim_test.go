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

func TestShimmedTools_HasAllExpected(t *testing.T) {
	want := []string{"npm", "pnpm", "yarn", "pip", "pip3", "uv", "poetry", "cargo", "gem", "composer"}
	for _, w := range want {
		found := false
		for _, t2 := range ShimmedTools {
			if t2 == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("ShimmedTools missing %q", w)
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
