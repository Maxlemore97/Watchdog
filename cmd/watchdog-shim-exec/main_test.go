//go:build !windows

// Smoke tests for the per-call shim dispatcher. POSIX-only because
// the tests need a fake "real" binary that absorbs argv and prints a
// recognisable line; on Windows the dispatcher uses exec.Command
// against an actual PE binary and the test scaffolding diverges.
package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func buildBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "watchdog-shim-exec")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("build: %v", err)
	}
	return bin
}

// makeRealBin writes a fake "real" package-manager binary that prints
// REAL-RAN <name> <args...> to stdout and exits 0. The dispatcher
// should execv it on allow.
func makeRealBin(t *testing.T, dir, name string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	script := `#!/bin/sh
printf 'REAL-RAN %s' "$0" >&2
printf ' %s' "$@" >&2
printf '\n' >&2
echo OK
exit 0
`
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func runShim(t *testing.T, bin string, args []string, env ...string) (string, string, int) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		}
	}
	return stdout.String(), stderr.String(), code
}

// ---------- pass-through cases --------------------------------------

func TestShimExec_MissingToolNameReturnsErr(t *testing.T) {
	bin := buildBinary(t)
	_, stderr, code := runShim(t, bin, nil)
	if code != 2 {
		t.Errorf("exit = %d", code)
	}
	if !strings.Contains(stderr, "missing tool name") {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestShimExec_NonInstallCommandPassesThrough(t *testing.T) {
	bin := buildBinary(t)
	shimDir := t.TempDir()
	realDir := t.TempDir()
	makeRealBin(t, realDir, "npm")
	stdout, stderr, code := runShim(t, bin,
		[]string{"npm", "test"},
		"PATH="+shimDir+string(os.PathListSeparator)+realDir+":/bin:/usr/bin",
		"WATCHDOG_SHIM_DIR="+shimDir,
		"WATCHDOG_CACHE_DIR="+t.TempDir(),
	)
	if code != 0 {
		t.Errorf("exit = %d, stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, "OK") {
		t.Errorf("real binary did not run: stdout=%q stderr=%q", stdout, stderr)
	}
	if !strings.Contains(stderr, "REAL-RAN") {
		t.Errorf("real binary marker missing: %q", stderr)
	}
}

func TestShimExec_UnknownBinaryPassesThrough(t *testing.T) {
	// `cat` is shimmed? No — not in DefaultShimmedTools. So non-shimmed
	// binaries must pass through even when invoked.
	bin := buildBinary(t)
	realDir := t.TempDir()
	makeRealBin(t, realDir, "git")
	stdout, _, code := runShim(t, bin,
		[]string{"git", "status"},
		"PATH="+realDir+":/bin:/usr/bin",
		"WATCHDOG_CACHE_DIR="+t.TempDir(),
	)
	if code != 0 {
		t.Errorf("exit = %d", code)
	}
	if !strings.Contains(stdout, "OK") {
		t.Errorf("git fake did not run: %q", stdout)
	}
}

func TestShimExec_DisabledExecsReal(t *testing.T) {
	bin := buildBinary(t)
	realDir := t.TempDir()
	makeRealBin(t, realDir, "npm")
	stdout, _, code := runShim(t, bin,
		[]string{"npm", "install", "lodash"},
		"PATH="+realDir+":/bin:/usr/bin",
		"WATCHDOG_DISABLE=1",
		"WATCHDOG_CACHE_DIR="+t.TempDir(),
	)
	if code != 0 {
		t.Errorf("exit = %d", code)
	}
	if !strings.Contains(stdout, "OK") {
		t.Errorf("disabled flag should pass through to real binary: %q", stdout)
	}
}

// ---------- deny path ----------------------------------------------

func TestShimExec_DenyExits1WithoutExec(t *testing.T) {
	bin := buildBinary(t)
	realDir := t.TempDir()
	makeRealBin(t, realDir, "npm")
	// WATCHDOG_FAILCLOSED_VERDICT=deny forces deny when OSV is
	// unreachable. PATH excludes any LLM CLI; WATCHDOG_RESOLVE_LATEST=0
	// avoids the registry latest-version call; an unreachable OSV
	// endpoint pushes the fail-closed path.
	closedSrv := newClosedServer(t)
	stdout, stderr, code := runShim(t, bin,
		[]string{"npm", "install", "lodash"},
		"PATH="+realDir+":/bin:/usr/bin",
		"WATCHDOG_MODE=osv",
		"WATCHDOG_FAILCLOSED_VERDICT=deny",
		"WATCHDOG_RESOLVE_LATEST=0",
		"WATCHDOG_OSV_ENDPOINT="+closedSrv,
		"WATCHDOG_CACHE_DIR="+t.TempDir(),
	)
	if code == 0 {
		t.Errorf("expected deny exit 1, got 0; stdout=%q stderr=%q", stdout, stderr)
	}
	if strings.Contains(stdout, "OK") {
		t.Error("real binary should NOT have run on deny")
	}
	if !strings.Contains(stderr, "watchdog: blocked install") {
		t.Errorf("expected deny diagnostic, got stderr=%q", stderr)
	}
}

// ---------- allow path: OSV clean ----------------------------------

func TestShimExec_AllowExecsReal(t *testing.T) {
	bin := buildBinary(t)
	realDir := t.TempDir()
	makeRealBin(t, realDir, "npm")
	// OSV returns no vulns; LLM mode=osv so analyzer is skipped. The
	// dispatcher should exec the real binary.
	cleanSrv := newCleanOSVServer(t)
	defer cleanSrv.Close()
	stdout, _, code := runShim(t, bin,
		[]string{"npm", "install", "lodash"},
		"PATH="+realDir+":/bin:/usr/bin",
		"WATCHDOG_MODE=osv",
		"WATCHDOG_RESOLVE_LATEST=0",
		"WATCHDOG_OSV_ENDPOINT="+cleanSrv.URL,
		"WATCHDOG_CACHE_DIR="+t.TempDir(),
	)
	if code != 0 {
		t.Errorf("expected allow exit 0, got %d", code)
	}
	if !strings.Contains(stdout, "OK") {
		t.Errorf("real binary should have run on allow: %q", stdout)
	}
}
