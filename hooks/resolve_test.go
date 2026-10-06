package hooks_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// runResolve sources lib/resolve.sh in a hermetic bash and runs snippet.
func runResolve(t *testing.T, home, snippet string, env ...string) (string, error) {
	t.Helper()
	lib, _ := filepath.Abs(filepath.Join("lib", "resolve.sh"))
	cmd := exec.Command("bash", "-c", ". \"$1\"; "+snippet, "bash", lib)
	cmd.Env = append([]string{"HOME=" + home, "PATH=/usr/bin:/bin:/usr/sbin:/sbin"}, env...)
	out, err := cmd.Output()
	return strings.TrimSpace(string(out)), err
}

func requireBash(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("bash hook library")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}
}

// A binary planted earlier in the search order must be skipped when
// its hash differs from the manifest; the genuine one is used.
func TestResolveWatchdogBin_SkipsBinaryWithWrongHash(t *testing.T) {
	requireBash(t)
	home := t.TempDir()
	planted := filepath.Join(home, "planted")
	genuine := filepath.Join(home, ".watchdog", "bin")
	for _, d := range []string{planted, genuine} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	fake := []byte("#!/bin/sh\necho fake\n")
	real := []byte("#!/bin/sh\necho real\n")
	if err := os.WriteFile(filepath.Join(planted, "watchdog-prompt"), fake, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(genuine, "watchdog-prompt"), real, 0o755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(real)
	manifest, _ := json.Marshal(map[string]any{
		"binaries": map[string]string{"watchdog-prompt": hex.EncodeToString(sum[:])},
	})
	if err := os.WriteFile(filepath.Join(home, ".watchdog", "manifest.json"), manifest, 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := runResolve(t, home, "resolve_watchdog_bin watchdog-prompt", "WATCHDOG_INSTALL_DIR="+planted)
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if got != filepath.Join(genuine, "watchdog-prompt") {
		t.Errorf("resolved %q, want the manifest-matching binary in %s", got, genuine)
	}

	// Only the planted binary present → nothing resolves, so the
	// wrapper falls into its tamper fallback.
	if err := os.Remove(filepath.Join(genuine, "watchdog-prompt")); err != nil {
		t.Fatal(err)
	}
	if got, err := runResolve(t, home, "resolve_watchdog_bin watchdog-prompt", "WATCHDOG_INSTALL_DIR="+planted); err == nil {
		t.Errorf("planted binary resolved: %q", got)
	}
}

// The key path is data: it must never be evaluated as Python.
func TestExtractJSONField_KeyPathIsData(t *testing.T) {
	requireBash(t)
	home := t.TempDir()
	got, err := runResolve(t, home, `extract_json_field '{"tool_input":{"command":"npm i x"}}' tool_input.command`)
	if err != nil || got != "npm i x" {
		t.Errorf("nested lookup = %q, %v", got, err)
	}
	marker := filepath.Join(home, "pwned")
	inj := `__import__('os').system('touch ` + marker + `')`
	_, _ = runResolve(t, home, `extract_json_field '{}' "$KEY"`, "KEY="+inj)
	if _, err := os.Stat(marker); err == nil {
		t.Error("key path was executed as code")
	}
}
