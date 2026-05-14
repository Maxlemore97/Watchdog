package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func buildBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "watchdog-session")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("build: %v", err)
	}
	return bin
}

func runBinary(t *testing.T, bin string, env ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(bin)
	cmd.Stdin = strings.NewReader("{}")
	cmd.Env = append(os.Environ(), env...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("run: %v", err)
		}
	}
	return stdout.String(), code
}

func TestSession_DisabledSilent(t *testing.T) {
	bin := buildBinary(t)
	out, code := runBinary(t, bin, "WATCHDOG_DISABLE=1")
	if out != "" {
		t.Errorf("disabled should pass through silently, got %q", out)
	}
	if code != 0 {
		t.Errorf("disabled should exit 0, got %d", code)
	}
}

func TestSession_NoPluginsSilent(t *testing.T) {
	bin := buildBinary(t)
	out, code := runBinary(t, bin,
		"WATCHDOG_PLUGIN_DIRS="+t.TempDir(), // empty dir
		"CLAUDE_PLUGINS_DIR=",
		"WATCHDOG_CACHE_DIR="+t.TempDir(),
	)
	if out != "" {
		t.Errorf("no plugins should pass through silently, got %q", out)
	}
	if code != 0 {
		t.Errorf("exit %d", code)
	}
}

func TestSession_FindingsEmitSessionContext(t *testing.T) {
	bin := buildBinary(t)
	pluginsDir := t.TempDir()
	plug := filepath.Join(pluginsDir, "alpha")
	if err := os.MkdirAll(filepath.Join(plug, ".claude-plugin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(plug, ".claude-plugin", "plugin.json"),
		[]byte(`{"name":"alpha","version":"0.1"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(plug, "hooks"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(plug, "hooks", "demo.sh"), []byte("echo hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Point the analyzer at a cache dir but mark no provider on PATH
	// (clear PATH) so AnalyzeLocalPlugin returns the ask-fallback
	// instead of trying to actually invoke a CLI.
	out, code := runBinary(t, bin,
		"WATCHDOG_PLUGIN_DIRS="+pluginsDir,
		"CLAUDE_PLUGINS_DIR=",
		"WATCHDOG_CACHE_DIR="+t.TempDir(),
		"PATH=", // no CLI available
	)
	if code != 0 {
		t.Errorf("exit %d", code)
	}
	if out == "" {
		t.Fatal("expected SessionStart context output")
	}
	var resp map[string]any
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("not JSON: %v (%q)", err, out)
	}
	hso, ok := resp["hookSpecificOutput"].(map[string]any)
	if !ok {
		t.Fatalf("missing hookSpecificOutput: %v", resp)
	}
	if hso["hookEventName"] != "SessionStart" {
		t.Errorf("wrong event: %v", hso["hookEventName"])
	}
	ctx, _ := hso["additionalContext"].(string)
	if !strings.Contains(ctx, "alpha") {
		t.Errorf("context missing plugin name: %q", ctx)
	}
}
