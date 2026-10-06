package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Maxlemore97/watchdog/internal/testenv"
)

// buildBinary compiles watchdog-pretool into a tmpdir and returns its
// path. Other tests in this file reuse it via package-level sync.
// Appends .exe on Windows so exec.Command can resolve the binary.
func buildBinary(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	name := "watchdog-pretool"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	bin := filepath.Join(tmp, name)
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("build: %v", err)
	}
	return bin
}

// runBinary feeds stdin to the built binary and returns stdout.
func runBinary(t *testing.T, bin, stdin string, env ...string) string {
	t.Helper()
	cmd := exec.Command(bin)
	cmd.Stdin = strings.NewReader(stdin)
	cmd.Env = testenv.Hermetic(t, env...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("run: %v", err)
	}
	return stdout.String()
}

func TestPretool_NonBashPassthrough(t *testing.T) {
	bin := buildBinary(t)
	payload := `{"tool_name":"Read","tool_input":{"command":"x"}}`
	out := runBinary(t, bin, payload, "WATCHDOG_DISABLE=0")
	if out != "" {
		t.Errorf("non-Bash should pass through silently, got %q", out)
	}
}

func TestPretool_EmptyCommandPassthrough(t *testing.T) {
	bin := buildBinary(t)
	payload := `{"tool_name":"Bash","tool_input":{"command":""}}`
	out := runBinary(t, bin, payload)
	if out != "" {
		t.Errorf("empty command should pass through silently, got %q", out)
	}
}

func TestPretool_NonInstallPassthrough(t *testing.T) {
	bin := buildBinary(t)
	payload := `{"tool_name":"Bash","tool_input":{"command":"ls -la"}}`
	out := runBinary(t, bin, payload)
	if out != "" {
		t.Errorf("non-install should pass through silently, got %q", out)
	}
}

func TestPretool_MalformedStdinSilent(t *testing.T) {
	bin := buildBinary(t)
	out := runBinary(t, bin, "not json{{{")
	if out != "" {
		t.Errorf("malformed stdin should pass through silently, got %q", out)
	}
}

func TestPretool_DisabledEnvSilent(t *testing.T) {
	bin := buildBinary(t)
	payload := `{"tool_name":"Bash","tool_input":{"command":"npm install lodash"}}`
	out := runBinary(t, bin, payload, "WATCHDOG_DISABLE=1")
	if out != "" {
		t.Errorf("WATCHDOG_DISABLE should pass through silently, got %q", out)
	}
}

func TestPretool_InstallProducesHookDecision(t *testing.T) {
	bin := buildBinary(t)
	// Use mode=osv with WATCHDOG_RESOLVE_LATEST=0 so we skip the
	// registry HTTP call. The OSV query itself will fail without
	// network; failclosed_verdict=allow keeps the test self-contained.
	payload := `{"tool_name":"Bash","tool_input":{"command":"npm install some-deliberately-fake-package-xyz-9q"}}`
	out := runBinary(t, bin, payload,
		"WATCHDOG_MODE=osv",
		"WATCHDOG_RESOLVE_LATEST=0",
		"WATCHDOG_FAILCLOSED_VERDICT=allow",
		"WATCHDOG_CACHE_DIR="+t.TempDir(),
	)
	if out == "" {
		t.Fatal("expected hook decision JSON, got empty")
	}
	var resp map[string]any
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("not JSON: %v (%q)", err, out)
	}
	hso, ok := resp["hookSpecificOutput"].(map[string]any)
	if !ok {
		t.Fatalf("missing hookSpecificOutput: %v", resp)
	}
	if hso["hookEventName"] != "PreToolUse" {
		t.Errorf("wrong event: %v", hso["hookEventName"])
	}
	decision, _ := hso["permissionDecision"].(string)
	if decision != "allow" && decision != "ask" && decision != "deny" {
		t.Errorf("unexpected decision %q", decision)
	}
	reason, _ := hso["permissionDecisionReason"].(string)
	if !strings.HasPrefix(reason, "watchdog:") {
		t.Errorf("reason missing watchdog prefix: %q", reason)
	}
}

func decisionOf(t *testing.T, out string) string {
	t.Helper()
	if out == "" {
		return ""
	}
	var resp struct {
		HookSpecificOutput map[string]any `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("not JSON: %v (%q)", err, out)
	}
	d, _ := resp.HookSpecificOutput["permissionDecision"].(string)
	return d
}

// Edit/Write never pass through Bash, so the pretool hook must gate
// writes to Watchdog's own state and to agent hook/MCP configs itself.
func TestPretool_FileWriteGuard(t *testing.T) {
	bin := buildBinary(t)
	wd := t.TempDir()
	shimDir := t.TempDir()
	home := t.TempDir()
	cases := []struct {
		tool, path, want string
	}{
		{"Write", filepath.Join(wd, "manifest.json"), "deny"},
		{"Edit", filepath.Join(wd, "decisions", "x.json"), "deny"},
		{"Write", filepath.Join(shimDir, "npm"), "deny"},
		{"MultiEdit", filepath.Join(home, ".claude", "settings.json"), "ask"},
		{"Write", filepath.Join(home, ".cursor", "mcp.json"), "ask"},
		{"Write", filepath.Join(home, "proj", ".mcp.json"), "ask"},
		{"Write", filepath.Join(home, "proj", "main.go"), ""},
	}
	for _, tc := range cases {
		payload, _ := json.Marshal(map[string]any{
			"tool_name":  tc.tool,
			"tool_input": map[string]any{"file_path": tc.path},
		})
		out := runBinary(t, bin, string(payload), "WATCHDOG_DIR="+wd, "WATCHDOG_SHIM_DIR="+shimDir)
		if got := decisionOf(t, out); got != tc.want {
			t.Errorf("%s %s: decision %q, want %q (out=%q)", tc.tool, tc.path, got, tc.want, out)
		}
	}
}

// The degraded-integrity notice is shown once per session, not on
// every Bash call.
func TestPretool_DegradedNoticeOncePerSession(t *testing.T) {
	bin := buildBinary(t)
	wd := t.TempDir()
	cache := t.TempDir()
	// Signing key present + manifest absent → MANIFEST_REMOVED (hard).
	if err := os.WriteFile(filepath.Join(wd, ".signing.pub"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	payload := `{"session_id":"s-1","tool_name":"Bash","tool_input":{"command":"ls"}}`
	env := []string{"WATCHDOG_DIR=" + wd, "WATCHDOG_CACHE_DIR=" + cache}
	if out := runBinary(t, bin, payload, env...); !strings.Contains(out, "integrity degraded") {
		t.Fatalf("first call should carry the notice, got %q", out)
	}
	if out := runBinary(t, bin, payload, env...); out != "" {
		t.Errorf("second call in same session should be silent, got %q", out)
	}
	other := strings.Replace(payload, "s-1", "s-2", 1)
	if out := runBinary(t, bin, other, env...); !strings.Contains(out, "integrity degraded") {
		t.Errorf("new session should get the notice again, got %q", out)
	}
}
