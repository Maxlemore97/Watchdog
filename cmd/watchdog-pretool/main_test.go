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
	cmd.Env = append(os.Environ(), env...)
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
