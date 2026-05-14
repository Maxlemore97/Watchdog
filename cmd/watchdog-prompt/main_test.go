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
	bin := filepath.Join(t.TempDir(), "watchdog-prompt")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("build: %v", err)
	}
	return bin
}

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

func TestPrompt_EmptyPromptSilent(t *testing.T) {
	bin := buildBinary(t)
	out := runBinary(t, bin, `{"prompt":""}`)
	if out != "" {
		t.Errorf("empty prompt should pass through silently, got %q", out)
	}
}

func TestPrompt_NoPluginInstallSilent(t *testing.T) {
	bin := buildBinary(t)
	out := runBinary(t, bin, `{"prompt":"hello world"}`)
	if out != "" {
		t.Errorf("non-plugin prompt should pass through silently, got %q", out)
	}
}

func TestPrompt_MalformedSilent(t *testing.T) {
	bin := buildBinary(t)
	out := runBinary(t, bin, `not json{{{`)
	if out != "" {
		t.Errorf("malformed stdin should pass through silently, got %q", out)
	}
}

func TestPrompt_DisabledSilent(t *testing.T) {
	bin := buildBinary(t)
	out := runBinary(t, bin,
		`{"prompt":"/plugin install foo"}`,
		"WATCHDOG_DISABLE=1",
	)
	if out != "" {
		t.Errorf("disabled should pass through silently, got %q", out)
	}
}

func TestPrompt_PluginInstallProducesContext(t *testing.T) {
	bin := buildBinary(t)
	out := runBinary(t, bin,
		`{"prompt":"/plugin install some-nonexistent-plugin-xyz"}`,
		"PATH=", // no LLM CLI; analyzer falls back to ask
		"WATCHDOG_CACHE_DIR="+t.TempDir(),
	)
	if out == "" {
		t.Fatal("plugin install should produce some output")
	}
	var resp map[string]any
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("not JSON: %v (%q)", err, out)
	}
	// Either decision/reason OR hookSpecificOutput/additionalContext must be present.
	hasDecision := resp["decision"] != nil
	hso, _ := resp["hookSpecificOutput"].(map[string]any)
	hasContext := hso != nil && hso["additionalContext"] != nil
	if !hasDecision && !hasContext {
		t.Errorf("response lacks decision and context: %v", resp)
	}
}
