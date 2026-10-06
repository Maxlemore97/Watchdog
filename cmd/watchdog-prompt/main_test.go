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

func buildBinary(t *testing.T) string {
	t.Helper()
	name := "watchdog-prompt"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	bin := filepath.Join(t.TempDir(), name)
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
	cmd.Env = testenv.Hermetic(t, env...)
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

// The shell wrapper's tamper fallback (binary gone, manifest present)
// must emit a decision Claude Code honours for UserPromptSubmit. Only
// "block" is valid there; "deny" is silently ignored (fail-open).
func TestPromptWrapper_TamperFallbackBlocks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash wrapper")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	for _, d := range []string{"/usr/local/bin", "/opt/homebrew/bin"} {
		if _, err := os.Stat(filepath.Join(d, "watchdog-prompt")); err == nil {
			t.Skipf("real watchdog-prompt installed in %s; wrapper would exec it", d)
		}
	}
	home := t.TempDir()
	wdDir := filepath.Join(home, ".watchdog")
	if err := os.MkdirAll(wdDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wdDir, "manifest.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	script, _ := filepath.Abs(filepath.Join("..", "..", "hooks", "prompt.sh"))
	cmd := exec.Command(bash, script)
	cmd.Stdin = strings.NewReader(`{"prompt":"/plugin install evil"}`)
	// Hermetic env: no search-path entry can resolve a real watchdog-prompt.
	cmd.Env = []string{"HOME=" + home, "WATCHDOG_DIR=" + wdDir, "PATH=/usr/bin:/bin"}
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		t.Fatalf("wrapper: %v", err)
	}
	var resp map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		t.Fatalf("not JSON: %v (%q)", err, stdout.String())
	}
	if resp["decision"] != "block" {
		t.Errorf("decision = %v, want block", resp["decision"])
	}
}
