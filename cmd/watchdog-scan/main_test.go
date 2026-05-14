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
	bin := filepath.Join(t.TempDir(), "watchdog-scan")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("build: %v", err)
	}
	return bin
}

func runBinary(t *testing.T, bin, target string, env ...string) string {
	t.Helper()
	args := []string{}
	if target != "" {
		args = append(args, target)
	}
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), env...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("run: %v", err)
	}
	return stdout.String()
}

func TestScan_NoArgsAskFallback(t *testing.T) {
	bin := buildBinary(t)
	out := runBinary(t, bin, "")
	if !strings.Contains(out, "ask") || !strings.Contains(out, "no target") {
		t.Errorf("expected ask/no-target message, got %q", out)
	}
}

func TestScan_TargetProducesResultsArray(t *testing.T) {
	bin := buildBinary(t)
	// PATH cleared → analyzer returns ask fallback for each ecosystem.
	out := runBinary(t, bin, "some-nonexistent-pkg-xyz",
		"PATH=",
		"WATCHDOG_CACHE_DIR="+t.TempDir(),
	)
	var resp map[string]any
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("not JSON: %v (%q)", err, out)
	}
	if resp["target"] != "some-nonexistent-pkg-xyz" {
		t.Errorf("target field missing: %v", resp)
	}
	if _, ok := resp["results"].([]any); !ok {
		t.Errorf("results field not an array: %v", resp["results"])
	}
}

func TestScan_GitURLClassifiedAsPlugin(t *testing.T) {
	bin := buildBinary(t)
	out := runBinary(t, bin, "https://github.com/example/repo.git",
		"PATH=",
		"WATCHDOG_CACHE_DIR="+t.TempDir(),
	)
	var resp map[string]any
	_ = json.Unmarshal([]byte(out), &resp)
	results, _ := resp["results"].([]any)
	if len(results) == 0 {
		t.Skip("no analyzer available; skipping classifier assertion")
	}
	first, _ := results[0].(map[string]any)
	if first["ecosystem"] != "plugin" {
		t.Errorf("git URL should classify as plugin, got %v", first["ecosystem"])
	}
}
