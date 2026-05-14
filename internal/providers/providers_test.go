package providers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// makeFakeBin writes an executable shell script that prints its argv
// and stdin to stdout, exits 0. Returns the binary path. Caller is
// expected to t.Setenv("PATH", binDir) (or :$PATH) so resolution
// works.
func makeFakeBin(t *testing.T, dir, name string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	script := `#!/bin/sh
echo argv:$*
cat
`
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestResolveProvider_AutoDetectClaude(t *testing.T) {
	dir := t.TempDir()
	makeFakeBin(t, dir, "claude")
	t.Setenv("PATH", dir)
	t.Setenv("WATCHDOG_LLM_PROVIDER", "")
	prov, err := ResolveProvider()
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if prov.Name != "claude" {
		t.Errorf("got %q, want claude", prov.Name)
	}
}

func TestResolveProvider_OrderingClaudeFirst(t *testing.T) {
	dir := t.TempDir()
	makeFakeBin(t, dir, "gemini")
	makeFakeBin(t, dir, "claude")
	t.Setenv("PATH", dir)
	t.Setenv("WATCHDOG_LLM_PROVIDER", "")
	prov, err := ResolveProvider()
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if prov.Name != "claude" {
		t.Errorf("claude should win when both present, got %q", prov.Name)
	}
}

func TestResolveProvider_NoProviderReturnsError(t *testing.T) {
	dir := t.TempDir() // empty PATH dir
	t.Setenv("PATH", dir)
	t.Setenv("WATCHDOG_LLM_PROVIDER", "")
	if _, err := ResolveProvider(); err == nil {
		t.Error("expected ErrNoProvider with empty PATH")
	}
}

func TestResolveProvider_InvalidProviderFallsBackToAuto(t *testing.T) {
	dir := t.TempDir()
	makeFakeBin(t, dir, "ollama")
	t.Setenv("PATH", dir)
	t.Setenv("WATCHDOG_LLM_PROVIDER", "nonsense")
	prov, err := ResolveProvider()
	if err != nil || prov.Name != "ollama" {
		t.Errorf("invalid provider didn't fall back: %v %q", err, prov.Name)
	}
}

func TestBuildConfig_EnvOverrides(t *testing.T) {
	t.Setenv("WATCHDOG_LLM_BIN", "/custom/claude")
	t.Setenv("WATCHDOG_LLM_MODEL", "custom-model")
	t.Setenv("WATCHDOG_LLM_TIMEOUT", "5")
	t.Setenv("WATCHDOG_LLM_APPEND_SYSTEM", "false")
	cfg := BuildConfig(Registry["claude"], "SYS")
	if cfg.Bin != "/custom/claude" {
		t.Errorf("bin = %q", cfg.Bin)
	}
	if cfg.Model != "custom-model" {
		t.Errorf("model = %q", cfg.Model)
	}
	if cfg.Timeout.Seconds() != 5 {
		t.Errorf("timeout = %v", cfg.Timeout)
	}
	if cfg.AppendSystem {
		t.Error("append_system should be false")
	}
}

func TestInvokeLLM_ChildEnvCarriesDisableFlag(t *testing.T) {
	dir := t.TempDir()
	// fake that echoes WATCHDOG_DISABLE
	path := filepath.Join(dir, "claude")
	if err := os.WriteFile(path, []byte(`#!/bin/sh
echo "DISABLE=$WATCHDOG_DISABLE"
`), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("WATCHDOG_LLM_PROVIDER", "claude")
	t.Setenv("WATCHDOG_LLM_APPEND_SYSTEM", "0")
	out, prov, _, err := InvokeLLM("hi", "SYS")
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	if prov.Name != "claude" {
		t.Errorf("provider = %q", prov.Name)
	}
	if !strings.Contains(out, "DISABLE=1") {
		t.Errorf("WATCHDOG_DISABLE not set in child env: %q", out)
	}
}

func TestInvokeLLM_NoProvider(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	t.Setenv("WATCHDOG_LLM_PROVIDER", "")
	_, _, _, err := InvokeLLM("hi", "SYS")
	if err == nil {
		t.Error("expected error with no provider on PATH")
	}
}

func TestInvokeGeneric_NoCmdReturnsErr(t *testing.T) {
	t.Setenv("WATCHDOG_LLM_CMD", "")
	cfg := Config{}
	if _, err := invokeGeneric("x", cfg); err == nil {
		t.Error("expected error with empty WATCHDOG_LLM_CMD")
	}
}

func TestRegistry_HasFiveProviders(t *testing.T) {
	want := []string{"claude", "gemini", "openai", "ollama", "generic"}
	for _, name := range want {
		if _, ok := Registry[name]; !ok {
			t.Errorf("missing provider %q", name)
		}
	}
}
