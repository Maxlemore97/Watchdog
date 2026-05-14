//go:build !windows

// Provider tests use POSIX shell scripts as fake LLM CLIs (chmod +x,
// /bin/sh shebang, cat/printf). On Windows exec.LookPath ignores
// no-extension scripts and POSIX shell isn't available. The argv-
// shape contracts the tests pin are identical on Windows builds; we
// trust the build, not a re-test on the platform that can't run the
// stubs cheaply.
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
	t.Setenv("PATH", dir+":/bin:/usr/bin")
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

// makeCapturingBin writes a fake binary that records argv into
// $WATCHDOG_TEST_ARGV_FILE and stdin into $WATCHDOG_TEST_STDIN_FILE,
// then prints "OK" so the caller's RC = 0.
func makeCapturingBin(t *testing.T, dir, name string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	script := `#!/bin/sh
printf '%s\n' "$@" > "$WATCHDOG_TEST_ARGV_FILE"
cat > "$WATCHDOG_TEST_STDIN_FILE"
echo OK
`
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	s := strings.TrimRight(string(data), "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func TestInvokeClaude_ArgvShape(t *testing.T) {
	dir := t.TempDir()
	makeCapturingBin(t, dir, "claude")
	argvFile := filepath.Join(dir, "argv")
	stdinFile := filepath.Join(dir, "stdin")
	t.Setenv("PATH", dir+":/bin:/usr/bin")
	t.Setenv("WATCHDOG_LLM_PROVIDER", "claude")
	t.Setenv("WATCHDOG_TEST_ARGV_FILE", argvFile)
	t.Setenv("WATCHDOG_TEST_STDIN_FILE", stdinFile)

	out, _, _, err := InvokeLLM("USER", "SYS")
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	if !strings.Contains(out, "OK") {
		t.Errorf("stdout = %q", out)
	}
	args := readLines(t, argvFile)
	// claude argv must include the hardening flags.
	got := strings.Join(args, " ")
	for _, needle := range []string{"-p", "--model", "--output-format", "json",
		"--max-turns", "1", "--allowed-tools"} {
		if !strings.Contains(got, needle) {
			t.Errorf("claude argv missing %q: %v", needle, args)
		}
	}
	if stdin := readLines(t, stdinFile); len(stdin) == 0 || stdin[0] != "USER" {
		t.Errorf("claude stdin = %v, want USER", stdin)
	}
}

func TestInvokeGemini_ArgvShape(t *testing.T) {
	dir := t.TempDir()
	makeCapturingBin(t, dir, "gemini")
	argvFile := filepath.Join(dir, "argv")
	stdinFile := filepath.Join(dir, "stdin")
	t.Setenv("PATH", dir+":/bin:/usr/bin")
	t.Setenv("WATCHDOG_LLM_PROVIDER", "gemini")
	t.Setenv("WATCHDOG_TEST_ARGV_FILE", argvFile)
	t.Setenv("WATCHDOG_TEST_STDIN_FILE", stdinFile)

	if _, _, _, err := InvokeLLM("USER", "SYS"); err != nil {
		t.Fatalf("invoke: %v", err)
	}
	args := readLines(t, argvFile)
	got := strings.Join(args, " ")
	if !strings.Contains(got, "-m") {
		t.Errorf("gemini argv missing -m: %v", args)
	}
	// gemini gets system+user combined via stdin
	stdin := readLines(t, stdinFile)
	stdinJoined := strings.Join(stdin, "\n")
	if !strings.Contains(stdinJoined, "USER") || !strings.Contains(stdinJoined, "SYS") {
		t.Errorf("gemini stdin missing user/system: %q", stdinJoined)
	}
}

func TestInvokeOpenAI_ArgvShape(t *testing.T) {
	dir := t.TempDir()
	makeCapturingBin(t, dir, "openai")
	argvFile := filepath.Join(dir, "argv")
	stdinFile := filepath.Join(dir, "stdin")
	t.Setenv("PATH", dir+":/bin:/usr/bin")
	t.Setenv("WATCHDOG_LLM_PROVIDER", "openai")
	t.Setenv("WATCHDOG_TEST_ARGV_FILE", argvFile)
	t.Setenv("WATCHDOG_TEST_STDIN_FILE", stdinFile)

	if _, _, _, err := InvokeLLM("USER", "SYS"); err != nil {
		t.Fatalf("invoke: %v", err)
	}
	args := readLines(t, argvFile)
	got := strings.Join(args, " ")
	for _, needle := range []string{"api", "chat.completions.create", "-m"} {
		if !strings.Contains(got, needle) {
			t.Errorf("openai argv missing %q: %v", needle, args)
		}
	}
	// openai passes both system + user as -g flags
	roleCount := strings.Count(got, "-g")
	if roleCount < 2 {
		t.Errorf("expected ≥2 -g flags (system + user), got %d in %v", roleCount, args)
	}
}

func TestInvokeOllama_ArgvShape(t *testing.T) {
	dir := t.TempDir()
	makeCapturingBin(t, dir, "ollama")
	argvFile := filepath.Join(dir, "argv")
	stdinFile := filepath.Join(dir, "stdin")
	t.Setenv("PATH", dir+":/bin:/usr/bin")
	t.Setenv("WATCHDOG_LLM_PROVIDER", "ollama")
	t.Setenv("WATCHDOG_TEST_ARGV_FILE", argvFile)
	t.Setenv("WATCHDOG_TEST_STDIN_FILE", stdinFile)

	if _, _, _, err := InvokeLLM("USER", "SYS"); err != nil {
		t.Fatalf("invoke: %v", err)
	}
	args := readLines(t, argvFile)
	if len(args) < 2 || args[0] != "run" {
		t.Errorf("ollama argv should start with `run <model>`: %v", args)
	}
	// ollama gets system+user combined via stdin (same as gemini).
	stdin := strings.Join(readLines(t, stdinFile), "\n")
	if !strings.Contains(stdin, "USER") || !strings.Contains(stdin, "SYS") {
		t.Errorf("ollama stdin missing user/system: %q", stdin)
	}
}

func TestInvokeGeneric_ArgvShape(t *testing.T) {
	dir := t.TempDir()
	makeCapturingBin(t, dir, "my-llm")
	argvFile := filepath.Join(dir, "argv")
	stdinFile := filepath.Join(dir, "stdin")
	t.Setenv("PATH", dir+":/bin:/usr/bin")
	t.Setenv("WATCHDOG_LLM_PROVIDER", "generic")
	t.Setenv("WATCHDOG_LLM_CMD", "my-llm --model x")
	t.Setenv("WATCHDOG_TEST_ARGV_FILE", argvFile)
	t.Setenv("WATCHDOG_TEST_STDIN_FILE", stdinFile)

	if _, _, _, err := InvokeLLM("USER", "SYS"); err != nil {
		t.Fatalf("invoke: %v", err)
	}
	args := readLines(t, argvFile)
	got := strings.Join(args, " ")
	if !strings.Contains(got, "--model x") {
		t.Errorf("generic argv missing user flags: %v", args)
	}
}

func TestRunCmd_StdoutCappedAtLimit(t *testing.T) {
	// Generic provider that floods stdout. Verify captured output is
	// bounded by stdoutCapBytes — a hostile or runaway CLI cannot OOM
	// the analyzer by writing gigabytes to stdout.
	dir := t.TempDir()
	path := filepath.Join(dir, "stdout-flood")
	// Write ~16 MB to stdout — 4x the cap.
	script := `#!/bin/sh
yes flood-line | head -c 16777216
`
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":/bin:/usr/bin")
	t.Setenv("WATCHDOG_LLM_PROVIDER", "generic")
	t.Setenv("WATCHDOG_LLM_CMD", "stdout-flood")

	out, _, _, err := InvokeLLM("hi", "SYS")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) > stdoutCapBytes {
		t.Errorf("stdout not capped: len=%d, want <= %d", len(out), stdoutCapBytes)
	}
	if len(out) == 0 {
		t.Error("expected some stdout capture, got empty")
	}
}

func TestRunCmd_StderrCappedAtLimit(t *testing.T) {
	// Run a binary that floods stderr; verify the wrapped error
	// message is bounded (stderrCapBytes capped at 64KB; the truncate
	// for the error message further caps to 200 chars).
	dir := t.TempDir()
	path := filepath.Join(dir, "flood")
	script := `#!/bin/sh
# 1 MB of garbage to stderr, then exit nonzero so runCmd reports it.
yes flood-line | head -c 1048576 >&2
exit 1
`
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":/bin:/usr/bin")
	t.Setenv("WATCHDOG_LLM_PROVIDER", "generic")
	t.Setenv("WATCHDOG_LLM_CMD", "flood")

	_, _, _, err := InvokeLLM("hi", "SYS")
	if err == nil {
		t.Fatal("expected error from nonzero exit")
	}
	if len(err.Error()) > 1000 {
		t.Errorf("error message not bounded: len=%d", len(err.Error()))
	}
}
