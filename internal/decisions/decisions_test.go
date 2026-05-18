package decisions

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// withTempDir points WATCHDOG_DIR (and the audit log) at a temp dir
// so each test starts clean.
func withTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("WATCHDOG_DIR", dir)
	t.Setenv("WATCHDOG_AUDIT_LOG", filepath.Join(dir, "audit.jsonl"))
	return dir
}

func TestWrite_Read_Allow_RoundTrip(t *testing.T) {
	withTempDir(t)
	cmd := "npm install lodash@4.17.21"
	Write(cmd, "allow", "OSV clean, LLM clean")
	tok, err := Read(cmd)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if tok.Verdict != "allow" || tok.Reason == "" {
		t.Errorf("token = %+v", tok)
	}
}

func TestWrite_Deny_IsCachedAndReadable(t *testing.T) {
	withTempDir(t)
	cmd := "pip install evil-typo-package"
	Write(cmd, "deny", "OSV: critical CVE")
	tok, err := Read(cmd)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if tok.Verdict != "deny" {
		t.Errorf("verdict = %q", tok.Verdict)
	}
}

func TestWrite_Ask_IsNotCached(t *testing.T) {
	withTempDir(t)
	cmd := "yarn add ambiguous"
	Write(cmd, "ask", "low confidence")
	_, err := Read(cmd)
	if !errors.Is(err, ErrNoDecision) {
		t.Errorf("expected ErrNoDecision, got %v", err)
	}
}

func TestRead_NoTokenReturnsErrNoDecision(t *testing.T) {
	withTempDir(t)
	_, err := Read("npm install never-preflighted")
	if !errors.Is(err, ErrNoDecision) {
		t.Errorf("err = %v, want ErrNoDecision", err)
	}
}

func TestRead_ExpiredTokenReturnsErrExpiredAndIsDeleted(t *testing.T) {
	dir := withTempDir(t)
	t.Setenv("WATCHDOG_DECISION_TTL", "0.05") // 50ms
	cmd := "npm install soon-to-expire"
	Write(cmd, "allow", "ok")
	tokPath := filepath.Join(dir, "decisions", Key(cmd)+".json")
	if _, err := os.Stat(tokPath); err != nil {
		t.Fatalf("token not on disk: %v", err)
	}

	// Backdate the file's mtime AND the written_at field by rewriting
	// it with a stale timestamp. ModTime is what Cleanup uses; Read
	// uses written_at.
	stale := time.Now().Add(-time.Hour)
	if err := os.Chtimes(tokPath, stale, stale); err != nil {
		t.Fatal(err)
	}
	// Also rewrite the JSON so written_at is stale.
	data, _ := os.ReadFile(tokPath)
	_ = data
	staleToken := []byte(`{"verdict":"allow","reason":"ok","command":"npm install soon-to-expire","written_at":"2020-01-01T00:00:00Z"}`)
	if err := os.WriteFile(tokPath, staleToken, 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Read(cmd)
	if !errors.Is(err, ErrExpired) {
		t.Errorf("err = %v, want ErrExpired", err)
	}
	if _, err := os.Stat(tokPath); !os.IsNotExist(err) {
		t.Error("expired token not removed")
	}
}

func TestCanonicalize_WhitespaceEquivalence(t *testing.T) {
	withTempDir(t)
	Write("npm install lodash", "allow", "ok")
	// Extra whitespace shouldn't matter.
	tok, err := Read("npm  install  lodash")
	if err != nil {
		t.Fatalf("Read with extra spaces: %v", err)
	}
	if tok.Verdict != "allow" {
		t.Errorf("verdict = %q", tok.Verdict)
	}
}

func TestKey_StableAcrossEquivalentCommands(t *testing.T) {
	cases := []struct {
		a, b string
		same bool
	}{
		{"npm install x", "npm install x", true},
		{"npm install x", "npm  install  x", true},
		{"npm install x", "npm install y", false},
		{"npm install x", "pnpm install x", false},
	}
	for _, tc := range cases {
		got := Key(tc.a) == Key(tc.b)
		if got != tc.same {
			t.Errorf("Key(%q) == Key(%q) = %v, want %v", tc.a, tc.b, got, tc.same)
		}
	}
}

func TestCleanup_RemovesAgedTokens(t *testing.T) {
	dir := withTempDir(t)
	t.Setenv("WATCHDOG_DECISION_TTL", "0.05")
	Write("npm install a", "allow", "ok")
	Write("npm install b", "allow", "ok")

	// Backdate both mtimes.
	tokDir := filepath.Join(dir, "decisions")
	entries, _ := os.ReadDir(tokDir)
	stale := time.Now().Add(-time.Hour)
	for _, e := range entries {
		_ = os.Chtimes(filepath.Join(tokDir, e.Name()), stale, stale)
	}

	n := Cleanup()
	if n != 2 {
		t.Errorf("Cleanup removed %d, want 2", n)
	}
	if Count() != 0 {
		t.Errorf("expected empty cache after cleanup, count = %d", Count())
	}
}

func TestCleanup_PreservesFreshTokens(t *testing.T) {
	withTempDir(t)
	Write("npm install fresh", "allow", "ok")
	if n := Cleanup(); n != 0 {
		t.Errorf("Cleanup removed %d fresh tokens", n)
	}
	if Count() != 1 {
		t.Errorf("Count = %d, want 1", Count())
	}
}

func TestWrite_AtomicViaTempThenRename(t *testing.T) {
	dir := withTempDir(t)
	Write("npm install x", "allow", "ok")
	// After Write returns, there should be exactly one .json file and
	// no leftover .tmp files.
	entries, _ := os.ReadDir(filepath.Join(dir, "decisions"))
	var jsons, tmps int
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".json" {
			jsons++
		}
		if filepath.Ext(e.Name()) == ".tmp" {
			tmps++
		}
	}
	if jsons != 1 || tmps != 0 {
		t.Errorf("decisions/: %d json, %d tmp (want 1, 0)", jsons, tmps)
	}
}

func TestTTL_DefaultAndOverride(t *testing.T) {
	t.Setenv("WATCHDOG_DECISION_TTL", "")
	if got := TTL(); got != DefaultTTL {
		t.Errorf("default TTL = %v, want %v", got, DefaultTTL)
	}
	t.Setenv("WATCHDOG_DECISION_TTL", "120")
	if got := TTL(); got != 120*time.Second {
		t.Errorf("override TTL = %v, want 120s", got)
	}
	t.Setenv("WATCHDOG_DECISION_TTL", "garbage")
	if got := TTL(); got != DefaultTTL {
		t.Errorf("bogus TTL should fall back to default, got %v", got)
	}
}
