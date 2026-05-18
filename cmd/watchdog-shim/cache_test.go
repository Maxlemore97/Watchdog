package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeCacheFile drops a JSON file into the test cache dir with the
// requested mtime and content shape. Returns the path.
func writeCacheFile(t *testing.T, dir, name string, content any, mtime time.Time) string {
	t.Helper()
	data, err := json.Marshal(content)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if !mtime.IsZero() {
		if err := os.Chtimes(path, mtime, mtime); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func TestClassifyCacheFile(t *testing.T) {
	dir := t.TempDir()
	llm := writeCacheFile(t, dir, "aaaa.json",
		map[string]any{"verdict": "allow", "reason": "ok"}, time.Time{})
	osv := writeCacheFile(t, dir, "bbbb.json",
		[]any{map[string]any{"id": "GHSA-x"}}, time.Time{})
	ledger := writeCacheFile(t, dir, "vetted_plugins.json",
		map[string]any{"version": 1, "entries": map[string]any{}}, time.Time{})
	unk := writeCacheFile(t, dir, "cccc.json",
		map[string]any{"random": "object"}, time.Time{})

	if got := classifyCacheFile(llm, "aaaa.json"); got != "llm" {
		t.Errorf("llm classify = %q", got)
	}
	if got := classifyCacheFile(osv, "bbbb.json"); got != "osv" {
		t.Errorf("osv classify = %q", got)
	}
	if got := classifyCacheFile(ledger, "vetted_plugins.json"); got != "ledger" {
		t.Errorf("ledger classify = %q", got)
	}
	if got := classifyCacheFile(unk, "cccc.json"); got != "unknown" {
		t.Errorf("unknown classify = %q", got)
	}
}

func TestScanCache_IgnoresTmpAndNonJSON(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("WATCHDOG_CACHE_DIR", dir)
	writeCacheFile(t, dir, "aa.json", map[string]any{"verdict": "ask"}, time.Time{})
	// Tmp staging artefact from a torn cache write.
	_ = os.WriteFile(filepath.Join(dir, "aa.json.123.tmp"),
		[]byte(`{"verdict":"deny"}`), 0o644)
	// Stray non-JSON file.
	_ = os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("hi"), 0o644)

	entries, err := scanCache()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("scan returned %d entries, want 1", len(entries))
	}
}

func TestCmdCacheClear_TypeFilter(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("WATCHDOG_CACHE_DIR", dir)
	llm := writeCacheFile(t, dir, "aaaa.json",
		map[string]any{"verdict": "allow"}, time.Time{})
	osv := writeCacheFile(t, dir, "bbbb.json",
		[]any{map[string]any{"id": "GHSA-x"}}, time.Time{})

	if rc := cmdCacheClear([]string{"--type=llm"}); rc != 0 {
		t.Fatalf("clear llm rc = %d", rc)
	}
	if _, err := os.Stat(llm); !os.IsNotExist(err) {
		t.Errorf("llm entry survived: %v", err)
	}
	if _, err := os.Stat(osv); err != nil {
		t.Errorf("osv entry should remain: %v", err)
	}
}

func TestCmdCacheClear_OlderThanFilter(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("WATCHDOG_CACHE_DIR", dir)
	old := writeCacheFile(t, dir, "aaaa.json",
		map[string]any{"verdict": "allow"}, time.Now().Add(-48*time.Hour))
	young := writeCacheFile(t, dir, "bbbb.json",
		map[string]any{"verdict": "deny"}, time.Now().Add(-1*time.Hour))

	if rc := cmdCacheClear([]string{"--type=llm", "--older-than=24h"}); rc != 0 {
		t.Fatalf("clear rc = %d", rc)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Errorf("old entry should be gone: %v", err)
	}
	if _, err := os.Stat(young); err != nil {
		t.Errorf("young entry should remain: %v", err)
	}
}

func TestCmdCacheClear_DryRunKeepsFiles(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("WATCHDOG_CACHE_DIR", dir)
	path := writeCacheFile(t, dir, "aaaa.json",
		map[string]any{"verdict": "allow"}, time.Time{})

	if rc := cmdCacheClear([]string{"--type=all", "--dry-run"}); rc != 0 {
		t.Fatalf("dry-run rc = %d", rc)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("dry-run removed a file: %v", err)
	}
}

func TestCmdCacheClear_NeverTouchesLedger(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("WATCHDOG_CACHE_DIR", dir)
	ledger := writeCacheFile(t, dir, "vetted_plugins.json",
		map[string]any{"version": 1, "entries": map[string]any{}}, time.Time{})

	if rc := cmdCacheClear([]string{"--type=all"}); rc != 0 {
		t.Fatalf("clear rc = %d", rc)
	}
	if _, err := os.Stat(ledger); err != nil {
		t.Errorf("ledger must survive --type=all: %v", err)
	}
}

func TestCmdCacheClear_RejectsBadType(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("WATCHDOG_CACHE_DIR", dir)
	if rc := cmdCacheClear([]string{"--type=banana"}); rc == 0 {
		t.Error("bad type should not return 0")
	}
}

func TestParseAgeDuration(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"24h", 24 * time.Hour},
		{"7d", 7 * 24 * time.Hour},
		{"30m", 30 * time.Minute},
		{"0d", 0},
	}
	for _, c := range cases {
		got, err := parseAgeDuration(c.in)
		if err != nil {
			t.Errorf("parseAgeDuration(%q) err: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("parseAgeDuration(%q) = %v, want %v", c.in, got, c.want)
		}
	}
	if _, err := parseAgeDuration("notaduration"); err == nil {
		t.Error("expected error for bogus input")
	}
}
