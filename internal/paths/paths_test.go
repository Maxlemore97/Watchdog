package paths

import (
	"path/filepath"
	"testing"
)

func TestCacheDir_OverrideWins(t *testing.T) {
	t.Setenv("WATCHDOG_CACHE_DIR", "/tmp/explicit-watchdog")
	t.Setenv("XDG_CACHE_HOME", "/should-not-be-used")
	if got := CacheDir(); got != "/tmp/explicit-watchdog" {
		t.Fatalf("CacheDir = %q, want explicit override", got)
	}
}

func TestCacheDir_XDGUsed(t *testing.T) {
	t.Setenv("WATCHDOG_CACHE_DIR", "")
	t.Setenv("XDG_CACHE_HOME", "/tmp/xdg-base")
	want := filepath.Join("/tmp/xdg-base", "watchdog")
	if got := CacheDir(); got != want {
		t.Fatalf("CacheDir = %q, want %q", got, want)
	}
}

func TestCacheDir_FallbackToHomeCache(t *testing.T) {
	t.Setenv("WATCHDOG_CACHE_DIR", "")
	t.Setenv("XDG_CACHE_HOME", "")
	got := CacheDir()
	if filepath.Base(got) != "watchdog" {
		t.Fatalf("CacheDir = %q, want suffix watchdog", got)
	}
	if filepath.Base(filepath.Dir(got)) != ".cache" {
		t.Fatalf("CacheDir = %q, want under .cache/", got)
	}
}
