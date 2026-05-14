// Package paths centralises filesystem path resolution shared by the
// analyzer, OSV cache, and plugin ledger.
package paths

import (
	"os"
	"path/filepath"
)

// CacheDir returns the directory Watchdog uses for OSV/LLM caches and
// the plugin ledger. Resolution order:
//
//  1. WATCHDOG_CACHE_DIR env var (absolute path)
//  2. $XDG_CACHE_HOME/watchdog
//  3. ~/.cache/watchdog
func CacheDir() string {
	if override := os.Getenv("WATCHDOG_CACHE_DIR"); override != "" {
		return override
	}
	if xdg := os.Getenv("XDG_CACHE_HOME"); xdg != "" {
		return filepath.Join(xdg, "watchdog")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".cache", "watchdog")
	}
	return filepath.Join(home, ".cache", "watchdog")
}
