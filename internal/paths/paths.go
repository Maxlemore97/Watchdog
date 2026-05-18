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

// WatchdogDir returns the installation-state directory. This is where
// the shim binaries (~/.watchdog/bin), the integrity manifest, and the
// audit log live. Distinct from CacheDir, which holds regenerable
// state. Resolution:
//
//  1. WATCHDOG_DIR env var
//  2. ~/.watchdog
//
// Does not honour XDG because the shim dir lives here too and ~/.watchdog
// is what existing installs already use.
func WatchdogDir() string {
	if override := os.Getenv("WATCHDOG_DIR"); override != "" {
		return override
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".watchdog"
	}
	return filepath.Join(home, ".watchdog")
}

// ManifestPath returns the absolute path of the integrity manifest.
func ManifestPath() string {
	return filepath.Join(WatchdogDir(), "manifest.json")
}

// AuditLogPath returns the absolute path of the tamper / integrity
// audit log (JSONL).
func AuditLogPath() string {
	return filepath.Join(WatchdogDir(), "audit.jsonl")
}
