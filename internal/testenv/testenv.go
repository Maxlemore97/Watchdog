// Package testenv builds hermetic environments for tests that exec a
// Watchdog binary. Without it a subprocess inherits the developer's
// HOME (real ~/.watchdog manifest, decisions, audit log, installed
// Claude Code plugins) and PATH (real `claude` CLI), so a test can
// fail on local integrity state — or run billable LLM scans against
// the developer's plugins.
package testenv

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// NoLLMBin is a provider binary path that never exists, so any LLM
// call in a test fails fast and falls back to the fail-closed verdict.
const NoLLMBin = "/nonexistent/watchdog-test-no-llm"

// droppedPrefixes are host variables that leak user state or
// credentials into the child.
var droppedPrefixes = []string{
	"WATCHDOG_", "CLAUDE", "ANTHROPIC_", "OPENAI_", "GEMINI_", "GOOGLE_API",
	"HOME=", "USERPROFILE=", "XDG_CACHE_HOME=", "XDG_CONFIG_HOME=", "XDG_DATA_HOME=",
	"APPDATA=", "LOCALAPPDATA=",
}

// Hermetic returns the host environment minus user state and
// credentials, with HOME and every Watchdog state dir pointed at fresh
// temp dirs. extra entries are appended last and therefore win
// (os/exec keeps the last value of a duplicated key).
func Hermetic(t testing.TB, extra ...string) []string {
	t.Helper()
	home := t.TempDir()
	var env []string
	for _, kv := range os.Environ() {
		drop := false
		for _, p := range droppedPrefixes {
			if strings.HasPrefix(strings.ToUpper(kv), p) {
				drop = true
				break
			}
		}
		if !drop {
			env = append(env, kv)
		}
	}
	env = append(env,
		"HOME="+home,
		"USERPROFILE="+home,
		"APPDATA="+filepath.Join(home, "AppData", "Roaming"),
		"LOCALAPPDATA="+filepath.Join(home, "AppData", "Local"),
		"XDG_CACHE_HOME="+filepath.Join(home, ".cache"),
		"XDG_CONFIG_HOME="+filepath.Join(home, ".config"),
		"XDG_DATA_HOME="+filepath.Join(home, ".local", "share"),
		"WATCHDOG_DIR="+filepath.Join(home, ".watchdog"),
		"WATCHDOG_CACHE_DIR="+filepath.Join(home, ".cache", "watchdog"),
		"WATCHDOG_AUDIT_LOG="+filepath.Join(home, "audit.jsonl"),
		"WATCHDOG_LOG="+filepath.Join(home, "events.jsonl"),
		"WATCHDOG_LLM_BIN="+NoLLMBin,
	)
	return append(env, extra...)
}
