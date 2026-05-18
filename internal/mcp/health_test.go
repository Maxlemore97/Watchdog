package mcp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Maxlemore97/watchdog/internal/integrity"
)

// withTempWatchdog points WATCHDOG_DIR and WATCHDOG_SHIM_DIR at a
// fresh temp dir so each test starts with a clean integrity state.
func withTempWatchdog(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	shimDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(shimDir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WATCHDOG_DIR", dir)
	t.Setenv("WATCHDOG_SHIM_DIR", shimDir)
	t.Cleanup(integrity.ResetCache)
	return dir
}

func TestHealth_ReportsDisabledWhenEnvSet(t *testing.T) {
	withTempWatchdog(t)
	t.Setenv("WATCHDOG_DISABLE", "1")
	h := Health()
	if h.Status != "disabled" {
		t.Errorf("Status = %q, want disabled", h.Status)
	}
	if h.Version == "" {
		t.Error("Version should never be empty")
	}
}

func TestHealth_ReportsManifestMissing(t *testing.T) {
	withTempWatchdog(t)
	// No `watchdog-shim install` was ever run.
	h := Health()
	if h.ManifestPresent {
		t.Error("expected ManifestPresent=false")
	}
	if h.Status == "ok" {
		t.Errorf("Status = %q, want degraded (no manifest)", h.Status)
	}
}

func TestHealth_StatusOKAfterFreshInstall(t *testing.T) {
	dir := withTempWatchdog(t)
	// Drop a minimal valid manifest in place so VerifyDeep finds it.
	m := integrity.Manifest{
		Version:     integrity.CurrentVersion,
		WatchdogDir: dir,
		ShimDir:     filepath.Join(dir, "bin"),
		Binaries:    map[string]string{},
		Shims:       map[string]string{},
	}
	if err := integrity.WriteManifest(&m); err != nil {
		t.Fatal(err)
	}
	// Make sure the shim dir is first on PATH so PATH check passes.
	t.Setenv("PATH", filepath.Join(dir, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"))

	h := Health()
	// Self-binary won't be in manifest (we're running `go test`); that
	// emits SELF_UNKNOWN which is informational, so OK should still
	// hold and Status should be "ok".
	if h.Status != "ok" {
		t.Errorf("Status = %q, want ok. Failures: %v", h.Status, h.Integrity.Failures)
	}
	if !h.ManifestPresent {
		t.Error("ManifestPresent should be true")
	}
	if h.HandlerTimeoutSec <= 0 {
		t.Error("HandlerTimeoutSec should be positive")
	}
}

// JSON contract pin: the MCP boundary marshals HealthResult to JSON;
// renaming a field would silently break agents.
func TestHealthResult_JSONShape(t *testing.T) {
	withTempWatchdog(t)
	data, err := json.Marshal(Health())
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{
		"version", "status", "manifest_present", "integrity",
		"handler_timeout_sec", "uptime_sec",
	} {
		if _, ok := parsed[key]; !ok {
			t.Errorf("missing %q in JSON: %s", key, data)
		}
	}
}
