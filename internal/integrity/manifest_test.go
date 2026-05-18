package integrity

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// withTempWatchdogDir overrides WATCHDOG_DIR and WATCHDOG_SHIM_DIR
// to a fresh temp dir and returns paths {dir, shimDir}. Auto-cleanup
// via t.Cleanup.
func withTempWatchdogDir(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	shimDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(shimDir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WATCHDOG_DIR", dir)
	t.Setenv("WATCHDOG_SHIM_DIR", shimDir)
	t.Cleanup(ResetCache)
	return dir, shimDir
}

// writeFakeShim places a wrapper file with the Watchdog marker so
// Build() picks it up.
func writeFakeShim(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	content := "#!/usr/bin/env bash\n# Watchdog shim for " + name + "\n" + body
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestBuild_WriteLoad_RoundTrip(t *testing.T) {
	_, shimDir := withTempWatchdogDir(t)
	writeFakeShim(t, shimDir, "npm", "exec foo\n")
	writeFakeShim(t, shimDir, "pip", "exec bar\n")
	// One foreign file in shim dir — should be ignored by Build.
	if err := os.WriteFile(filepath.Join(shimDir, "user-script"),
		[]byte("#!/bin/sh\necho not mine\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	m, err := Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(m.Shims) != 2 {
		t.Errorf("expected 2 shims, got %d: %v", len(m.Shims), m.Shims)
	}
	if _, ok := m.Shims["user-script"]; ok {
		t.Error("foreign file leaked into manifest")
	}

	if err := WriteManifest(m); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}

	loaded, err := LoadManifest()
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	if loaded.Version != CurrentVersion {
		t.Errorf("version = %d, want %d", loaded.Version, CurrentVersion)
	}
	if loaded.ShimDir != shimDir {
		t.Errorf("ShimDir = %q, want %q", loaded.ShimDir, shimDir)
	}
	if len(loaded.Shims) != 2 {
		t.Errorf("loaded shims = %d", len(loaded.Shims))
	}
	for k, v := range m.Shims {
		if loaded.Shims[k] != v {
			t.Errorf("shim %s hash drift: %q vs %q", k, v, loaded.Shims[k])
		}
	}
}

func TestBuild_HashesWrapperContent(t *testing.T) {
	_, shimDir := withTempWatchdogDir(t)
	body := "exec watchdog-shim-exec npm \"$@\"\n"
	path := writeFakeShim(t, shimDir, "npm", body)

	m, err := Build()
	if err != nil {
		t.Fatal(err)
	}

	raw, _ := os.ReadFile(path)
	want := sha256.Sum256(raw)
	if got := m.Shims["npm"]; got != hex.EncodeToString(want[:]) {
		t.Errorf("hash mismatch: got %q want %q", got, hex.EncodeToString(want[:]))
	}
}

func TestLoadManifest_ReturnsErrorWhenMissing(t *testing.T) {
	withTempWatchdogDir(t)
	_, err := LoadManifest()
	if err == nil {
		t.Fatal("expected error for missing manifest")
	}
	if !os.IsNotExist(err) {
		t.Errorf("expected IsNotExist, got: %v", err)
	}
}

func TestWriteManifest_AtomicOverwrite(t *testing.T) {
	_, shimDir := withTempWatchdogDir(t)
	writeFakeShim(t, shimDir, "npm", "v1\n")
	m1, _ := Build()
	if err := WriteManifest(m1); err != nil {
		t.Fatal(err)
	}

	// Update the wrapper content; build a new manifest with a
	// different hash for npm.
	writeFakeShim(t, shimDir, "npm", "v2\n")
	m2, _ := Build()
	if m1.Shims["npm"] == m2.Shims["npm"] {
		t.Fatal("test setup failed: hashes should differ")
	}
	if err := WriteManifest(m2); err != nil {
		t.Fatal(err)
	}

	loaded, _ := LoadManifest()
	if loaded.Shims["npm"] != m2.Shims["npm"] {
		t.Errorf("overwrite lost: got %q want %q", loaded.Shims["npm"], m2.Shims["npm"])
	}
}
