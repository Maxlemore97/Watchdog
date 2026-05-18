package integrity

import (
	"encoding/json"
	"os"
	"testing"
)

// TestManifestSignature_RoundTrip writes a manifest, loads it, and
// verifies the signature path doesn't flag a clean manifest.
func TestManifestSignature_RoundTrip(t *testing.T) {
	_, shimDir := withTempWatchdogDir(t)
	writeFakeShim(t, shimDir, "npm", "v1\n")
	m, err := Build()
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteManifest(m); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadManifest()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Signature == "" {
		t.Fatal("WriteManifest did not produce a signature")
	}
	if loaded.Signature != m.Signature {
		t.Errorf("signature changed across round-trip:\n  wrote: %q\n  read:  %q",
			m.Signature, loaded.Signature)
	}

	// VerifyDeep should see no SIGNATURE_* failure on a clean install.
	st := VerifyDeep()
	if st.HasFailure(CodeSignatureMissing) ||
		st.HasFailure(CodeSignatureInvalid) ||
		st.HasFailure(CodeSignatureKeyMissing) {
		t.Errorf("clean install should have no signature failures, got %v", st.Failures)
	}
}

func TestManifestSignature_DetectsTamper(t *testing.T) {
	_, shimDir := withTempWatchdogDir(t)
	writeFakeShim(t, shimDir, "npm", "v1\n")
	m, _ := Build()
	if err := WriteManifest(m); err != nil {
		t.Fatal(err)
	}

	// Tamper: load the JSON on disk, change a binary hash, write back
	// (preserving the now-stale signature).
	data, _ := os.ReadFile(t.TempDir())
	_ = data
	raw, err := os.ReadFile(manifestPathForTest())
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	_ = json.Unmarshal(raw, &cfg)
	if shims, ok := cfg["shims"].(map[string]any); ok {
		shims["npm"] = "0000000000000000000000000000000000000000000000000000000000000000"
	}
	out, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(manifestPathForTest(), out, 0o644); err != nil {
		t.Fatal(err)
	}

	st := VerifyDeep()
	if !st.HasFailure(CodeSignatureInvalid) {
		t.Errorf("expected SIGNATURE_INVALID after tamper, got %v", st.Failures)
	}
}

func TestManifestSignature_LegacyV1AcceptedSoft(t *testing.T) {
	_, _ = withTempWatchdogDir(t)
	// Write a v1-shaped manifest by hand: no Signature field.
	legacy := `{
  "version": 1,
  "installed_at": "2026-01-01T00:00:00Z",
  "watchdog_dir": "/tmp/wd",
  "shim_dir": "/tmp/wd/bin",
  "binaries": {},
  "shims": {}
}
`
	if err := os.WriteFile(manifestPathForTest(), []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}
	st := VerifyDeep()
	if !st.HasFailure(CodeSignatureMissing) {
		t.Errorf("expected SIGNATURE_MISSING on legacy v1, got %v", st.Failures)
	}
	// SIGNATURE_MISSING is soft — does not flip OK on its own. But the
	// PATH check might flip it. We only assert the failure exists.
}

func TestManifestSignature_RejectsDeletedPubKey(t *testing.T) {
	_, shimDir := withTempWatchdogDir(t)
	writeFakeShim(t, shimDir, "npm", "v1\n")
	m, _ := Build()
	if err := WriteManifest(m); err != nil {
		t.Fatal(err)
	}
	// Now delete the public key — verifier has nothing to check
	// against, but the manifest claims to be signed.
	if err := os.Remove(PublicKeyPath()); err != nil {
		t.Fatal(err)
	}
	st := VerifyDeep()
	if !st.HasFailure(CodeSignatureKeyMissing) {
		t.Errorf("expected SIGNATURE_KEY_MISSING after key delete, got %v", st.Failures)
	}
}

// manifestPathForTest avoids importing the paths package here just
// to call ManifestPath; manifest_test.go shares this style.
func manifestPathForTest() string {
	dir := os.Getenv("WATCHDOG_DIR")
	if dir == "" {
		dir = ".watchdog"
	}
	return dir + "/manifest.json"
}
