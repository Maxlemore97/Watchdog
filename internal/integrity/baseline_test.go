package integrity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// withBaselinePubKey sets and restores the package-level BaselinePubKey
// for the duration of one test.
func withBaselinePubKey(t *testing.T, key string) {
	t.Helper()
	prev := BaselinePubKey
	BaselinePubKey = key
	t.Cleanup(func() { BaselinePubKey = prev })
}

func TestVerifyBaseline_SilentSkipWhenPubKeyUnset(t *testing.T) {
	withTempWatchdogDir(t)
	withBaselinePubKey(t, "")
	var st Status
	if !verifyBaseline(&st) {
		t.Error("expected silent skip on unstamped build")
	}
	if len(st.Failures) != 0 {
		t.Errorf("expected no failures, got %v", st.Failures)
	}
}

func TestVerifyBaseline_MissingBaselineFile(t *testing.T) {
	withTempWatchdogDir(t)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	withBaselinePubKey(t, base64.StdEncoding.EncodeToString(pub))
	var st Status
	if verifyBaseline(&st) {
		t.Error("expected fail when baseline missing")
	}
	if !st.HasFailure(CodeBaselineMissing) {
		t.Errorf("expected BASELINE_MISSING, got %v", st.Failures)
	}
}

func TestVerifyBaseline_ValidSignatureAndNoDrift(t *testing.T) {
	dir, _ := withTempWatchdogDir(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	withBaselinePubKey(t, base64.StdEncoding.EncodeToString(pub))

	// Write a baseline that references a fake binary we'll place
	// alongside.
	fakeBin := filepath.Join(dir, "watchdog-pretool")
	if err := os.WriteFile(fakeBin, []byte("fake binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Hash it the same way the verifier does (via resolveBinary).
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	expectedHash, err := hashFile(fakeBin)
	if err != nil {
		t.Fatal(err)
	}

	b := Baseline{
		Version: "v0.test",
		Binaries: map[string]string{
			"watchdog-pretool": expectedHash,
		},
	}
	canon, _ := CanonicalJSON(&b)
	b.Signature = SignBytes(priv, canon)
	data, _ := json.MarshalIndent(&b, "", "  ")
	if err := os.WriteFile(BaselinePath(), data, 0o644); err != nil {
		t.Fatal(err)
	}

	var st Status
	if !verifyBaseline(&st) {
		t.Errorf("expected clean baseline, got failures: %v", st.Failures)
	}
}

func TestVerifyBaseline_DetectsBinaryDrift(t *testing.T) {
	dir, _ := withTempWatchdogDir(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	withBaselinePubKey(t, base64.StdEncoding.EncodeToString(pub))

	// Baseline records one hash; on-disk binary has a DIFFERENT hash.
	fakeBin := filepath.Join(dir, "watchdog-pretool")
	if err := os.WriteFile(fakeBin, []byte("modified bytes"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	b := Baseline{
		Version: "v0.test",
		Binaries: map[string]string{
			"watchdog-pretool": "0000000000000000000000000000000000000000000000000000000000000000",
		},
	}
	canon, _ := CanonicalJSON(&b)
	b.Signature = SignBytes(priv, canon)
	data, _ := json.MarshalIndent(&b, "", "  ")
	if err := os.WriteFile(BaselinePath(), data, 0o644); err != nil {
		t.Fatal(err)
	}

	var st Status
	if verifyBaseline(&st) {
		t.Error("expected drift detection")
	}
	if !st.HasFailure(CodeBaselineDrift) {
		t.Errorf("expected BASELINE_BINARY_DRIFT, got %v", st.Failures)
	}
}

func TestVerifyBaseline_RejectsWrongSignature(t *testing.T) {
	withTempWatchdogDir(t)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	withBaselinePubKey(t, base64.StdEncoding.EncodeToString(pub))

	// Baseline signed with a DIFFERENT key.
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	b := Baseline{Version: "v0.test", Binaries: map[string]string{}}
	canon, _ := CanonicalJSON(&b)
	b.Signature = SignBytes(otherPriv, canon)
	data, _ := json.MarshalIndent(&b, "", "  ")
	if err := os.WriteFile(BaselinePath(), data, 0o644); err != nil {
		t.Fatal(err)
	}

	var st Status
	if verifyBaseline(&st) {
		t.Error("expected verify failure on wrong signature")
	}
	if !st.HasFailure(CodeBaselineInvalid) {
		t.Errorf("expected BASELINE_SIGNATURE_INVALID, got %v", st.Failures)
	}
}
