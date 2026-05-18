package integrity

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"runtime"
	"testing"
)

// withTempWatchdogDir is also used by manifest_test.go; redefining is
// not necessary — we share via the package-level helper there.

func TestLoadOrCreateKey_GeneratesOnFirstCall(t *testing.T) {
	withTempWatchdogDir(t)
	priv, pub, err := LoadOrCreateKey()
	if err != nil {
		t.Fatalf("LoadOrCreateKey: %v", err)
	}
	if len(priv) != ed25519.PrivateKeySize {
		t.Errorf("priv size = %d", len(priv))
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Errorf("pub size = %d", len(pub))
	}
	// Files exist with the right perms.
	st, err := os.Stat(PrivateKeyPath())
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
		t.Errorf("private key perm = %v, want 0600", st.Mode().Perm())
	}
}

func TestLoadOrCreateKey_StableAcrossCalls(t *testing.T) {
	withTempWatchdogDir(t)
	priv1, pub1, err := LoadOrCreateKey()
	if err != nil {
		t.Fatal(err)
	}
	priv2, pub2, err := LoadOrCreateKey()
	if err != nil {
		t.Fatal(err)
	}
	if !equalBytes(priv1, priv2) {
		t.Error("private key changed across LoadOrCreateKey calls")
	}
	if !equalBytes(pub1, pub2) {
		t.Error("public key changed across LoadOrCreateKey calls")
	}
}

func TestLoadPublicKey_MissingFileReturnsIsNotExist(t *testing.T) {
	withTempWatchdogDir(t)
	_, err := LoadPublicKey()
	if !os.IsNotExist(err) {
		t.Errorf("LoadPublicKey on missing = %v, want IsNotExist", err)
	}
}

func TestLoadPublicKey_AfterCreate(t *testing.T) {
	withTempWatchdogDir(t)
	_, pub, err := LoadOrCreateKey()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if !equalBytes(pub, loaded) {
		t.Error("LoadPublicKey returned a different key from LoadOrCreateKey")
	}
}

func TestSignBytes_VerifyBytes_RoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("the canonical manifest bytes")
	sig := SignBytes(priv, msg)
	if err := VerifyBytes(pub, msg, sig); err != nil {
		t.Errorf("verify failed: %v", err)
	}
}

func TestVerifyBytes_RejectsTamperedMessage(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sig := SignBytes(priv, []byte("original"))
	if err := VerifyBytes(pub, []byte("modified"), sig); err == nil {
		t.Error("verify accepted tampered message")
	}
}

func TestVerifyBytes_RejectsTamperedSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sig := SignBytes(priv, []byte("msg"))
	// Flip a bit in the base64 by swapping two characters.
	tampered := "A" + sig[1:]
	if err := VerifyBytes(pub, []byte("msg"), tampered); err == nil {
		t.Error("verify accepted tampered signature")
	}
}

func TestCanonicalJSON_DeterministicAcrossRuns(t *testing.T) {
	type doc struct {
		B string         `json:"b"`
		A map[string]int `json:"a"`
	}
	d := doc{A: map[string]int{"y": 2, "x": 1}, B: "hi"}
	a, _ := CanonicalJSON(d)
	b, _ := CanonicalJSON(d)
	if string(a) != string(b) {
		t.Errorf("CanonicalJSON not deterministic:\n%s\nvs\n%s", a, b)
	}
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
