package integrity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Maxlemore97/watchdog/internal/paths"
)

// Key paths under $WATCHDOG_DIR. Private key is 0600 so only the
// owning user can read it; public key is 0644 so any local
// verification path (shim, hooks, future maintenance tools) can
// check signatures without touching the private side.
const (
	privateKeyFilename = ".signing.key"
	publicKeyFilename  = ".signing.pub"
)

// PrivateKeyPath returns the on-disk location of the local signing
// private key.
func PrivateKeyPath() string {
	return filepath.Join(paths.WatchdogDir(), privateKeyFilename)
}

// PublicKeyPath returns the on-disk location of the local signing
// public key.
func PublicKeyPath() string {
	return filepath.Join(paths.WatchdogDir(), publicKeyFilename)
}

// LoadOrCreateKey returns the local Ed25519 keypair, generating one
// on first call. The private key file is created with mode 0600; the
// public key with 0644. Subsequent calls re-load the same pair so
// signatures stay stable across re-installs.
//
// Returns wrapped errors that distinguish "couldn't generate" from
// "couldn't write" — callers (the installer, doctor) log these as
// non-fatal warnings so a write-protected $WATCHDOG_DIR doesn't
// break install entirely.
func LoadOrCreateKey() (ed25519.PrivateKey, ed25519.PublicKey, error) {
	priv, pub, err := loadKey()
	if err == nil {
		return priv, pub, nil
	}
	if !os.IsNotExist(err) {
		return nil, nil, fmt.Errorf("load key: %w", err)
	}
	// First-run generation.
	pubGen, privGen, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}
	if err := persistKey(privGen, pubGen); err != nil {
		return nil, nil, fmt.Errorf("persist key: %w", err)
	}
	return privGen, pubGen, nil
}

// LoadPublicKey reads only the public key. Verification-only paths
// (shim, hooks) use this so they never touch the private side.
//
// Returns os.IsNotExist when the file is absent so callers can
// distinguish "no install signing" from "I/O error".
func LoadPublicKey() (ed25519.PublicKey, error) {
	data, err := os.ReadFile(PublicKeyPath())
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key wrong size: got %d, want %d",
			len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

func loadKey() (ed25519.PrivateKey, ed25519.PublicKey, error) {
	privData, err := os.ReadFile(PrivateKeyPath())
	if err != nil {
		return nil, nil, err
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(privData)))
	if err != nil {
		return nil, nil, fmt.Errorf("decode private key: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, nil, fmt.Errorf("private key wrong size: got %d, want %d",
			len(seed), ed25519.SeedSize)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return priv, pub, nil
}

func persistKey(priv ed25519.PrivateKey, pub ed25519.PublicKey) error {
	if len(priv) != ed25519.PrivateKeySize || len(pub) != ed25519.PublicKeySize {
		return errors.New("invalid key sizes")
	}
	if err := os.MkdirAll(paths.WatchdogDir(), 0o755); err != nil {
		return err
	}
	// Store the seed (32 bytes) rather than the full private key (64
	// bytes); ed25519.NewKeyFromSeed reconstructs the rest. Smaller
	// on-disk footprint and matches the OpenSSH/age convention.
	seed := priv.Seed()
	privB64 := base64.StdEncoding.EncodeToString(seed)
	if err := writeFile0600(PrivateKeyPath(), []byte(privB64+"\n")); err != nil {
		return err
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	return os.WriteFile(PublicKeyPath(), []byte(pubB64+"\n"), 0o644)
}

// writeFile0600 atomically writes data with mode 0600. Creates the
// file fresh so a previous larger file's tail can't leak.
func writeFile0600(path string, data []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}
