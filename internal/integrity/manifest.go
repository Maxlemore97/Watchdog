// Package integrity provides the manifest written at install time and
// the verify functions used by every Watchdog entry point.
//
// The threat model is an adversarial agent operating within the same
// user context as Watchdog. Such an adversary can edit files but
// must not be able to silently bypass the protection — every tamper
// step should produce either an audit-log entry, a loud failure, or
// a denied tool call. The manifest is the "this is what should be
// installed" baseline that every hot path verifies against.
//
// Manifest is unsigned in v1. An attacker with filesystem write can
// rewrite both the manifest and the verifier; the deterrent here is
// the audit trail (internal/audit) and that tampering requires
// multiple coordinated edits, not one `rm`.
package integrity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Maxlemore97/watchdog/internal/paths"
	"github.com/Maxlemore97/watchdog/internal/shim"
)

// CurrentVersion is the schema version written by the current code.
// Bump when fields change in incompatible ways. v2 added Signature.
const CurrentVersion = 2

// ProtectiveBinaries lists the binaries whose hashes the manifest
// records. Listed in alphabetical order for deterministic output.
//
// The set is the security-critical subset: anything that decides
// permissions, intercepts installs, or installs/repairs the shim.
// Cosmetic binaries (watchdog-scan, watchdog-action) are excluded
// because they don't run in the hot path of a session.
var ProtectiveBinaries = []string{
	"watchdog-pretool",
	"watchdog-prompt",
	"watchdog-session",
	"watchdog-shim",
	"watchdog-shim-exec",
}

// Manifest is the on-disk record of an install. Stored at
// $WATCHDOG_DIR/manifest.json. Read by every Verify() caller.
type Manifest struct {
	Version     int       `json:"version"`
	InstalledAt time.Time `json:"installed_at"`
	WatchdogDir string    `json:"watchdog_dir"`
	ShimDir     string    `json:"shim_dir"`
	// Binaries maps binary basename → hex sha256. Verify resolves each
	// basename via exec.LookPath at check time.
	Binaries map[string]string `json:"binaries"`
	// Shims maps shim wrapper filename (e.g., "npm", "pip3", "npm.cmd")
	// → hex sha256 of the wrapper file.
	Shims map[string]string `json:"shims"`
	// Signature is a base64-encoded Ed25519 signature over the canonical
	// JSON of every other field (with Signature itself cleared). Written
	// by WriteManifest using the local signing key; verified by
	// LoadManifest. Empty in legacy v1 manifests — Verify reports
	// SIGNATURE_MISSING (soft) so old installs keep working until the
	// next install upgrades them.
	Signature string `json:"signature,omitempty"`
}

// hashFile returns the hex sha256 of the file at path. Returns "" if
// the file cannot be read.
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// resolveBinary finds a watchdog-* binary's absolute path. Prefers a
// sibling of the currently-running executable (so a freshly-built
// tree finds its own binaries even before they're on PATH), and
// falls back to exec.LookPath.
func resolveBinary(name string) string {
	if runtime.GOOS == "windows" && filepath.Ext(name) == "" {
		// Best-effort: also try .exe on Windows.
		if p := resolveBinary(name + ".exe"); p != "" {
			return p
		}
	}
	if self, err := os.Executable(); err == nil {
		sibling := filepath.Join(filepath.Dir(self), name)
		if st, err := os.Stat(sibling); err == nil && !st.IsDir() {
			return sibling
		}
	}
	for _, dir := range strings.Split(os.Getenv("PATH"), string(os.PathListSeparator)) {
		if dir == "" {
			continue
		}
		candidate := filepath.Join(dir, name)
		if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
			return candidate
		}
	}
	return ""
}

// Build constructs a fresh Manifest by scanning the current install
// state. Binaries not found are skipped (not error). Shim wrappers
// are hashed from shimDir; only files that exist are included.
//
// The resulting manifest represents the trusted baseline for this
// install. Pass it to WriteManifest to persist.
func Build() (*Manifest, error) {
	m := &Manifest{
		Version:     CurrentVersion,
		InstalledAt: time.Now().UTC(),
		WatchdogDir: paths.WatchdogDir(),
		ShimDir:     shim.DefaultShimDir(),
		Binaries:    map[string]string{},
		Shims:       map[string]string{},
	}
	if v := os.Getenv("WATCHDOG_SHIM_DIR"); v != "" {
		m.ShimDir = v
	}
	for _, name := range ProtectiveBinaries {
		path := resolveBinary(name)
		if path == "" {
			continue
		}
		sum, err := hashFile(path)
		if err != nil {
			continue
		}
		m.Binaries[name] = sum
	}
	entries, err := os.ReadDir(m.ShimDir)
	if err == nil {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			full := filepath.Join(m.ShimDir, e.Name())
			// Only hash files that bear our shim marker, so user-placed
			// scripts in the shim dir don't pollute the manifest.
			data, err := os.ReadFile(full)
			if err != nil {
				continue
			}
			head := data
			if len(head) > 400 {
				head = head[:400]
			}
			if !strings.Contains(string(head), "Watchdog shim") {
				continue
			}
			sum := sha256.Sum256(data)
			m.Shims[e.Name()] = hex.EncodeToString(sum[:])
		}
	}
	return m, nil
}

// LoadManifest reads the manifest from disk and parses it. Returns a
// concrete error so callers can distinguish "missing" from "corrupt".
func LoadManifest() (*Manifest, error) {
	path := paths.ManifestPath()
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if m.Binaries == nil {
		m.Binaries = map[string]string{}
	}
	if m.Shims == nil {
		m.Shims = map[string]string{}
	}
	return &m, nil
}

// WriteManifest signs m with the local Ed25519 key, then atomically
// writes it via temp + rename. The signing key is created on first
// call (LoadOrCreateKey). On signing failure (e.g., $WATCHDOG_DIR not
// writable), the manifest is written unsigned and the caller's
// integrity check will report SIGNATURE_MISSING.
func WriteManifest(m *Manifest) error {
	dir := paths.WatchdogDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	// Sign before write. Clear any existing Signature field so the
	// canonical bytes are independent of how the caller built m.
	priv, _, err := LoadOrCreateKey()
	if err == nil {
		m.Signature = ""
		canon, cErr := CanonicalJSON(m)
		if cErr == nil {
			m.Signature = SignBytes(priv, canon)
		}
	}
	// If signing failed (no priv key, or canonical-JSON error), leave
	// Signature empty — verify will report SIGNATURE_MISSING. Better
	// than failing install entirely on a key-creation hiccup.

	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	path := paths.ManifestPath()
	tmp := path + "." + strconv.Itoa(os.Getpid()) + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// SortedBinaries returns manifest binary keys in deterministic order.
func (m *Manifest) SortedBinaries() []string {
	out := make([]string, 0, len(m.Binaries))
	for k := range m.Binaries {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// SortedShims returns manifest shim keys in deterministic order.
func (m *Manifest) SortedShims() []string {
	out := make([]string, 0, len(m.Shims))
	for k := range m.Shims {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
