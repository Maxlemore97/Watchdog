package integrity

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"crypto/ed25519"

	"github.com/Maxlemore97/watchdog/internal/paths"
)

// BaselinePubKey is the base64-encoded Ed25519 public key the release
// build uses to sign baseline.json. Stamped into each binary at
// release time via -ldflags '-X .../integrity.BaselinePubKey=…'. Empty
// in unstamped builds (go install without ldflags); in that case
// baseline verification is a silent no-op.
//
// This is independent of the local signing key (.signing.pub). The
// local key proves the dynamic manifest hasn't been tampered with;
// the baseline pubkey proves the installed binaries are the bytes
// the release pipeline produced. Together they cover both ends:
// "did someone edit the manifest?" and "did someone swap a binary?".
var BaselinePubKey = ""

// Baseline is the release-time record of which binary hashes are
// expected. Distributed alongside the binaries as baseline.json under
// $WATCHDOG_DIR (placed by the install script after fetching from
// the release archive). Signed with the release private key, which
// never lives on a user machine.
type Baseline struct {
	Version   string            `json:"version"`
	Binaries  map[string]string `json:"binaries"` // basename → sha256 hex
	Signature string            `json:"signature,omitempty"`
}

// BaselinePath returns the on-disk location of baseline.json.
func BaselinePath() string {
	return filepath.Join(paths.WatchdogDir(), "baseline.json")
}

// verifyBaseline is called from VerifyDeep when --deep is set. It
// returns true iff no new failures were added. Empty BaselinePubKey
// (unstamped build) → silent skip → returns true. Missing
// baseline.json → BASELINE_MISSING (warn-shaped; flips OK because
// the user got a stamped binary but no baseline so something is off).
func verifyBaseline(st *Status) bool {
	if BaselinePubKey == "" {
		// Unstamped build — release-pubkey signing is not in effect.
		// Skip silently. Doctor will surface this elsewhere via
		// "watchdog-shim version: dev".
		return true
	}
	data, err := os.ReadFile(BaselinePath())
	if err != nil {
		if os.IsNotExist(err) {
			st.Failures = append(st.Failures, Failure{
				Code: CodeBaselineMissing,
				Path: BaselinePath(),
				Detail: "release-signed baseline.json not found; install script " +
					"should have placed it alongside the manifest",
			})
			return false
		}
		st.Failures = append(st.Failures, Failure{
			Code:   CodeBaselineMissing,
			Path:   BaselinePath(),
			Detail: err.Error(),
		})
		return false
	}
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		st.Failures = append(st.Failures, Failure{
			Code:   CodeBaselineInvalid,
			Path:   BaselinePath(),
			Detail: "parse baseline.json: " + err.Error(),
		})
		return false
	}

	// Verify the baseline's own signature against the embedded
	// release public key.
	pub, err := decodeBaselinePubKey()
	if err != nil {
		st.Failures = append(st.Failures, Failure{
			Code:   CodeBaselineInvalid,
			Path:   BaselinePath(),
			Detail: "embedded baseline pubkey malformed: " + err.Error(),
		})
		return false
	}
	sig := b.Signature
	b.Signature = ""
	canon, err := CanonicalJSON(&b)
	b.Signature = sig
	if err != nil {
		st.Failures = append(st.Failures, Failure{
			Code:   CodeBaselineInvalid,
			Path:   BaselinePath(),
			Detail: "re-serialize for verify: " + err.Error(),
		})
		return false
	}
	if err := VerifyBytes(pub, canon, sig); err != nil {
		st.Failures = append(st.Failures, Failure{
			Code:   CodeBaselineInvalid,
			Path:   BaselinePath(),
			Detail: err.Error(),
		})
		return false
	}

	// Per-binary drift check.
	clean := true
	for name, expected := range b.Binaries {
		path := resolveBinary(name)
		if path == "" {
			// Missing binary is reported by VerifyDeep already; skip
			// here to avoid double-reporting.
			continue
		}
		actual, err := hashFile(path)
		if err != nil || actual != expected {
			st.Failures = append(st.Failures, Failure{
				Code:   CodeBaselineDrift,
				Path:   path,
				Detail: fmt.Sprintf("%s hash differs from release baseline", name),
			})
			clean = false
		}
	}
	return clean
}

func decodeBaselinePubKey() (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(BaselinePubKey)
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("baseline pubkey wrong size: got %d, want %d",
			len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}
