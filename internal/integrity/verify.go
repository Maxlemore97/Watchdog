package integrity

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/Maxlemore97/watchdog/internal/config"
	"github.com/Maxlemore97/watchdog/internal/paths"
	"github.com/Maxlemore97/watchdog/internal/shim"
)

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Failure codes. Stable strings — used in audit log and reason text.
const (
	CodeDisabled            = "DISABLED"
	CodeManifestMissing     = "MANIFEST_MISSING"
	CodeManifestCorrupt     = "MANIFEST_CORRUPT"
	CodePathNotShimFirst    = "PATH_NOT_SHIM_FIRST"
	CodeSelfHashMismatch    = "SELF_HASH_MISMATCH"
	CodeSelfUnknown         = "SELF_UNKNOWN_TO_MANIFEST"
	CodeBinaryMissing       = "BINARY_MISSING"
	CodeBinaryHashMismatch  = "BINARY_HASH_MISMATCH"
	CodeShimMissing         = "SHIM_MISSING"
	CodeShimHashMismatch    = "SHIM_HASH_MISMATCH"
	CodeSignatureMissing    = "SIGNATURE_MISSING"
	CodeSignatureInvalid    = "SIGNATURE_INVALID"
	CodeSignatureKeyMissing = "SIGNATURE_KEY_MISSING"
	CodeBaselineMissing     = "BASELINE_MISSING"
	CodeBaselineInvalid     = "BASELINE_SIGNATURE_INVALID"
	CodeBaselineDrift       = "BASELINE_BINARY_DRIFT"
)

// Failure describes one integrity-check failure. Code is a stable
// machine token; Detail is a human reason.
type Failure struct {
	Code   string `json:"code"`
	Path   string `json:"path,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// Status is the result of a Verify call.
//
// OK == true iff Failures is empty AND Disabled is false.
//
// Disabled is true when WATCHDOG_DISABLE is set. Callers should NOT
// fail-closed in that case (the user opted out); they may still log
// the disabled state to the audit log if desired.
//
// ManifestMissing is true when the manifest file isn't on disk. This
// is distinct from other failures because it can mean either a manual
// install (no `watchdog-shim install` was ever run) or post-install
// tampering. Callers may choose to treat MANIFEST_MISSING as
// non-enforcing (back-compat with pre-integrity installs) while still
// fail-closing on every other failure.
type Status struct {
	OK              bool
	Disabled        bool
	ManifestMissing bool
	Failures        []Failure
}

// HasFailure reports whether any failure with the given code is set.
func (s Status) HasFailure(code string) bool {
	for _, f := range s.Failures {
		if f.Code == code {
			return true
		}
	}
	return false
}

// FirstReason returns a one-line human description of the first
// failure, suitable for a permissionDecisionReason.
func (s Status) FirstReason() string {
	if s.Disabled {
		return "WATCHDOG_DISABLE is set (no integrity enforcement)"
	}
	if len(s.Failures) == 0 {
		return ""
	}
	f := s.Failures[0]
	if f.Detail != "" {
		return fmt.Sprintf("%s — %s", f.Code, f.Detail)
	}
	return f.Code
}

// shimDirForCheck mirrors the resolution in cmd/watchdog-shim-exec
// (and the doctor) so all entry points agree on the shim dir.
func shimDirForCheck(manifest *Manifest) string {
	if v := os.Getenv("WATCHDOG_SHIM_DIR"); v != "" {
		return v
	}
	if manifest != nil && manifest.ShimDir != "" {
		return manifest.ShimDir
	}
	return shim.DefaultShimDir()
}

// selfBinaryName returns the basename of the currently-running
// executable, stripped of a .exe suffix on Windows.
func selfBinaryName() string {
	self, err := os.Executable()
	if err != nil {
		self = os.Args[0]
	}
	name := filepath.Base(self)
	if runtime.GOOS == "windows" {
		for _, ext := range []string{".exe", ".cmd", ".bat"} {
			if len(name) > len(ext) && name[len(name)-len(ext):] == ext {
				return name[:len(name)-len(ext)]
			}
		}
	}
	return name
}

// selfPath returns the absolute path of the currently-running binary,
// resolving any symlink.
func selfPath() string {
	self, err := os.Executable()
	if err != nil {
		return os.Args[0]
	}
	if resolved, err := filepath.EvalSymlinks(self); err == nil {
		return resolved
	}
	return self
}

var (
	cachedStatus     Status
	cachedStatusOnce sync.Once
)

// Verify is the cheap, hot-path integrity check. Intended for every
// PreToolUse and shim invocation. Bounded to a handful of syscalls
// and one self-hash. Result is memoised for the process lifetime.
//
// Checks performed:
//  1. WATCHDOG_DISABLE → return Disabled.
//  2. Manifest exists and parses.
//  3. PATH[0] resolves to the shim dir.
//  4. The currently-running binary's hash matches the manifest entry
//     for its basename. (If the basename is absent from the manifest,
//     that's SELF_UNKNOWN_TO_MANIFEST — soft failure.)
func Verify() Status {
	cachedStatusOnce.Do(func() {
		cachedStatus = computeStatus(false)
	})
	return cachedStatus
}

// VerifyDeep checks everything Verify does plus a full hash sweep of
// all binaries and shim wrappers listed in the manifest. Used by the
// session hook and `watchdog-shim doctor`. Not memoised — call it
// from interactive contexts only.
func VerifyDeep() Status {
	return computeStatus(true)
}

// ResetCache clears the memoised Verify result. Tests use this; not
// part of the hot path.
func ResetCache() {
	cachedStatusOnce = sync.Once{}
	cachedStatus = Status{}
}

func computeStatus(deep bool) Status {
	if config.Disabled() {
		return Status{
			OK:       true,
			Disabled: true,
		}
	}
	st := Status{OK: true}
	m, err := LoadManifest()
	if err != nil {
		if os.IsNotExist(err) {
			st.ManifestMissing = true
			st.Failures = append(st.Failures, Failure{
				Code:   CodeManifestMissing,
				Path:   paths.ManifestPath(),
				Detail: "no manifest at " + paths.ManifestPath(),
			})
		} else {
			st.Failures = append(st.Failures, Failure{
				Code:   CodeManifestCorrupt,
				Path:   paths.ManifestPath(),
				Detail: err.Error(),
			})
		}
		st.OK = false
		return st
	}

	// Manifest signature check. Three cases:
	//   - v1 manifest with no Signature → SIGNATURE_MISSING (soft;
	//     legacy back-compat; doesn't flip OK).
	//   - v2 manifest with bad signature → SIGNATURE_INVALID (hard;
	//     tamper-shaped).
	//   - v2 manifest but ~/.watchdog/.signing.pub absent →
	//     SIGNATURE_KEY_MISSING (hard; tamper-shaped).
	verifyManifestSignature(m, &st)

	// PATH first-position check.
	if !shim.IsShimDirFirstOnPath(shimDirForCheck(m)) {
		st.OK = false
		st.Failures = append(st.Failures, Failure{
			Code:   CodePathNotShimFirst,
			Path:   shimDirForCheck(m),
			Detail: "shim dir is not the first PATH entry",
		})
	}

	// Self-hash check.
	selfName := selfBinaryName()
	if expected, ok := m.Binaries[selfName]; ok {
		actual, herr := hashFile(selfPath())
		if herr != nil {
			st.OK = false
			st.Failures = append(st.Failures, Failure{
				Code: CodeBinaryMissing,
				Path: selfPath(),
				Detail: fmt.Sprintf("could not hash own binary %s: %v",
					selfName, herr),
			})
		} else if actual != expected {
			st.OK = false
			st.Failures = append(st.Failures, Failure{
				Code:   CodeSelfHashMismatch,
				Path:   selfPath(),
				Detail: fmt.Sprintf("%s hash differs from manifest", selfName),
			})
		}
	} else if selfName != "" {
		// Self is not in the manifest. This is a soft failure: maybe
		// the user is running a newer/older build than what was installed.
		st.Failures = append(st.Failures, Failure{
			Code:   CodeSelfUnknown,
			Path:   selfPath(),
			Detail: "self binary " + selfName + " is not in the manifest",
		})
		// Do not flip OK; SELF_UNKNOWN is informational.
	}

	if deep {
		st.OK = deepCheck(m, &st) && st.OK
		// Build-time baseline. No-op when BaselinePubKey is empty
		// (unstamped builds). When it's set and baseline.json exists,
		// reports binary drift against the release-signed baseline.
		st.OK = verifyBaseline(&st) && st.OK
	}
	return st
}

// verifyManifestSignature checks m.Signature against the local public
// key. Appends one of three failure codes; returns nothing because
// the failure mode (soft vs hard) is encoded in the OK flag.
func verifyManifestSignature(m *Manifest, st *Status) {
	if m.Signature == "" {
		// Legacy v1 manifest. Soft failure so old installs keep
		// working; re-running install upgrades them.
		st.Failures = append(st.Failures, Failure{
			Code:   CodeSignatureMissing,
			Path:   paths.ManifestPath(),
			Detail: "manifest has no signature (legacy v1 — re-run watchdog-shim install)",
		})
		return
	}
	pub, err := LoadPublicKey()
	if err != nil {
		// Manifest claims a signature but we have no key to verify.
		// Either the user deleted the .signing.pub file (tamper) or
		// the install never wrote one (key creation failed earlier).
		// Either way, hard failure — we can't tell signed-and-good
		// from signed-and-forged.
		st.OK = false
		st.Failures = append(st.Failures, Failure{
			Code:   CodeSignatureKeyMissing,
			Path:   PublicKeyPath(),
			Detail: "manifest is signed but public key missing: " + err.Error(),
		})
		return
	}
	sig := m.Signature
	m.Signature = ""
	canon, cErr := CanonicalJSON(m)
	m.Signature = sig
	if cErr != nil {
		st.OK = false
		st.Failures = append(st.Failures, Failure{
			Code:   CodeSignatureInvalid,
			Path:   paths.ManifestPath(),
			Detail: "could not re-serialize for verification: " + cErr.Error(),
		})
		return
	}
	if err := VerifyBytes(pub, canon, sig); err != nil {
		st.OK = false
		st.Failures = append(st.Failures, Failure{
			Code:   CodeSignatureInvalid,
			Path:   paths.ManifestPath(),
			Detail: err.Error(),
		})
	}
}

// deepCheck hashes every binary and shim listed in the manifest and
// appends failures to st. Returns true iff no new failures were
// added.
func deepCheck(m *Manifest, st *Status) bool {
	clean := true
	for _, name := range m.SortedBinaries() {
		expected := m.Binaries[name]
		path := resolveBinary(name)
		if path == "" {
			st.Failures = append(st.Failures, Failure{
				Code: CodeBinaryMissing,
				Path: name,
				Detail: fmt.Sprintf("expected binary %s not on PATH or in install dir",
					name),
			})
			clean = false
			continue
		}
		actual, err := hashFile(path)
		if err != nil {
			st.Failures = append(st.Failures, Failure{
				Code:   CodeBinaryMissing,
				Path:   path,
				Detail: fmt.Sprintf("could not hash %s: %v", path, err),
			})
			clean = false
			continue
		}
		if actual != expected {
			st.Failures = append(st.Failures, Failure{
				Code:   CodeBinaryHashMismatch,
				Path:   path,
				Detail: fmt.Sprintf("hash of %s differs from manifest", name),
			})
			clean = false
		}
	}
	for _, fname := range m.SortedShims() {
		expected := m.Shims[fname]
		path := filepath.Join(shimDirForCheck(m), fname)
		data, err := os.ReadFile(path)
		if err != nil {
			st.Failures = append(st.Failures, Failure{
				Code:   CodeShimMissing,
				Path:   path,
				Detail: fmt.Sprintf("shim wrapper %s missing: %v", fname, err),
			})
			clean = false
			continue
		}
		// Cheap inline sha256 of small wrapper bytes.
		actual := sha256Hex(data)
		if actual != expected {
			st.Failures = append(st.Failures, Failure{
				Code:   CodeShimHashMismatch,
				Path:   path,
				Detail: fmt.Sprintf("shim wrapper %s hash differs from manifest", fname),
			})
			clean = false
		}
	}
	return clean
}
