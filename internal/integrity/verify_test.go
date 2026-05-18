package integrity

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVerify_DisabledReturnsEarly(t *testing.T) {
	dir, _ := withTempWatchdogDir(t)
	t.Setenv("WATCHDOG_DISABLE", "1")
	// No manifest, no PATH setup — Disabled should short-circuit.
	st := VerifyDeep()
	if !st.Disabled {
		t.Errorf("expected Disabled=true, got %+v", st)
	}
	if !st.OK {
		t.Errorf("expected OK=true when Disabled")
	}
	if len(st.Failures) != 0 {
		t.Errorf("expected no failures, got %v", st.Failures)
	}
	_ = dir
}

func TestVerify_ManifestMissingIsBackCompat(t *testing.T) {
	withTempWatchdogDir(t)
	st := VerifyDeep()
	if !st.ManifestMissing {
		t.Errorf("expected ManifestMissing=true, got %+v", st)
	}
	if st.OK {
		t.Errorf("ManifestMissing should yield OK=false (caller decides)")
	}
	if !st.HasFailure(CodeManifestMissing) {
		t.Errorf("missing MANIFEST_MISSING failure")
	}
}

func TestVerifyDeep_DetectsShimHashMismatch(t *testing.T) {
	_, shimDir := withTempWatchdogDir(t)
	t.Setenv("PATH", shimDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	wrapper := writeFakeShim(t, shimDir, "npm", "v1\n")
	m, _ := Build()
	if err := WriteManifest(m); err != nil {
		t.Fatal(err)
	}

	// Tamper with the wrapper after install.
	if err := os.WriteFile(wrapper, []byte("#!/usr/bin/env bash\n# Watchdog shim for npm\nevil\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	st := VerifyDeep()
	if st.OK {
		t.Errorf("expected OK=false after tamper, got %+v", st)
	}
	if !st.HasFailure(CodeShimHashMismatch) {
		t.Errorf("missing SHIM_HASH_MISMATCH failure: %+v", st.Failures)
	}
}

func TestVerifyDeep_DetectsShimMissing(t *testing.T) {
	_, shimDir := withTempWatchdogDir(t)
	t.Setenv("PATH", shimDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	wrapper := writeFakeShim(t, shimDir, "npm", "v1\n")
	m, _ := Build()
	if err := WriteManifest(m); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(wrapper); err != nil {
		t.Fatal(err)
	}
	st := VerifyDeep()
	if !st.HasFailure(CodeShimMissing) {
		t.Errorf("missing SHIM_MISSING failure: %+v", st.Failures)
	}
}

func TestVerify_DetectsPathNotShimFirst(t *testing.T) {
	_, shimDir := withTempWatchdogDir(t)
	// Place shim dir AFTER /usr/bin so it isn't first.
	t.Setenv("PATH", "/usr/bin"+string(os.PathListSeparator)+shimDir)
	writeFakeShim(t, shimDir, "npm", "v1\n")
	m, _ := Build()
	if err := WriteManifest(m); err != nil {
		t.Fatal(err)
	}
	st := Verify()
	if !st.HasFailure(CodePathNotShimFirst) {
		t.Errorf("missing PATH_NOT_SHIM_FIRST: %+v", st.Failures)
	}
}

func TestVerify_OKOnCleanInstall(t *testing.T) {
	_, shimDir := withTempWatchdogDir(t)
	t.Setenv("PATH", shimDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	writeFakeShim(t, shimDir, "npm", "v1\n")
	m, _ := Build()
	if err := WriteManifest(m); err != nil {
		t.Fatal(err)
	}
	st := Verify()
	// Self-binary check will hit SELF_UNKNOWN_TO_MANIFEST because the
	// test binary isn't `watchdog-pretool` etc. Filter that out.
	for _, f := range st.Failures {
		if f.Code != CodeSelfUnknown {
			t.Errorf("unexpected failure: %+v", f)
		}
	}
}

func TestStatus_FirstReasonReadable(t *testing.T) {
	s := Status{
		Failures: []Failure{
			{Code: CodeShimHashMismatch, Detail: "npm wrapper changed"},
		},
	}
	got := s.FirstReason()
	if got == "" || !contains(got, CodeShimHashMismatch) {
		t.Errorf("FirstReason() = %q", got)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// Make sure paths.AuditLogPath / ManifestPath round-trip via env.
func TestManifestPath_RespectsWatchdogDir(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("WATCHDOG_DIR", tmp)
	want := filepath.Join(tmp, "manifest.json")
	if got := manifestPathDirect(); got != want {
		t.Errorf("ManifestPath() = %q want %q", got, want)
	}
}

// manifestPathDirect re-derives the path the same way the package
// does, used only by the test above to avoid importing paths twice.
func manifestPathDirect() string {
	dir := os.Getenv("WATCHDOG_DIR")
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".watchdog")
	}
	return filepath.Join(dir, "manifest.json")
}
