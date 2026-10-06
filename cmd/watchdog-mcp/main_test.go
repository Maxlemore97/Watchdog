package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestRequireBearer(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	h := requireBearer("s3cret-token-0123456789abcdef0123", ok)
	cases := []struct {
		name, auth, origin string
		want               int
	}{
		{"no token", "", "", http.StatusUnauthorized},
		{"wrong token", "Bearer nope", "", http.StatusUnauthorized},
		{"basic scheme", "Basic s3cret-token-0123456789abcdef0123", "", http.StatusUnauthorized},
		{"browser origin", "Bearer s3cret-token-0123456789abcdef0123", "https://evil.example", http.StatusForbidden},
		{"valid", "Bearer s3cret-token-0123456789abcdef0123", "", http.StatusOK},
	}
	t.Setenv("WATCHDOG_AUDIT_LOG", filepath.Join(t.TempDir(), "audit.jsonl"))
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		if tc.auth != "" {
			req.Header.Set("Authorization", tc.auth)
		}
		if tc.origin != "" {
			req.Header.Set("Origin", tc.origin)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Errorf("%s: status %d, want %d", tc.name, rec.Code, tc.want)
		}
	}
}

func TestDaemonToken_CreatedPrivateAndStable(t *testing.T) {
	t.Setenv("WATCHDOG_DIR", t.TempDir())
	tok1, err := loadOrCreateDaemonToken()
	if err != nil {
		t.Fatal(err)
	}
	if len(tok1) < 32 {
		t.Fatalf("token too short: %q", tok1)
	}
	tok2, _ := loadOrCreateDaemonToken()
	if tok1 != tok2 {
		t.Error("token not persisted across starts")
	}
	if runtime.GOOS != "windows" {
		st, err := os.Stat(daemonTokenPath())
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Errorf("token file mode %v, want 0600", st.Mode().Perm())
		}
	}
}

func TestBuildDaemonListener_RefusesNonLoopback(t *testing.T) {
	for _, addr := range []string{"tcp://0.0.0.0:0", "tcp://192.168.1.10:0", "tcp://example.com:0", "http://127.0.0.1:0"} {
		if l, _, err := buildDaemonListener(addr); err == nil {
			l.Close()
			t.Errorf("buildDaemonListener(%q) accepted", addr)
		}
	}
	l, disp, err := buildDaemonListener("tcp://127.0.0.1:0")
	if err != nil {
		t.Fatalf("loopback refused: %v", err)
	}
	l.Close()
	if disp == "" {
		t.Error("empty display addr")
	}
}

func TestBuildDaemonListener_UnixSocketPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permissions")
	}
	// Short dir: unix socket paths are limited to ~104 bytes on macOS.
	dir, err := os.MkdirTemp("/tmp", "wdmcp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "sub", "mcp.sock")
	l, _, err := buildDaemonListener("unix://" + sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	st, err := os.Stat(sock)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		t.Errorf("socket mode %v is accessible to group/other", st.Mode().Perm())
	}
	dst, _ := os.Stat(filepath.Dir(sock))
	if dst.Mode().Perm()&0o077 != 0 {
		t.Errorf("socket dir mode %v is accessible to group/other", dst.Mode().Perm())
	}
}
