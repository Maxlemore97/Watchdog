package selfupdate

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// buildArchive returns the host-OS-appropriate archive (zip on
// Windows, tar.gz elsewhere) containing the requested entries with
// mode 0755. Mirrors goreleaser's platform-conditional archive
// format so the test exercises the same extraction path the
// production binary takes.
func buildArchive(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	if runtime.GOOS == "windows" {
		return buildZip(t, entries)
	}
	return buildTarGz(t, entries)
}

func buildTarGz(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range entries {
		hdr := &tar.Header{
			Name:     name,
			Mode:     0o755,
			Size:     int64(len(body)),
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildZip(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range entries {
		hdr := &zip.FileHeader{Name: name, Method: zip.Deflate}
		hdr.SetMode(0o755)
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// archiveSuffix returns the host-OS archive extension. Matches the
// suffix Resolve computes so tests built via fakeRelease line up.
func archiveSuffix() string {
	if runtime.GOOS == "windows" {
		return "zip"
	}
	return "tar.gz"
}

// archiveBinaryName returns the platform-specific binary filename
// inside the archive. Windows builds get `.exe`; POSIX builds do not.
func archiveBinaryName(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}

// fakeRelease stands up an httptest server that serves the two URLs
// Resolve+Apply need: the latest-tag JSON and the archive + checksums
// pair for a given tag.
func fakeRelease(t *testing.T, tag string, archiveBytes []byte) (apiURL, baseURL, archiveName string) {
	t.Helper()
	osName, archName := runtime.GOOS, runtime.GOARCH
	bare := strings.TrimPrefix(tag, "v")
	archiveName = fmt.Sprintf("watchdog_%s_%s_%s.%s", bare, osName, archName, archiveSuffix())
	sum := sha256.Sum256(archiveBytes)
	sumHex := hex.EncodeToString(sum[:])
	checksums := []byte(fmt.Sprintf("%s  %s\n", sumHex, archiveName))

	mux := http.NewServeMux()
	mux.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"tag_name": tag})
	})
	mux.HandleFunc(fmt.Sprintf("/%s/releases/download/%s/%s", Repo, tag, archiveName), func(w http.ResponseWriter, r *http.Request) {
		w.Write(archiveBytes)
	})
	mux.HandleFunc(fmt.Sprintf("/%s/releases/download/%s/checksums.txt", Repo, tag), func(w http.ResponseWriter, r *http.Request) {
		w.Write(checksums)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL + "/api", srv.URL, archiveName
}

func TestResolve_PinsExplicitVersion(t *testing.T) {
	p, err := Resolve(Options{TargetVersion: "v1.2.3", InstallDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if p.Target != "v1.2.3" {
		t.Errorf("target = %q", p.Target)
	}
	wantSuffix := "." + archiveSuffix()
	if !strings.HasSuffix(p.Archive, wantSuffix) || !strings.Contains(p.Archive, "1.2.3") {
		t.Errorf("archive = %q (want suffix %q, contain %q)", p.Archive, wantSuffix, "1.2.3")
	}
}

func TestResolve_AddsVPrefix(t *testing.T) {
	p, err := Resolve(Options{TargetVersion: "1.2.3", InstallDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if p.Target != "v1.2.3" {
		t.Errorf("target = %q (expected v-prefix)", p.Target)
	}
}

func TestResolve_DetectsNoOpOnExactMatch(t *testing.T) {
	p, err := Resolve(Options{CurrentVersion: "v0.9.5", TargetVersion: "v0.9.5", InstallDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if !p.NoOp {
		t.Error("expected NoOp=true for same version without --force")
	}
}

func TestResolve_ForceOverridesNoOp(t *testing.T) {
	p, err := Resolve(Options{CurrentVersion: "v0.9.5", TargetVersion: "v0.9.5", Force: true, InstallDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if p.NoOp {
		t.Error("expected NoOp=false under Force")
	}
}

func TestResolve_DetectsDowngrade(t *testing.T) {
	p, err := Resolve(Options{CurrentVersion: "v0.9.7", TargetVersion: "v0.9.5", InstallDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Downgrade {
		t.Error("expected Downgrade=true")
	}
}

func TestResolve_NewerNotDowngrade(t *testing.T) {
	p, err := Resolve(Options{CurrentVersion: "v0.9.5", TargetVersion: "v0.9.7", InstallDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if p.Downgrade {
		t.Error("upgrade should not be flagged downgrade")
	}
}

func TestApply_HappyPath(t *testing.T) {
	dir := t.TempDir()
	entries := map[string][]byte{}
	for _, b := range Binaries {
		entries[archiveBinaryName(b)] = []byte("#!/bin/sh\nexit 0\n")
	}
	tag := "v9.9.9"
	apiURL, baseURL, _ := fakeRelease(t, tag, buildArchive(t, entries))

	plan, err := Resolve(Options{
		CurrentVersion: "v0.0.1",
		TargetVersion:  tag,
		InstallDir:     dir,
		BaseURL:        baseURL,
		APIURL:         apiURL,
	})
	if err != nil {
		t.Fatal(err)
	}
	installed, err := plan.Apply(&bytes.Buffer{}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(installed) != len(Binaries) {
		t.Errorf("installed %d, expected %d", len(installed), len(Binaries))
	}
	for _, name := range Binaries {
		st, err := os.Stat(filepath.Join(dir, archiveBinaryName(name)))
		if err != nil {
			t.Errorf("%s missing: %v", name, err)
			continue
		}
		// Windows ignores Unix execute bits but the file should exist
		// and be non-empty.
		if runtime.GOOS != "windows" && st.Mode().Perm()&0o100 == 0 {
			t.Errorf("%s not executable: %v", name, st.Mode())
		}
		if st.Size() == 0 {
			t.Errorf("%s is empty", name)
		}
	}
}

func TestApply_RejectsChecksumMismatch(t *testing.T) {
	dir := t.TempDir()
	good := buildArchive(t, map[string][]byte{archiveBinaryName("watchdog-shim"): []byte("hi")})
	// serve a checksums.txt whose hash matches `good`, but serve a
	// *different* archive — that's the on-the-wire tamper we're
	// guarding against.
	osName, archName := runtime.GOOS, runtime.GOARCH
	archive := fmt.Sprintf("watchdog_8.8.8_%s_%s.%s", osName, archName, archiveSuffix())
	sum := sha256.Sum256(good)
	sumHex := hex.EncodeToString(sum[:])
	bad := []byte("wrong bytes")

	mux := http.NewServeMux()
	mux.HandleFunc(fmt.Sprintf("/%s/releases/download/v8.8.8/%s", Repo, archive), func(w http.ResponseWriter, r *http.Request) {
		w.Write(bad)
	})
	mux.HandleFunc(fmt.Sprintf("/%s/releases/download/v8.8.8/checksums.txt", Repo), func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s  %s\n", sumHex, archive)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	plan, err := Resolve(Options{TargetVersion: "v8.8.8", InstallDir: dir, BaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	_, err = plan.Apply(&bytes.Buffer{}, Options{})
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Errorf("expected checksum mismatch error, got %v", err)
	}
}

func TestApply_RefusesDowngradeWithoutForce(t *testing.T) {
	dir := t.TempDir()
	tag := "v0.0.1"
	_, baseURL, _ := fakeRelease(t, tag, buildArchive(t, map[string][]byte{archiveBinaryName("watchdog-shim"): []byte("x")}))
	plan, err := Resolve(Options{
		CurrentVersion: "v0.9.9",
		TargetVersion:  tag,
		InstallDir:     dir,
		BaseURL:        baseURL,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = plan.Apply(&bytes.Buffer{}, Options{})
	if err == nil || !strings.Contains(err.Error(), "downgrade") {
		t.Errorf("expected downgrade refusal, got %v", err)
	}
}

func TestApply_NoOpSkipsDownload(t *testing.T) {
	dir := t.TempDir()
	plan, err := Resolve(Options{
		CurrentVersion: "v0.9.7",
		TargetVersion:  "v0.9.7",
		InstallDir:     dir,
		// Deliberately point BaseURL at an unreachable address. If
		// Apply skips the download path it never trips this.
		BaseURL: "http://127.0.0.1:1",
	})
	if err != nil {
		t.Fatal(err)
	}
	buf := &bytes.Buffer{}
	installed, err := plan.Apply(buf, Options{})
	if err != nil {
		t.Fatalf("noop apply should succeed: %v", err)
	}
	if len(installed) != 0 {
		t.Error("noop should install nothing")
	}
	if !strings.Contains(buf.String(), "already on") {
		t.Errorf("expected 'already on' note, got %q", buf.String())
	}
}

func TestExtractArchive_RejectsPathTraversal(t *testing.T) {
	dir := t.TempDir()
	bad := buildArchive(t, map[string][]byte{"../escape": []byte("nope")})
	suffix := archiveSuffix()
	archivePath := filepath.Join(dir, "bad."+suffix)
	if err := os.WriteFile(archivePath, bad, 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")
	if err := os.Mkdir(out, 0o755); err != nil {
		t.Fatal(err)
	}
	err := extractArchive(archivePath, out)
	if err == nil || !strings.Contains(err.Error(), "escape") {
		t.Errorf("expected escape rejection, got %v", err)
	}
}

// TestAtomicReplace_WindowsRenamesExistingAside pins the Windows
// self-overwrite workaround. On POSIX, rename-over-existing is
// atomic and leaves no .old file. On Windows, the prior dst is
// renamed to dst+".old" first so the path frees up for the staged
// .new file. The test runs everywhere and asserts the per-OS
// invariant.
func TestAtomicReplace_WindowsRenamesExistingAside(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "watchdog-shim")
	if runtime.GOOS == "windows" {
		dst += ".exe"
	}
	if err := os.WriteFile(dst, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	stage := dst + ".new"
	if err := os.WriteFile(stage, []byte("new"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := atomicReplace(stage, dst); err != nil {
		t.Fatalf("atomicReplace: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil || string(got) != "new" {
		t.Errorf("dst contents = %q (err=%v), want %q", got, err, "new")
	}
	oldPath := dst + ".old"
	if runtime.GOOS == "windows" {
		if _, err := os.Stat(oldPath); err != nil {
			t.Errorf("Windows path: expected %s (rename-aside), missing: %v", oldPath, err)
		}
	} else {
		if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
			t.Errorf("POSIX path: no .old should exist; got err=%v", err)
		}
	}
}

func TestFetchLatestTag_ParsesGitHubResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `{"tag_name":"v1.2.3"}`)
	}))
	t.Cleanup(srv.Close)
	tag, err := fetchLatestTag(Options{APIURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if tag != "v1.2.3" {
		t.Errorf("tag = %q", tag)
	}
}
