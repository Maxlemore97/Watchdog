package selfupdate

import (
	"archive/tar"
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

// buildArchive returns a gzipped tarball containing the requested
// (name → bytes) entries with mode 0755. Used by the integration
// tests to stand up a fake GitHub release.
func buildArchive(t *testing.T, entries map[string][]byte) []byte {
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

// fakeRelease stands up an httptest server that serves the two URLs
// Resolve+Apply need: the latest-tag JSON and the archive + checksums
// pair for a given tag.
func fakeRelease(t *testing.T, tag string, archiveBytes []byte) (apiURL, baseURL, archiveName string) {
	t.Helper()
	osName, archName := runtime.GOOS, runtime.GOARCH
	bare := strings.TrimPrefix(tag, "v")
	archiveName = fmt.Sprintf("watchdog_%s_%s_%s.tar.gz", bare, osName, archName)
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
	if !strings.HasSuffix(p.Archive, ".tar.gz") || !strings.Contains(p.Archive, "1.2.3") {
		t.Errorf("archive = %q", p.Archive)
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
	if runtime.GOOS == "windows" {
		t.Skip("self-update Apply not supported on Windows")
	}
	dir := t.TempDir()
	entries := map[string][]byte{}
	for _, b := range Binaries {
		entries[b] = []byte("#!/bin/sh\nexit 0\n")
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
		st, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Errorf("%s missing: %v", name, err)
			continue
		}
		if st.Mode().Perm()&0o100 == 0 {
			t.Errorf("%s not executable: %v", name, st.Mode())
		}
	}
}

func TestApply_RejectsChecksumMismatch(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip()
	}
	dir := t.TempDir()
	good := buildArchive(t, map[string][]byte{"watchdog-shim": []byte("hi")})
	// serve a checksums.txt whose hash matches `good`, but serve a
	// *different* archive — that's the on-the-wire tamper we're
	// guarding against.
	osName, archName := runtime.GOOS, runtime.GOARCH
	archive := fmt.Sprintf("watchdog_8.8.8_%s_%s.tar.gz", osName, archName)
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
	if runtime.GOOS == "windows" {
		t.Skip()
	}
	dir := t.TempDir()
	tag := "v0.0.1"
	_, baseURL, _ := fakeRelease(t, tag, buildArchive(t, map[string][]byte{"watchdog-shim": []byte("x")}))
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
	if runtime.GOOS == "windows" {
		t.Skip()
	}
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

func TestExtractTarGz_RejectsPathTraversal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip()
	}
	dir := t.TempDir()
	bad := buildArchive(t, map[string][]byte{"../escape": []byte("nope")})
	archivePath := filepath.Join(dir, "bad.tar.gz")
	if err := os.WriteFile(archivePath, bad, 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")
	if err := os.Mkdir(out, 0o755); err != nil {
		t.Fatal(err)
	}
	err := extractTarGz(archivePath, out)
	if err == nil || !strings.Contains(err.Error(), "escape") {
		t.Errorf("expected escape rejection, got %v", err)
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
