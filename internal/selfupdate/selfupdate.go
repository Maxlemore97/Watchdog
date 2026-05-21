// Package selfupdate downloads a newer Watchdog release from GitHub
// and atomically replaces the on-disk binaries.
//
// Mirrors the install.sh contract: same tarball naming, same
// checksums.txt format, same binary set. Lives in Go so that
//
//   - `watchdog-shim update` can do the right thing without forcing
//     the user to remember the install.sh one-liner, and
//   - the update flow can regenerate the integrity manifest in the
//     same process, closing a window where the wrappers would point
//     at a stale binary hash.
//
// Stdlib-only by design — the engine guarantee.
package selfupdate

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Repo is the GitHub repository in `owner/name` form. Kept exported
// so tests can swap it out via Options without env-var gymnastics.
const Repo = "Maxlemore97/Watchdog"

// Binaries are the Go binaries shipped in every release tarball. Kept
// in sync with install.sh's loop. Order matches the release manifest
// and matters only for printed output.
var Binaries = []string{
	"watchdog-pretool",
	"watchdog-session",
	"watchdog-prompt",
	"watchdog-scan",
	"watchdog-mcp",
	"watchdog-shim",
	"watchdog-shim-exec",
	"watchdog-action",
}

// Options tunes a single update run.
type Options struct {
	// CurrentVersion is the version the running binary reports. Used
	// to short-circuit "already on target" and to refuse downgrades
	// unless Force is set.
	CurrentVersion string

	// TargetVersion pins the install to a specific tag (e.g. "v0.9.5").
	// Empty = resolve the latest stable tag from the GitHub API.
	TargetVersion string

	// InstallDir is where binaries land. Empty = derive from the
	// running binary's location (so updating from ~/.local/bin
	// rewrites the same dir).
	InstallDir string

	// Force allows reinstalling the current version (to heal a
	// corrupted install) and allows downgrades.
	Force bool

	// CheckOnly resolves current vs latest, prints, and returns
	// without downloading.
	CheckOnly bool

	// BaseURL overrides the GitHub host. Tests set this to an
	// httptest.NewServer URL; production callers leave empty.
	BaseURL string
	APIURL  string

	// HTTPClient lets tests inject a stub. Production callers leave
	// nil to use the package default (which sets a sane timeout).
	HTTPClient *http.Client
}

// Plan is the resolved set of decisions before any I/O against the
// install dir. Building this in a separate step makes --check cheap
// (planning ≠ installing) and the dry-run path explicit.
type Plan struct {
	Current    string
	Target     string
	OS         string
	Arch       string
	Archive    string
	ArchiveURL string
	SumsURL    string
	InstallDir string
	NoOp       bool // current == target && !Force
	Downgrade  bool // target < current (semantically)
}

// Resolve builds a Plan from Options. Does network I/O only when
// TargetVersion is empty (the latest-tag lookup); otherwise pure.
// Returns an error for unsupported OS/arch, ambiguous install dir,
// or an unresolvable target tag.
func Resolve(opts Options) (*Plan, error) {
	osName, archName, err := detectOSArch()
	if err != nil {
		return nil, err
	}
	target := strings.TrimSpace(opts.TargetVersion)
	if target == "" {
		latest, err := fetchLatestTag(opts)
		if err != nil {
			return nil, err
		}
		target = latest
	}
	if !strings.HasPrefix(target, "v") {
		target = "v" + target
	}
	dir := opts.InstallDir
	if dir == "" {
		dir = defaultInstallDir()
	}
	bare := strings.TrimPrefix(target, "v")
	archive := fmt.Sprintf("watchdog_%s_%s_%s.tar.gz", bare, osName, archName)
	base := opts.BaseURL
	if base == "" {
		base = "https://github.com"
	}
	plan := &Plan{
		Current:    strings.TrimSpace(opts.CurrentVersion),
		Target:     target,
		OS:         osName,
		Arch:       archName,
		Archive:    archive,
		ArchiveURL: fmt.Sprintf("%s/%s/releases/download/%s/%s", base, Repo, target, archive),
		SumsURL:    fmt.Sprintf("%s/%s/releases/download/%s/checksums.txt", base, Repo, target),
		InstallDir: dir,
		NoOp:       plan_noOp(opts.CurrentVersion, target, opts.Force),
		Downgrade:  plan_downgrade(opts.CurrentVersion, target),
	}
	return plan, nil
}

// Apply runs the download → verify → atomic-install pipeline. Returns
// the list of binaries actually written. progress, if non-nil, gets
// human-readable status lines.
func (p *Plan) Apply(progress io.Writer, opts Options) ([]string, error) {
	if runtime.GOOS == "windows" {
		return nil, fmt.Errorf("self-update is not supported on Windows yet; use install.ps1")
	}
	if p.NoOp {
		fmt.Fprintf(progress, "watchdog-shim update: already on %s; pass --force to reinstall.\n", p.Target)
		return nil, nil
	}
	if p.Downgrade && !opts.Force {
		return nil, fmt.Errorf("refusing downgrade from %s to %s; pass --force to override", p.Current, p.Target)
	}

	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}

	tmp, err := os.MkdirTemp("", "watchdog-update-*")
	if err != nil {
		return nil, fmt.Errorf("tempdir: %w", err)
	}
	defer os.RemoveAll(tmp)

	fmt.Fprintf(progress, "watchdog-shim update: fetching %s\n", p.ArchiveURL)
	archivePath := filepath.Join(tmp, p.Archive)
	if err := downloadTo(client, p.ArchiveURL, archivePath); err != nil {
		return nil, fmt.Errorf("download archive: %w", err)
	}

	fmt.Fprintln(progress, "watchdog-shim update: fetching checksums.txt")
	sumsPath := filepath.Join(tmp, "checksums.txt")
	if err := downloadTo(client, p.SumsURL, sumsPath); err != nil {
		return nil, fmt.Errorf("download checksums: %w", err)
	}

	want, err := lookupSum(sumsPath, p.Archive)
	if err != nil {
		return nil, err
	}
	got, err := sha256File(archivePath)
	if err != nil {
		return nil, fmt.Errorf("hash archive: %w", err)
	}
	if got != want {
		return nil, fmt.Errorf("checksum mismatch for %s: got %s, want %s", p.Archive, got, want)
	}
	fmt.Fprintf(progress, "watchdog-shim update: checksum verified (%s)\n", got)

	extractDir := filepath.Join(tmp, "extract")
	if err := os.Mkdir(extractDir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir extract: %w", err)
	}
	if err := extractTarGz(archivePath, extractDir); err != nil {
		return nil, fmt.Errorf("extract: %w", err)
	}

	if err := os.MkdirAll(p.InstallDir, 0o755); err != nil {
		return nil, fmt.Errorf("install dir: %w", err)
	}

	// Permission probe — fail before we touch any existing binary.
	probe := filepath.Join(p.InstallDir, ".watchdog-update.probe")
	if err := os.WriteFile(probe, []byte("ok"), 0o644); err != nil {
		return nil, fmt.Errorf("install dir not writable: %w", err)
	}
	_ = os.Remove(probe)

	installed := []string{}
	for _, name := range Binaries {
		src := filepath.Join(extractDir, name)
		if _, err := os.Stat(src); err != nil {
			// Skip absent binaries silently — the release manifest
			// may shrink in future versions, and an older tarball
			// missing a binary should not crater the update.
			continue
		}
		dst := filepath.Join(p.InstallDir, name)
		stage := dst + ".new"
		if err := copyFile(src, stage, 0o755); err != nil {
			return installed, fmt.Errorf("stage %s: %w", name, err)
		}
		if err := os.Rename(stage, dst); err != nil {
			_ = os.Remove(stage)
			return installed, fmt.Errorf("install %s: %w", name, err)
		}
		installed = append(installed, name)
	}
	fmt.Fprintf(progress, "watchdog-shim update: %d binaries installed into %s\n", len(installed), p.InstallDir)

	return installed, nil
}

// detectOSArch maps Go's runtime constants to the release naming
// (darwin, linux, amd64, arm64). Mirrors install.sh's uname maps.
func detectOSArch() (string, string, error) {
	var osName string
	switch runtime.GOOS {
	case "darwin", "linux":
		osName = runtime.GOOS
	default:
		return "", "", fmt.Errorf("unsupported OS for self-update: %s", runtime.GOOS)
	}
	var arch string
	switch runtime.GOARCH {
	case "amd64", "arm64":
		arch = runtime.GOARCH
	default:
		return "", "", fmt.Errorf("unsupported arch for self-update: %s", runtime.GOARCH)
	}
	return osName, arch, nil
}

// defaultInstallDir places the binaries beside the currently-running
// watchdog-shim, so updating from ~/.local/bin replaces ~/.local/bin.
// Falls back to ~/.local/bin when os.Executable can't be resolved.
func defaultInstallDir() string {
	if self, err := os.Executable(); err == nil {
		if abs, err := filepath.Abs(self); err == nil {
			return filepath.Dir(abs)
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".local", "bin")
	}
	return "/usr/local/bin"
}

// fetchLatestTag resolves the latest release tag via the GitHub API.
// Returns the raw `tag_name` field (e.g. "v0.9.6"). The API URL is
// overridable through Options.APIURL for tests.
func fetchLatestTag(opts Options) (string, error) {
	api := opts.APIURL
	if api == "" {
		api = fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", Repo)
	}
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	req, err := http.NewRequest(http.MethodGet, api, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "watchdog-shim-update")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("github api %s: status %d", api, resp.StatusCode)
	}
	var doc struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return "", err
	}
	if doc.TagName == "" {
		return "", fmt.Errorf("github api %s: empty tag_name", api)
	}
	return doc.TagName, nil
}

func downloadTo(client *http.Client, url, dst string) error {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "watchdog-shim-update")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("%s: status %d", url, resp.StatusCode)
	}
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func lookupSum(sumsPath, archive string) (string, error) {
	data, err := os.ReadFile(sumsPath)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		// goreleaser writes "<sha256>  <name>"; some tooling strips the
		// leading "./" so accept both.
		if fields[1] == archive || fields[1] == "./"+archive {
			return fields[0], nil
		}
	}
	return "", fmt.Errorf("checksums.txt has no entry for %s", archive)
}

func sha256File(path string) (string, error) {
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

func extractTarGz(archive, dst string) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		// Skip anything that isn't a regular file. We never want to
		// follow archive symlinks during a privileged install.
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		// Guard against ../escape — refuse any header that resolves
		// outside dst after Clean.
		name := filepath.Clean(hdr.Name)
		if strings.HasPrefix(name, "..") || strings.Contains(name, string(filepath.Separator)+"..") {
			return fmt.Errorf("tarball entry escapes target: %q", hdr.Name)
		}
		out := filepath.Join(dst, name)
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			return err
		}
		mode := os.FileMode(hdr.Mode).Perm()
		if mode == 0 {
			mode = 0o755
		}
		w, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
		if err != nil {
			return err
		}
		if _, err := io.Copy(w, tr); err != nil {
			w.Close()
			return err
		}
		if err := w.Close(); err != nil {
			return err
		}
	}
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// plan_noOp reports whether Apply should short-circuit. Exact tag
// equality only — not semver-aware. Suffix differences (dev, rc1)
// count as "not equal" and trigger a real install.
func plan_noOp(current, target string, force bool) bool {
	if force {
		return false
	}
	cur := normalize(current)
	tgt := normalize(target)
	return cur != "" && cur == tgt
}

// plan_downgrade returns true when target sorts strictly below
// current. Uses a lexicographic comparison on the dot-separated
// numeric prefix. Pre-release suffixes (-rc1, -dev) are ignored,
// which matches the "stable tags only" release process.
func plan_downgrade(current, target string) bool {
	c := semverNums(current)
	t := semverNums(target)
	if c == nil || t == nil {
		return false
	}
	for i := 0; i < len(c) && i < len(t); i++ {
		if t[i] < c[i] {
			return true
		}
		if t[i] > c[i] {
			return false
		}
	}
	return len(t) < len(c)
}

func normalize(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	return v
}

func semverNums(v string) []int {
	n := normalize(v)
	if n == "" {
		return nil
	}
	parts := strings.Split(n, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		x := 0
		for _, c := range p {
			if c < '0' || c > '9' {
				return nil
			}
			x = x*10 + int(c-'0')
		}
		out = append(out, x)
	}
	return out
}
