// Package ledger persists per-plugin content hashes and last-known
// verdicts under ${WATCHDOG_CACHE_DIR}/vetted_plugins.json. The
// SessionStart adapter uses it to skip plugins whose on-disk contents
// have not changed since they were last reviewed.
package ledger

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Maxlemore97/watchdog/internal/log"
	"github.com/Maxlemore97/watchdog/internal/paths"
)

const (
	Version  = 1
	SelfName = "watchdog"
)

var (
	hashDirs  = []string{".claude-plugin", "hooks", "commands", "skills"}
	hashFiles = []string{"plugin.json"}
)

func LedgerPath() string {
	return filepath.Join(paths.CacheDir(), "vetted_plugins.json")
}

func MaxScansPerSession() int {
	if raw := os.Getenv("WATCHDOG_SESSION_MAX_SCANS"); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil {
			return v
		}
	}
	return 10
}

// PluginDirs returns the directories Watchdog scans for installed
// plugins, deduped, only existing dirs are returned.
func PluginDirs() []string {
	var raw []string
	if env := os.Getenv("WATCHDOG_PLUGIN_DIRS"); env != "" {
		raw = append(raw, splitPathList(env)...)
	}
	raw = append(raw, os.Getenv("CLAUDE_PLUGINS_DIR"))
	if home, err := os.UserHomeDir(); err == nil {
		raw = append(raw, filepath.Join(home, ".claude", "plugins"))
	}
	seen := map[string]bool{}
	var out []string
	for _, p := range raw {
		if p == "" {
			continue
		}
		abs, err := filepath.Abs(expand(p))
		if err != nil || seen[abs] {
			continue
		}
		seen[abs] = true
		if st, err := os.Stat(abs); err == nil && st.IsDir() {
			out = append(out, abs)
		}
	}
	return out
}

func expand(p string) string {
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[2:])
		}
	}
	return p
}

func splitPathList(s string) []string {
	sep := string(os.PathListSeparator)
	out := []string{}
	for _, p := range strings.Split(s, sep) {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Ledger is the persisted document.
type Ledger struct {
	Version int                    `json:"version"`
	Entries map[string]LedgerEntry `json:"entries"`
}

type LedgerEntry struct {
	Name            string `json:"name"`
	Path            string `json:"path"`
	ManifestVersion string `json:"manifest_version,omitempty"`
	ContentHash     string `json:"content_hash"`
	Verdict         string `json:"verdict"`
	Risk            string `json:"risk,omitempty"`
	Reason          string `json:"reason,omitempty"`
	ScannedAt       int64  `json:"scanned_at"`
}

// WithLock serializes Load→modify→Save sequences across processes.
//
// Two SessionStart hooks running concurrently (e.g. multiple Claude
// Code windows opened at once) would otherwise both Load the same
// snapshot, both modify independently, and the second Save would
// drop the first's scan results. The lock file is best-effort: a
// stale lock older than staleLockSecs is forcibly broken so a
// crashed sibling cannot wedge the ledger forever.
//
// fn always runs — if the lock cannot be acquired after retries, we
// fall back to unlocked execution (the worst case is the original
// race, which is also the pre-lock behavior).
func WithLock(fn func()) {
	dir := paths.CacheDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fn()
		return
	}
	lockPath := LedgerPath() + ".lock"
	const (
		maxAttempts    = 50
		retryDelay     = 100 * time.Millisecond
		staleLockSecs  = 60
	)
	acquired := false
	for i := 0; i < maxAttempts; i++ {
		f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err == nil {
			_ = f.Close()
			acquired = true
			break
		}
		if st, statErr := os.Stat(lockPath); statErr == nil {
			if time.Since(st.ModTime()) > staleLockSecs*time.Second {
				_ = os.Remove(lockPath)
				continue
			}
		}
		time.Sleep(retryDelay)
	}
	if acquired {
		defer os.Remove(lockPath)
	}
	fn()
}

func Load() Ledger {
	path := LedgerPath()
	data, err := os.ReadFile(path)
	if err != nil {
		return Ledger{Version: Version, Entries: map[string]LedgerEntry{}}
	}
	var l Ledger
	if err := json.Unmarshal(data, &l); err != nil {
		return Ledger{Version: Version, Entries: map[string]LedgerEntry{}}
	}
	if l.Entries == nil {
		l.Entries = map[string]LedgerEntry{}
	}
	return l
}

func Save(l Ledger) {
	dir := paths.CacheDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	data, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return
	}
	path := LedgerPath()
	// PID-suffixed tmp so parallel sessions writing the ledger don't
	// tear each other's atomic-rename staging file.
	tmp := path + "." + strconv.Itoa(os.Getpid()) + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		log.Event("cache_write_failed", map[string]any{"path": path, "stage": "write_tmp", "error": err.Error()})
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		log.Event("cache_write_failed", map[string]any{"path": path, "stage": "rename", "error": err.Error()})
	}
}

// ContentHash returns a stable SHA-256 over the plugin's hashable files.
func ContentHash(pluginRoot string) string {
	var files []string
	for _, sub := range hashDirs {
		root := filepath.Join(pluginRoot, sub)
		if st, err := os.Stat(root); err == nil && st.IsDir() {
			_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return nil
				}
				lst, err := os.Lstat(p)
				if err != nil || lst.Mode()&os.ModeSymlink != 0 || !lst.Mode().IsRegular() {
					return nil
				}
				files = append(files, p)
				return nil
			})
		}
	}
	for _, name := range hashFiles {
		p := filepath.Join(pluginRoot, name)
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
			files = append(files, p)
		}
	}
	sort.Slice(files, func(i, j int) bool {
		a, _ := filepath.Rel(pluginRoot, files[i])
		b, _ := filepath.Rel(pluginRoot, files[j])
		return a < b
	})
	h := sha256.New()
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		rel, _ := filepath.Rel(pluginRoot, f)
		h.Write([]byte(filepath.ToSlash(rel)))
		h.Write([]byte{0})
		inner := sha256.Sum256(data)
		h.Write(inner[:])
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ReadManifest returns the parsed plugin.json. Rejects symlinks so a
// hostile plugin can't surface arbitrary host-side file contents.
func ReadManifest(pluginRoot string) map[string]any {
	for _, candidate := range []string{".claude-plugin/plugin.json", "plugin.json"} {
		path := filepath.Join(pluginRoot, candidate)
		lst, err := os.Lstat(path)
		if err != nil || lst.Mode()&os.ModeSymlink != 0 || !lst.Mode().IsRegular() {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var out map[string]any
		if err := json.Unmarshal(data, &out); err != nil {
			continue
		}
		return out
	}
	return map[string]any{}
}

// PluginInfo holds one discovered plugin's identity + manifest.
type PluginInfo struct {
	Name     string
	Path     string
	Manifest map[string]any
}

// Discover returns plugins beneath the provided roots (or the default
// dirs when roots is nil/empty).
func Discover(roots []string) []PluginInfo {
	if len(roots) == 0 {
		roots = PluginDirs()
	}
	seen := map[string]bool{}
	var out []PluginInfo
	for _, root := range roots {
		st, err := os.Stat(root)
		if err != nil || !st.IsDir() {
			continue
		}
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			child := filepath.Join(root, e.Name())
			manifest := ReadManifest(child)
			if len(manifest) == 0 {
				continue
			}
			abs, err := filepath.Abs(child)
			if err != nil || seen[abs] {
				continue
			}
			seen[abs] = true
			name, _ := manifest["name"].(string)
			if name == "" {
				name = e.Name()
			}
			if name == SelfName {
				continue
			}
			out = append(out, PluginInfo{Name: name, Path: child, Manifest: manifest})
		}
	}
	return out
}

// AnalyzerFn is the signature used to plug the LLM analyzer in.
// scan() defaults to analyzer.AnalyzeLocalPlugin in the adapters;
// tests inject a stub.
type AnalyzerFn func(name, path, contentHash string) map[string]any

// ScanResult describes one plugin scan outcome.
type ScanResult struct {
	Name    string
	Verdict map[string]any
}

// Scan walks plugins, computes content hashes, and runs analyzerFn on
// any whose hash is new or changed (subject to maxScans). Returns the
// findings, whether the ledger was mutated, and how many plugins were
// skipped due to the per-session cap.
func Scan(plugins []PluginInfo, ledger *Ledger, analyzerFn AnalyzerFn, maxScans int) ([]ScanResult, bool, int) {
	if maxScans <= 0 {
		maxScans = MaxScansPerSession()
	}
	if ledger.Entries == nil {
		ledger.Entries = map[string]LedgerEntry{}
	}
	var findings []ScanResult
	dirty := false
	scansUsed := 0
	skipped := 0
	for _, p := range plugins {
		h := ContentHash(p.Path)
		if prev, ok := ledger.Entries[p.Name]; ok && prev.ContentHash == h {
			continue
		}
		if scansUsed >= maxScans {
			skipped++
			continue
		}
		scansUsed++
		verdict := analyzerFn(p.Name, p.Path, h)
		if verdict == nil {
			verdict = map[string]any{"verdict": "ask", "reason": "analyzer returned no result"}
		}
		ver, _ := verdict["verdict"].(string)
		if ver == "" {
			ver = "ask"
		}
		risk, _ := verdict["risk"].(string)
		reason, _ := verdict["reason"].(string)
		if len(reason) > 300 {
			reason = reason[:300]
		}
		manifestVersion, _ := p.Manifest["version"].(string)
		ledger.Entries[p.Name] = LedgerEntry{
			Name:            p.Name,
			Path:            p.Path,
			ManifestVersion: manifestVersion,
			ContentHash:     h,
			Verdict:         ver,
			Risk:            risk,
			Reason:          reason,
			ScannedAt:       time.Now().Unix(),
		}
		findings = append(findings, ScanResult{Name: p.Name, Verdict: verdict})
		dirty = true
	}
	return findings, dirty, skipped
}
