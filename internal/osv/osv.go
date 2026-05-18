// Package osv talks to OSV.dev for vulnerability lookups and resolves
// "latest" versions across npm, PyPI, crates.io, RubyGems, and
// Packagist. All HTTP is short-timeout, stdlib-only. Successful OSV
// responses are cached on disk for WATCHDOG_CACHE_TTL seconds.
package osv

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Maxlemore97/watchdog/internal/log"
	"github.com/Maxlemore97/watchdog/internal/paths"
	"github.com/Maxlemore97/watchdog/internal/types"
	"github.com/Maxlemore97/watchdog/internal/urlenc"
)

const (
	Endpoint    = "https://api.osv.dev/v1/query"
	HTTPTimeout = 5 * time.Second
	UserAgent   = "watchdog-scanner/0.4 (+https://github.com/Maxlemore97/watchdog)"
)

// SeverityRank holds the canonical severity ordering. Unknown
// severities rank "high" so users raising MIN_SEVERITY to "high"
// still see them. Aligned with the Python reference.
var SeverityRank = map[string]int{
	"none":     0,
	"low":      1,
	"medium":   2,
	"high":     3,
	"critical": 4,
}

const UnknownSeverityRank = 3 // matches SeverityRank["high"]

// CacheTTLSeconds reads WATCHDOG_CACHE_TTL each call so tests and
// long-lived processes can change it without reloading.
func CacheTTLSeconds() int {
	if raw := os.Getenv("WATCHDOG_CACHE_TTL"); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil {
			return v
		}
	}
	return 3600
}

// MinSeverity returns the lowercased validated severity floor from
// WATCHDOG_MIN_SEVERITY. Falls back to "low" on missing or invalid.
func MinSeverity() string {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv("WATCHDOG_MIN_SEVERITY")))
	if _, ok := SeverityRank[raw]; ok {
		return raw
	}
	return "low"
}

// MinSeverityRank returns the rank of the active severity floor.
func MinSeverityRank() int {
	return SeverityRank[MinSeverity()]
}

// ResolveLatestEnabled checks WATCHDOG_RESOLVE_LATEST. Default on.
func ResolveLatestEnabled() bool {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv("WATCHDOG_RESOLVE_LATEST")))
	switch raw {
	case "0", "false", "no", "off":
		return false
	}
	return true
}

// cachePath returns the on-disk cache path for a package query.
func cachePath(pkg types.Package) string {
	key := strings.ToLower(fmt.Sprintf("%s|%s|%s", pkg.Ecosystem, pkg.Name, pkg.Version))
	sum := sha256.Sum256([]byte(key))
	return filepath.Join(paths.CacheDir(), hex.EncodeToString(sum[:])[:32]+".json")
}

// CacheLoad returns cached vulnerability list if present and fresh.
func CacheLoad(pkg types.Package) []map[string]any {
	path := cachePath(pkg)
	st, err := os.Stat(path)
	if err != nil {
		return nil
	}
	if time.Since(st.ModTime()) > time.Duration(CacheTTLSeconds())*time.Second {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var vulns []map[string]any
	if err := json.Unmarshal(data, &vulns); err != nil {
		return nil
	}
	return vulns
}

// CacheStore atomically writes the vulnerability list to disk.
func CacheStore(pkg types.Package, vulns []map[string]any) {
	dir := paths.CacheDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	data, err := json.Marshal(vulns)
	if err != nil {
		return
	}
	path := cachePath(pkg)
	// PID-suffixed tmp so parallel processes can't tear each other's
	// cache writes via a shared staging filename.
	tmp := path + "." + strconv.Itoa(os.Getpid()) + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		log.Event("cache_write_failed", map[string]any{"path": path, "stage": "write_tmp", "error": err.Error()})
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		log.Event("cache_write_failed", map[string]any{"path": path, "stage": "rename", "error": err.Error()})
	}
}

// EndpointURL points at OSV.dev by default; tests override via env.
// Refuses non-http(s) schemes so a stray `file://` override cannot
// turn the OSV lookup into a local-file read.
func endpointURL() string {
	v := strings.TrimSpace(os.Getenv("WATCHDOG_OSV_ENDPOINT"))
	if v == "" {
		return Endpoint
	}
	low := strings.ToLower(v)
	if !strings.HasPrefix(low, "http://") && !strings.HasPrefix(low, "https://") {
		return Endpoint
	}
	return v
}

// Query looks up advisories for pkg on OSV.dev. Returns
// (vulns, error). On any network or parse failure err is non-nil so
// the caller's fail-closed verdict policy applies. Successful but
// empty responses return ([]map[string]any{}, nil). Cache hits return
// (cached, nil).
func Query(pkg types.Package) ([]map[string]any, error) {
	if cached := CacheLoad(pkg); cached != nil {
		return cached, nil
	}
	body := map[string]any{
		"package": map[string]string{"name": pkg.Name, "ecosystem": pkg.Ecosystem},
	}
	if pkg.Version != "" {
		body["version"] = pkg.Version
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", endpointURL(), bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", UserAgent)

	client := &http.Client{Timeout: HTTPTimeout}
	resp, err := client.Do(req)
	if err != nil {
		log.Event("osv_query_failed", map[string]any{
			"package": pkg.Ecosystem + ":" + pkg.Name,
			"error":   truncate(err.Error(), 200),
		})
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 5_000_000))
	if err != nil {
		log.Event("osv_query_failed", map[string]any{
			"package": pkg.Ecosystem + ":" + pkg.Name,
			"error":   truncate(err.Error(), 200),
		})
		return nil, err
	}
	var data struct {
		Vulns []map[string]any `json:"vulns"`
	}
	if err := json.Unmarshal(raw, &data); err != nil {
		log.Event("osv_query_failed", map[string]any{
			"package": pkg.Ecosystem + ":" + pkg.Name,
			"error":   truncate(err.Error(), 200),
		})
		return nil, err
	}
	vulns := data.Vulns
	if vulns == nil {
		vulns = []map[string]any{}
	}
	CacheStore(pkg, vulns)
	return vulns, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func scoreToRank(score float64) int {
	switch {
	case score >= 9.0:
		return SeverityRank["critical"]
	case score >= 7.0:
		return SeverityRank["high"]
	case score >= 4.0:
		return SeverityRank["medium"]
	case score > 0.0:
		return SeverityRank["low"]
	default:
		return SeverityRank["none"]
	}
}

// SeverityRankOf inspects a vulnerability record and returns its
// severity rank. Records carrying database_specific.severity win;
// otherwise the highest CVSS score wins; otherwise unknown (high).
func SeverityRankOf(vuln map[string]any) int {
	if dbs, ok := vuln["database_specific"].(map[string]any); ok {
		if label, ok := dbs["severity"].(string); ok {
			lower := strings.ToLower(strings.TrimSpace(label))
			if r, ok := SeverityRank[lower]; ok {
				return r
			}
		}
	}
	best := -1
	if entries, ok := vuln["severity"].([]any); ok {
		for _, raw := range entries {
			entry, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			scoreStr, ok := entry["score"].(string)
			if !ok || scoreStr == "" {
				continue
			}
			score, err := strconv.ParseFloat(scoreStr, 64)
			if err != nil {
				continue
			}
			r := scoreToRank(score)
			if r > best {
				best = r
			}
		}
	}
	if best >= 0 {
		return best
	}
	return UnknownSeverityRank
}

// SeverityLabel returns the lowercase name for a rank, or "unknown".
func SeverityLabel(rank int) string {
	for name, value := range SeverityRank {
		if value == rank {
			return name
		}
	}
	return "unknown"
}

// FilterBySeverity returns only the vulnerabilities at or above the
// active severity floor.
func FilterBySeverity(vulns []map[string]any) []map[string]any {
	threshold := MinSeverityRank()
	out := make([]map[string]any, 0, len(vulns))
	for _, v := range vulns {
		if SeverityRankOf(v) >= threshold {
			out = append(out, v)
		}
	}
	return out
}

// Summarize renders up to five vulnerabilities as "ID[severity], ...".
func Summarize(vulns []map[string]any) string {
	parts := []string{}
	for i, v := range vulns {
		if i >= 5 {
			parts = append(parts, "...")
			break
		}
		id, _ := v["id"].(string)
		if id == "" {
			id = "?"
		}
		parts = append(parts, fmt.Sprintf("%s[%s]", id, SeverityLabel(SeverityRankOf(v))))
	}
	return strings.Join(parts, ", ")
}

// ---------- latest-version resolution ------------------------------

// FetchLatestVersion returns the latest version string for a package
// in the given ecosystem, or "" on failure.
func FetchLatestVersion(pkg types.Package) string {
	switch pkg.Ecosystem {
	case "npm":
		return jsonGetString(
			"https://registry.npmjs.org/"+escape(pkg.Name, "@/")+"/latest",
			"version",
		)
	case "PyPI":
		data := jsonGet("https://pypi.org/pypi/" + escape(pkg.Name, "") + "/json")
		info, _ := data["info"].(map[string]any)
		v, _ := info["version"].(string)
		return v
	case "crates.io":
		data := jsonGet("https://crates.io/api/v1/crates/" + escape(pkg.Name, ""))
		crate, _ := data["crate"].(map[string]any)
		if v, ok := crate["max_stable_version"].(string); ok && v != "" {
			return v
		}
		if v, ok := crate["newest_version"].(string); ok {
			return v
		}
		return ""
	case "RubyGems":
		return jsonGetString(
			"https://rubygems.org/api/v1/gems/"+escape(pkg.Name, "")+".json",
			"version",
		)
	case "Packagist":
		data := jsonGet("https://repo.packagist.org/p2/" + escape(pkg.Name, "/") + ".json")
		packages, _ := data["packages"].(map[string]any)
		entries, _ := packages[pkg.Name].([]any)
		if entries == nil {
			for _, v := range packages {
				entries, _ = v.([]any)
				break
			}
		}
		for _, raw := range entries {
			entry, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			ver, _ := entry["version"].(string)
			if ver != "" && !strings.HasPrefix(ver, "dev-") {
				return ver
			}
		}
	}
	return ""
}

// ResolveVersion fills in the latest version when one is not pinned.
// Returns pkg unchanged when WATCHDOG_RESOLVE_LATEST is off.
func ResolveVersion(pkg types.Package) types.Package {
	if pkg.Version != "" || !ResolveLatestEnabled() {
		return pkg
	}
	latest := FetchLatestVersion(pkg)
	if latest == "" {
		return pkg
	}
	return types.Package{Ecosystem: pkg.Ecosystem, Name: pkg.Name, Version: latest}
}

// ---------- HTTP helpers ------------------------------------------

func escape(s, safe string) string { return urlenc.Escape(s, safe) }

func jsonGet(rawURL string) map[string]any {
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return map[string]any{}
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "application/json")
	client := &http.Client{Timeout: HTTPTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return map[string]any{}
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 5_000_000))
	if err != nil {
		return map[string]any{}
	}
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		return map[string]any{}
	}
	return data
}

func jsonGetString(rawURL, field string) string {
	data := jsonGet(rawURL)
	v, _ := data[field].(string)
	return v
}

// ErrNoNetwork is reserved for the rare case query callers want to
// distinguish "no result" from "could not reach". Currently unused
// (Query returns []) but exported for adapters that adopt richer
// failure handling later.
var ErrNoNetwork = errors.New("osv: network unavailable")
