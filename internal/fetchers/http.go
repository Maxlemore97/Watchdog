// Package fetchers downloads, extracts, and curates artifact bundles
// for the analyzer to review. Each fetch<Ecosystem> returns a small,
// size-capped subset of files plus metadata; a hostile registry can
// neither fill memory nor sneak symlinks out of an archive.
package fetchers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Maxlemore97/watchdog/internal/types"
	"github.com/Maxlemore97/watchdog/internal/urlenc"
)

const (
	HTTPTimeout      = 10 * time.Second
	UserAgent        = "watchdog-scanner/0.4"
	MaxFileBytes     = 10_000
	MaxBundleBytes   = 50_000
	MaxDownloadBytes = 5_000_000
	// MaxManifestBytes caps manifests that must be parsed whole
	// (npm package.json) to extract install scripts.
	MaxManifestBytes = 1_000_000
)

// httpGet / httpGetJSON are package-level vars so unit tests in this
// package can mock the network without running a real HTTP server.
// Production callers see the same behavior as before.
var (
	httpGet     = httpGetReal
	httpGetJSON = httpGetJSONReal
)

func httpGetReal(rawURL string) []byte {
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", UserAgent)
	client := &http.Client{Timeout: HTTPTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	// Read MaxDownloadBytes + 1 — if we got > MaxDownloadBytes, reject
	// per the Python behaviour (avoid OOMing on a 500MB registry blob).
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxDownloadBytes+1))
	if err != nil {
		return nil
	}
	if len(data) > MaxDownloadBytes {
		return nil
	}
	return data
}

func httpGetJSONReal(rawURL string) map[string]any {
	raw := httpGet(rawURL)
	if raw == nil {
		return nil
	}
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil
	}
	return data
}

// escape mimics urllib.parse.quote(name, safe=safe).
func escape(s, safe string) string { return urlenc.Escape(s, safe) }

func truncateString(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	return text[:limit] + "\n... [truncated, total " + strconv.Itoa(len(text)) + " bytes]"
}

// orderedFiles preserves insertion order so fitBundle iterates in a
// deterministic priority sequence. Fetchers MUST insert risky-script
// entries (e.g. `package.json#scripts`, `composer.json#scripts`)
// FIRST so they never get evicted by the bundle-size cap.
//
// Go maps have non-deterministic iteration order — relying on that
// in fitBundle was a real security regression (risky scripts could
// fall out of the LLM's view when an archive shipped many large
// files). This type fixes that.
type orderedFiles struct {
	order []string
	data  map[string]string
	// autoExec marks keys that run without the agent choosing to,
	// beyond what the path alone reveals (e.g. a script referenced
	// from a hook command).
	autoExec map[string]bool
}

func newOrderedFiles() *orderedFiles {
	return &orderedFiles{data: map[string]string{}, autoExec: map[string]bool{}}
}

// tier ranks a key for bundle ordering: auto-executed surfaces first,
// then other code, then documentation and manifests.
func (o *orderedFiles) tier(key string) int {
	if o.autoExec[key] || isAutoExecSurface(key) {
		return tierAutoExec
	}
	if isCodeSurface(key) {
		return tierCode
	}
	return tierOther
}

// set inserts or updates an entry. New keys preserve their first
// insertion position; re-inserts overwrite content but keep order.
func (o *orderedFiles) set(name, content string) {
	if _, exists := o.data[name]; !exists {
		o.order = append(o.order, name)
	}
	o.data[name] = content
}

// merge inserts every entry of other in the order it was added.
func (o *orderedFiles) merge(other map[string]string, order []string) {
	if order != nil {
		for _, k := range order {
			if v, ok := other[k]; ok {
				o.set(k, v)
			}
		}
		return
	}
	// Fallback: sort keys for determinism when no explicit order.
	keys := make([]string, 0, len(other))
	for k := range other {
		keys = append(keys, k)
	}
	sortKeys(keys)
	for _, k := range keys {
		o.set(k, other[k])
	}
}

func sortKeys(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

// fitBundle returns a map capped at MaxBundleBytes total. See
// fitBundleReport for ordering and truncation accounting.
func fitBundle(files *orderedFiles) map[string]string {
	out, _, _ := fitBundleReport(files)
	return out
}

// fitBundleReport caps the bundle at MaxBundleBytes. Entries are placed
// by tier — auto-executed surfaces, then other code, then docs and
// manifests — keeping insertion order within a tier, so an attacker
// cannot push a hook script out of view by shipping large
// documentation files.
//
// truncatedAuto lists auto-executed surfaces the LLM will not see in
// full (cut at MaxFileBytes, cut by the cap, or dropped).
// truncatedOther counts every other entry that was cut or dropped.
func fitBundleReport(files *orderedFiles) (out map[string]string, truncatedAuto []string, truncatedOther int) {
	out = map[string]string{}
	var byTier [3][]string
	for _, name := range files.order {
		t := files.tier(name)
		byTier[t] = append(byTier[t], name)
	}
	markTruncated := func(name string) {
		if files.tier(name) == tierAutoExec {
			truncatedAuto = append(truncatedAuto, name)
		} else {
			truncatedOther++
		}
	}
	used := 0
	for _, name := range slices.Concat(byTier[0], byTier[1], byTier[2]) {
		content, ok := files.data[name]
		if !ok {
			continue
		}
		if used >= MaxBundleBytes {
			markTruncated(name)
			continue
		}
		snippet := truncateString(content, MaxFileBytes)
		cut := len(snippet) != len(content)
		if used+len(snippet) > MaxBundleBytes {
			snippet = truncateUTF8(snippet, MaxBundleBytes-used) + "\n... [bundle cap reached]"
			cut = true
		}
		if cut {
			markTruncated(name)
		}
		out[name] = snippet
		used += len(snippet)
	}
	return out, truncatedAuto, truncatedOther
}

// truncateUTF8 returns at most n bytes of s without splitting a rune.
func truncateUTF8(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

const (
	tierAutoExec = iota
	tierCode
	tierOther
)

// autoExecBasenames run on install, on session/tool events, or define
// commands the host launches (MCP/LSP servers, hooks, monitors).
var autoExecBasenames = map[string]bool{
	"setup.py": true, "setup.cfg": true, "pyproject.toml": true, "build.rs": true,
	"extconf.rb": true, "rakefile": true, "rakefile.rb": true,
	"install.ps1": true, "init.ps1": true, "chocolateyinstall.ps1": true,
	".mcp.json": true, ".lsp.json": true, "hooks.json": true, "plugin.json": true,
	"settings.json": true, "monitors.json": true,
}

// autoExecDirs are plugin-root dirs whose contents run without the
// agent deciding to: hook handlers, monitors, and bin/ (prepended to
// the Bash tool's PATH, so it can shadow npm, git, …).
var autoExecDirs = []string{"hooks/", "bin/", "monitors/"}

var codeExts = map[string]bool{
	".sh": true, ".bash": true, ".zsh": true, ".fish": true, ".py": true,
	".js": true, ".mjs": true, ".cjs": true, ".ts": true, ".mts": true,
	".rb": true, ".pl": true, ".php": true, ".ps1": true, ".psm1": true,
	".bat": true, ".cmd": true, ".exe": true, ".lua": true,
}

// isAutoExecSurface reports whether a bundle key names content that
// runs without the agent choosing to: package install scripts, hook,
// MCP and LSP configs, and plugin hooks/, bin/, monitors/.
func isAutoExecSurface(key string) bool {
	if strings.HasSuffix(key, "#scripts") {
		return true
	}
	low := strings.ToLower(key)
	for _, d := range autoExecDirs {
		if strings.HasPrefix(low, d) {
			return true
		}
	}
	return autoExecBasenames[path.Base(low)]
}

// isCodeSurface reports whether a key is code the agent may run on
// demand (skill scripts, helper sources). Such code still goes through
// the Bash PreToolUse hook when invoked, so truncation only adds a
// note rather than forcing `ask`.
func isCodeSurface(key string) bool {
	low := strings.ToLower(key)
	if strings.HasPrefix(low, "scripts/") || strings.Contains(low, "/scripts/") {
		return true
	}
	return codeExts[path.Ext(low)]
}

// finalizeFrom fits files into the bundle, records truncation and
// stamps the content digest. The digest covers the full fetched
// content, not just the bytes that survived the cap, so a change
// hidden past the truncation point still invalidates cached verdicts.
func finalizeFrom(files *orderedFiles, b *types.ArtifactBundle) *types.ArtifactBundle {
	fitted, truncAuto, truncOther := fitBundleReport(files)
	b.Files = fitted
	b.TruncatedExecutable = truncAuto
	if n := len(truncAuto) + truncOther; n > 0 {
		b.Notes = append(b.Notes, fmt.Sprintf(
			"bundle truncated: %d file(s) cut or dropped by size caps; auto-executed surfaces affected: [%s]",
			n, strings.Join(truncAuto, ", ")))
	}
	b.UpstreamDigest = digestBundle(files.data)
	return b
}
