// Package fetchers downloads, extracts, and curates artifact bundles
// for the analyzer to review. Each fetch<Ecosystem> returns a small,
// size-capped subset of files plus metadata; a hostile registry can
// neither fill memory nor sneak symlinks out of an archive.
package fetchers

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/Maxlemore97/watchdog/internal/urlenc"
)

const (
	HTTPTimeout      = 10 * time.Second
	UserAgent        = "watchdog-scanner/0.4"
	MaxFileBytes     = 10_000
	MaxBundleBytes   = 50_000
	MaxDownloadBytes = 5_000_000
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
}

func newOrderedFiles() *orderedFiles {
	return &orderedFiles{data: map[string]string{}}
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

// fitBundle returns a map capped at MaxBundleBytes total. Iteration
// order is `files.order` so callers control priority. Entries beyond
// the cap are dropped silently.
func fitBundle(files *orderedFiles) map[string]string {
	out := map[string]string{}
	used := 0
	for _, name := range files.order {
		content, ok := files.data[name]
		if !ok {
			continue
		}
		snippet := truncateString(content, MaxFileBytes)
		if used+len(snippet) > MaxBundleBytes {
			remain := MaxBundleBytes - used
			if remain < 0 {
				remain = 0
			}
			if remain >= len(snippet) {
				snippet = snippet[:remain]
			} else {
				snippet = snippet[:remain] + "\n... [bundle cap reached]"
			}
		}
		out[name] = snippet
		used += len(snippet)
		if used >= MaxBundleBytes {
			break
		}
	}
	return out
}
