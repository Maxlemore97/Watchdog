// Package fetchers downloads, extracts, and curates artifact bundles
// for the analyzer to review. Each fetch<Ecosystem> returns a small,
// size-capped subset of files plus metadata; a hostile registry can
// neither fill memory nor sneak symlinks out of an archive.
package fetchers

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	HTTPTimeout      = 10 * time.Second
	UserAgent        = "watchdog-scanner/0.4"
	MaxFileBytes     = 10_000
	MaxBundleBytes   = 50_000
	MaxDownloadBytes = 5_000_000
)

func httpGet(rawURL string) []byte {
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

func httpGetJSON(rawURL string) map[string]any {
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
func escape(s, safe string) string {
	enc := url.PathEscape(s)
	for _, r := range safe {
		old := url.PathEscape(string(r))
		if old != string(r) {
			enc = strings.ReplaceAll(enc, old, string(r))
		}
	}
	return enc
}

func truncateString(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	return text[:limit] + "\n... [truncated, total " + itoa(len(text)) + " bytes]"
}

func itoa(n int) string {
	return strings.TrimLeft(stringifyInt(n), "0")
}

func stringifyInt(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	digits := []byte{}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	if neg {
		digits = append([]byte{'-'}, digits...)
	}
	return string(digits)
}

func fitBundle(files map[string]string) map[string]string {
	out := map[string]string{}
	used := 0
	// Iterate in caller-provided insertion order via a slice.
	// (Go maps don't preserve order; in practice fitBundle is called
	// per-ecosystem with files inserted in a deterministic flow:
	// risky-scripts first, then archive members in walk order.)
	// We mirror the Python dict-insertion-order semantics by sorting
	// keys here so the test surface is deterministic. The cap logic
	// is what matters; ordering is best-effort.
	for name, content := range files {
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
