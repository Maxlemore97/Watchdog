// Package analyzer wraps a fetched artifact bundle in a structured
// prompt, shells out to whichever local LLM CLI the user has
// configured (see providers), and parses a strict JSON verdict out of
// the response. Caches verdicts on disk under WATCHDOG_CACHE_DIR.
//
// The provider's child process receives WATCHDOG_DISABLE=1 so any
// hook the nested LLM session might trigger short-circuits and does
// not recursively re-invoke this analyzer.
package analyzer

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Maxlemore97/watchdog/internal/fetchers"
	"github.com/Maxlemore97/watchdog/internal/log"
	"github.com/Maxlemore97/watchdog/internal/paths"
	"github.com/Maxlemore97/watchdog/internal/providers"
	"github.com/Maxlemore97/watchdog/internal/types"
)

// htmlAttrEscaper mirrors Python's html.escape(s, quote=True). Go's
// stdlib html.EscapeString uses numeric entities (`&#34;`) where
// Python emits named ones (`&quot;`, `&#x27;`); aligning matters
// because the analyzer prompt and its tests pin the Python shape.
// Single-pass via NewReplacer — was 5 sequential ReplaceAll
// allocating new strings on each step.
var htmlAttrEscaper = strings.NewReplacer(
	"&", "&amp;",
	"<", "&lt;",
	">", "&gt;",
	`"`, "&quot;",
	"'", "&#x27;",
)

func escapeHTMLAttr(s string) string {
	return htmlAttrEscaper.Replace(s)
}

func cacheTTLSeconds() int {
	if raw := os.Getenv("WATCHDOG_LLM_CACHE_TTL"); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil {
			return v
		}
	}
	return 86400
}

// ---------- prefilter ---------------------------------------------

// hostilePattern pairs a regex with the label surfaced when it hits.
// Copied from the Python reference; RE2 in Go is stricter (no
// backrefs, no lookahead) but none of these patterns need either.
type hostilePattern struct {
	re    *regexp.Regexp
	label string
}

var hostilePatterns = []hostilePattern{
	{regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`), "embedded private key"},
	{regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`), "AWS access key id shape"},
	{regexp.MustCompile(`\bghp_[A-Za-z0-9]{36}\b`), "GitHub personal access token shape"},
	{regexp.MustCompile(`\bsk-[A-Za-z0-9]{20,}\b`), "OpenAI/Anthropic key shape"},
	{regexp.MustCompile(`\bxox[bpoa]-[A-Za-z0-9-]{10,}`), "Slack token shape"},
	{regexp.MustCompile(`(printenv|env)\s*\|\s*(curl|wget|nc)\b`), "env piped to network sink"},
	{regexp.MustCompile(`curl\s+[^|;&]*\|\s*(bash|sh|zsh)\b`), "curl piped to shell"},
}

// isDocPath classifies README-like files. Doc files routinely
// document install patterns (`curl … | bash`, `npm install …`) and
// may carry sample tokens. A pattern hit there should not deny — the
// user is reading docs, not executing them.
func isDocPath(p string) bool {
	leaf := strings.ToLower(p)
	if idx := strings.LastIndex(leaf, "/"); idx != -1 {
		leaf = leaf[idx+1:]
	}
	if strings.HasPrefix(leaf, "readme") {
		return true
	}
	return strings.HasSuffix(leaf, ".md") ||
		strings.HasSuffix(leaf, ".rst") ||
		strings.HasSuffix(leaf, ".txt")
}

// Prefilter runs deterministic regexes before the LLM. Returns nil
// when nothing matched, a deny verdict for code/script hits, or an
// ask verdict when every hit is inside a doc file.
func Prefilter(b *types.ArtifactBundle) map[string]any {
	if b == nil {
		return nil
	}
	var codeHits, docHits []string
	matchedLabel := ""
	keys := sortedKeys(b.Files)
	for _, p := range keys {
		content := b.Files[p]
		for _, hp := range hostilePatterns {
			if hp.re.MatchString(content) {
				hit := hp.label + " in " + p
				if isDocPath(p) {
					docHits = append(docHits, hit)
				} else {
					codeHits = append(codeHits, hit)
				}
				if matchedLabel == "" {
					matchedLabel = hp.label
				}
			}
		}
	}
	if len(codeHits) == 0 && len(docHits) == 0 {
		return nil
	}
	if len(codeHits) > 0 {
		log.Event("prefilter_deny", map[string]any{
			"ecosystem": b.Ecosystem,
			"name":      b.Name,
			"version":   b.Version,
			"reason":    matchedLabel,
			"hit_count": len(codeHits) + len(docHits),
		})
		indicators := append([]string{}, codeHits...)
		indicators = append(indicators, docHits...)
		return map[string]any{
			"verdict":    "deny",
			"risk":       "critical",
			"reason":     "prefilter: " + matchedLabel,
			"indicators": truncIndicators(indicators, 10),
		}
	}
	log.Event("prefilter_ask", map[string]any{
		"ecosystem": b.Ecosystem,
		"name":      b.Name,
		"version":   b.Version,
		"reason":    matchedLabel,
		"hit_count": len(docHits),
	})
	return map[string]any{
		"verdict":    "ask",
		"risk":       "medium",
		"reason":     "prefilter (doc-only): " + matchedLabel,
		"indicators": truncIndicators(docHits, 10),
	}
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func truncIndicators(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// ---------- cache --------------------------------------------------

func currentProviderSignature() string {
	prov, err := providers.ResolveProvider()
	if err != nil {
		return "none:none"
	}
	cfg := providers.BuildConfig(prov, SystemPrompt)
	return prov.Name + ":" + cfg.Model
}

func cacheKey(ecosystem, name, version string) string {
	raw := strings.ToLower(fmt.Sprintf("llm:%s:%s|%s|%s",
		currentProviderSignature(), ecosystem, name, version))
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])[:32]
}

func cacheLoad(key string) map[string]any {
	path := filepath.Join(paths.CacheDir(), key+".json")
	st, err := os.Stat(path)
	if err != nil {
		return nil
	}
	if time.Since(st.ModTime()) > time.Duration(cacheTTLSeconds())*time.Second {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		return nil
	}
	return out
}

func cacheStore(key string, verdict map[string]any) {
	dir := paths.CacheDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	data, err := json.Marshal(verdict)
	if err != nil {
		return
	}
	path := filepath.Join(dir, key+".json")
	// PID-suffixed tmp so parallel watchdog processes scanning the
	// same package don't write through each other's atomic rename
	// staging file. Each PID owns its own tmp; Rename of the loser
	// may still ENOENT but the cache content cannot be torn.
	tmp := path + "." + strconv.Itoa(os.Getpid()) + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return
	}
	_ = os.Rename(tmp, path)
}

// ---------- prompt builder ----------------------------------------

func buildUserPrompt(b *types.ArtifactBundle) string {
	version := b.Version
	if version == "" {
		version = "unknown"
	}
	parts := []string{
		"ecosystem: " + b.Ecosystem,
		"name: " + b.Name,
		"version: " + version,
		"",
		"metadata:",
	}
	metaJSON, _ := json.MarshalIndent(b.Metadata, "", "  ")
	metaStr := string(metaJSON)
	if len(metaStr) > 3000 {
		metaStr = metaStr[:3000]
	}
	parts = append(parts, metaStr, "")
	if len(b.Notes) > 0 {
		parts = append(parts, "fetch_notes: "+strings.Join(b.Notes, "; "), "")
	}
	for _, p := range sortedKeys(b.Files) {
		safePath := escapeHTMLAttr(p)
		// Neutralize any literal </UNTRUSTED so the body cannot close
		// the framing tag and inject instructions before the closer.
		safeBody := strings.ReplaceAll(b.Files[p], "</UNTRUSTED", `<\/UNTRUSTED`)
		parts = append(parts,
			fmt.Sprintf(`<UNTRUSTED kind="file" path="%s">`, safePath),
			safeBody,
			"</UNTRUSTED>",
			"",
		)
	}
	parts = append(parts, "Return a single JSON object matching the schema. No prose.")
	return strings.Join(parts, "\n")
}

// ---------- verdict extraction ------------------------------------

var (
	jsonFenceRE     = regexp.MustCompile("(?si)```(?:json)?\\s*(\\{.*?\\})\\s*```")
	verdictObjectRE = regexp.MustCompile(`(?s)\{[^{}]*"verdict"\s*:\s*"[^"]+"[^{}]*\}`)
)

// candidateVerdictJSONs returns possible JSON object substrings in
// priority order. Two tiers:
//  1. fenced ```json … ``` blocks
//  2. shallow object literals containing a "verdict" key
//
// The Python implementation also had a greedy first-{ to last-}
// fallback; it was dropped in 0.3 because it accepted arbitrary stray
// brace pairs in LLM prose — an injection vector when fetched
// content can influence the analyzer's output. Unparseable output
// returns nil here and the caller defaults to "ask".
func candidateVerdictJSONs(text string) []string {
	var out []string
	for _, m := range jsonFenceRE.FindAllStringSubmatch(text, -1) {
		if len(m) >= 2 && !slices.Contains(out, m[1]) {
			out = append(out, m[1])
		}
	}
	for _, m := range verdictObjectRE.FindAllString(text, -1) {
		if !slices.Contains(out, m) {
			out = append(out, m)
		}
	}
	return out
}

// extractVerdict pulls a strict-shape verdict object out of the LLM's
// stdout. Returns nil on no parseable result.
func extractVerdict(cliOutput string) map[string]any {
	if cliOutput == "" {
		return nil
	}
	// Try envelope JSON (e.g. `claude --output-format json` wraps the
	// model response under `result` or `messages[…].content`).
	var envelope any
	candidateText := ""
	if err := json.Unmarshal([]byte(cliOutput), &envelope); err == nil {
		if env, ok := envelope.(map[string]any); ok {
			if s, ok := env["result"].(string); ok && s != "" {
				candidateText = s
			} else if s, ok := env["text"].(string); ok && s != "" {
				candidateText = s
			} else if s, ok := env["response"].(string); ok && s != "" {
				candidateText = s
			}
			if candidateText == "" {
				if msgs, ok := env["messages"].([]any); ok {
					for i := len(msgs) - 1; i >= 0; i-- {
						msg, ok := msgs[i].(map[string]any)
						if !ok {
							continue
						}
						switch c := msg["content"].(type) {
						case string:
							candidateText = c
						case []any:
							for _, item := range c {
								m, ok := item.(map[string]any)
								if !ok {
									continue
								}
								if m["type"] == "text" {
									if t, ok := m["text"].(string); ok {
										candidateText = t
										break
									}
								}
							}
						}
						if candidateText != "" {
							break
						}
					}
				}
			}
		}
	}
	if candidateText == "" {
		candidateText = cliOutput
	}
	for _, cand := range candidateVerdictJSONs(candidateText) {
		var parsed map[string]any
		if err := json.Unmarshal([]byte(cand), &parsed); err != nil {
			continue
		}
		v, _ := parsed["verdict"].(string)
		if v != "allow" && v != "deny" && v != "ask" {
			parsed["verdict"] = "ask"
		}
		if _, ok := parsed["reason"]; !ok {
			parsed["reason"] = "no reason provided"
		}
		return parsed
	}
	return nil
}

// ---------- top-level entry points --------------------------------

// AnalyzePackage runs OSV-cached LLM source review on one published
// package. Returns a verdict map; on cache hit avoids LLM invocation.
func AnalyzePackage(ecosystem, name, version string) map[string]any {
	key := cacheKey(ecosystem, name, version)
	if cached := cacheLoad(key); cached != nil {
		return cached
	}
	bundle := fetchers.Fetch(ecosystem, name, version)
	if bundle == nil {
		return map[string]any{
			"verdict": "ask",
			"reason":  fmt.Sprintf("could not fetch %s:%s", ecosystem, name),
		}
	}
	if v := Prefilter(bundle); v != nil {
		cacheStore(key, v)
		return v
	}
	prompt := buildUserPrompt(bundle)
	output, _, _, err := providers.InvokeLLM(prompt, SystemPrompt)
	if err != nil || output == "" {
		return map[string]any{
			"verdict": "ask",
			"reason":  "llm analyzer returned no parseable verdict",
		}
	}
	v := extractVerdict(output)
	if v == nil {
		return map[string]any{
			"verdict": "ask",
			"reason":  "llm analyzer returned no parseable verdict",
		}
	}
	cacheStore(key, v)
	return v
}

// AnalyzeLocalPlugin runs the analyzer on a plugin directory already
// on disk. contentHash, when provided, is used in the cache key so
// re-scanning the same on-disk contents reuses the verdict.
func AnalyzeLocalPlugin(name, dir, contentHash string) map[string]any {
	bundle := fetchers.FetchPluginLocal(name, dir)
	if bundle == nil {
		return map[string]any{
			"verdict": "ask",
			"reason":  "could not read plugin: " + name,
		}
	}
	var key string
	if contentHash != "" {
		key = cacheKey("plugin-local", name, contentHash)
		if cached := cacheLoad(key); cached != nil {
			return cached
		}
	}
	if v := Prefilter(bundle); v != nil {
		if contentHash != "" {
			cacheStore(key, v)
		}
		return v
	}
	prompt := buildUserPrompt(bundle)
	output, _, _, err := providers.InvokeLLM(prompt, SystemPrompt)
	if err != nil || output == "" {
		return map[string]any{
			"verdict": "ask",
			"reason":  "llm analyzer returned no parseable verdict",
		}
	}
	v := extractVerdict(output)
	if v == nil {
		return map[string]any{
			"verdict": "ask",
			"reason":  "llm analyzer returned no parseable verdict",
		}
	}
	if contentHash != "" {
		cacheStore(key, v)
	}
	return v
}
