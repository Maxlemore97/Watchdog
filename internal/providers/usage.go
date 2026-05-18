package providers

import (
	"encoding/json"
	"strings"
)

// Usage reports tokens consumed by an LLM invocation. Counts are
// best-effort: only providers whose CLIs emit structured envelopes
// with token totals are parsed. Plain-text providers (gemini default,
// ollama default, generic) return ok=false.
type Usage struct {
	InputTokens  int
	OutputTokens int
}

// ExtractUsage attempts to parse token counts out of a provider's
// stdout. Provider-specific because each CLI wraps its response
// differently; the analyzer only needs the totals.
//
// Returns ok=false when the provider doesn't surface tokens, when
// stdout isn't a recognised JSON envelope, or when both counts are
// zero (which we treat as "not present" — a real exchange always
// has non-zero input tokens).
func ExtractUsage(providerName, stdout string) (Usage, bool) {
	trimmed := strings.TrimSpace(stdout)
	if !strings.HasPrefix(trimmed, "{") {
		return Usage{}, false
	}
	var env map[string]any
	if err := json.Unmarshal([]byte(trimmed), &env); err != nil {
		return Usage{}, false
	}
	switch providerName {
	case "claude":
		// `claude --output-format json` envelope:
		//   { "usage": { "input_tokens": N, "output_tokens": M, ... } }
		return readUsage(env, "input_tokens", "output_tokens")
	case "openai":
		// chat.completions envelope:
		//   { "usage": { "prompt_tokens": N, "completion_tokens": M, ... } }
		return readUsage(env, "prompt_tokens", "completion_tokens")
	}
	// gemini default output is plain text; ollama default likewise.
	// Adding --json / --format json would also require changing the
	// invocation, which is out of scope here.
	return Usage{}, false
}

func readUsage(env map[string]any, inKey, outKey string) (Usage, bool) {
	usage, ok := env["usage"].(map[string]any)
	if !ok {
		return Usage{}, false
	}
	in := intField(usage, inKey)
	out := intField(usage, outKey)
	if in == 0 && out == 0 {
		return Usage{}, false
	}
	return Usage{InputTokens: in, OutputTokens: out}, true
}

func intField(m map[string]any, k string) int {
	switch v := m[k].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case int64:
		return int(v)
	}
	return 0
}
