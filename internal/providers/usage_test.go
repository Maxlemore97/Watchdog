package providers

import "testing"

func TestExtractUsage_ClaudeEnvelope(t *testing.T) {
	stdout := `{
		"type": "result",
		"result": "...",
		"usage": {
			"input_tokens": 123,
			"output_tokens": 45,
			"cache_read_input_tokens": 0
		}
	}`
	u, ok := ExtractUsage("claude", stdout)
	if !ok {
		t.Fatal("claude usage extraction failed")
	}
	if u.InputTokens != 123 || u.OutputTokens != 45 {
		t.Errorf("claude usage = %+v", u)
	}
}

func TestExtractUsage_OpenAIEnvelope(t *testing.T) {
	stdout := `{
		"id": "chatcmpl-x",
		"choices": [{"message": {"content": "..."}}],
		"usage": {
			"prompt_tokens": 80,
			"completion_tokens": 20,
			"total_tokens": 100
		}
	}`
	u, ok := ExtractUsage("openai", stdout)
	if !ok {
		t.Fatal("openai usage extraction failed")
	}
	if u.InputTokens != 80 || u.OutputTokens != 20 {
		t.Errorf("openai usage = %+v", u)
	}
}

func TestExtractUsage_GeminiOllamaReturnFalse(t *testing.T) {
	for _, p := range []string{"gemini", "ollama", "generic", "unknown"} {
		_, ok := ExtractUsage(p, `{"usage":{"input_tokens":10,"output_tokens":5}}`)
		if ok {
			t.Errorf("provider %q should not surface tokens", p)
		}
	}
}

func TestExtractUsage_PlainTextReturnsFalse(t *testing.T) {
	_, ok := ExtractUsage("claude", "hello world\n")
	if ok {
		t.Error("plain text should not parse as usage envelope")
	}
}

func TestExtractUsage_ZeroCountsTreatedAsAbsent(t *testing.T) {
	// All-zero usage block is treated as not-present: the analyzer
	// shouldn't emit "0 tokens consumed" if the provider just didn't
	// surface real numbers.
	_, ok := ExtractUsage("claude", `{"usage":{"input_tokens":0,"output_tokens":0}}`)
	if ok {
		t.Error("zero-zero usage should report ok=false")
	}
}

func TestExtractUsage_MalformedJSONReturnsFalse(t *testing.T) {
	_, ok := ExtractUsage("claude", `{"usage": {oops`)
	if ok {
		t.Error("malformed JSON should not parse")
	}
}
