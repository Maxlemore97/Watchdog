package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Maxlemore97/watchdog/internal/providers"
)

func TestRunLLMSmoke_OK(t *testing.T) {
	prov := providers.Provider{Name: "claude", Bin: "claude", DefaultModel: "claude-haiku-4-5-20251001"}
	invoke := func(prompt string, cfg providers.Config) (string, error) {
		return `{"result":"PING"}`, nil
	}
	var buf bytes.Buffer
	runLLMSmoke(&buf, prov, 5*time.Second, invoke)
	out := buf.String()
	if !strings.Contains(out, "ok") || !strings.Contains(out, "claude") {
		t.Errorf("unexpected output: %q", out)
	}
	if !strings.Contains(out, "model=") {
		t.Errorf("output missing model annotation: %q", out)
	}
}

func TestRunLLMSmoke_ProviderError(t *testing.T) {
	prov := providers.Provider{Name: "gemini", Bin: "gemini", DefaultModel: "gemini-2.5-flash"}
	invoke := func(prompt string, cfg providers.Config) (string, error) {
		return "", errors.New("connection refused")
	}
	var buf bytes.Buffer
	runLLMSmoke(&buf, prov, 5*time.Second, invoke)
	out := buf.String()
	if !strings.Contains(out, "fail") {
		t.Errorf("provider error should produce fail line: %q", out)
	}
	if !strings.Contains(out, "connection refused") {
		t.Errorf("error message not surfaced: %q", out)
	}
}

func TestRunLLMSmoke_MissingPingWarns(t *testing.T) {
	prov := providers.Provider{Name: "ollama", Bin: "ollama", DefaultModel: "llama3.1"}
	invoke := func(prompt string, cfg providers.Config) (string, error) {
		return "I am sorry, but I cannot respond.", nil
	}
	var buf bytes.Buffer
	runLLMSmoke(&buf, prov, 5*time.Second, invoke)
	out := buf.String()
	if !strings.Contains(out, "warn") {
		t.Errorf("missing-marker should produce warn line: %q", out)
	}
}

func TestRunLLMSmoke_AppendSystemOff(t *testing.T) {
	// The smoke test must not drag in the full analyzer system prompt
	// — that would balloon the cost of a doctor check.
	prov := providers.Provider{Name: "claude", Bin: "claude", DefaultModel: "claude-haiku-4-5-20251001"}
	var gotCfg providers.Config
	invoke := func(prompt string, cfg providers.Config) (string, error) {
		gotCfg = cfg
		return "PING", nil
	}
	runLLMSmoke(&bytes.Buffer{}, prov, 5*time.Second, invoke)
	if gotCfg.AppendSystem {
		t.Error("smoke must not append the system prompt")
	}
}

func TestRunLLMSmoke_LongErrorTruncated(t *testing.T) {
	prov := providers.Provider{Name: "openai", Bin: "openai", DefaultModel: "gpt-4.1-mini"}
	long := strings.Repeat("x", 500)
	invoke := func(prompt string, cfg providers.Config) (string, error) {
		return "", errors.New(long)
	}
	var buf bytes.Buffer
	runLLMSmoke(&buf, prov, 5*time.Second, invoke)
	out := buf.String()
	// Must surface a truncation marker rather than dumping 500 bytes.
	if !strings.Contains(out, "…") {
		t.Errorf("expected truncation ellipsis in error report: %q", out)
	}
}
