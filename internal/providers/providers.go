// Package providers shells out to whichever local LLM CLI the user
// has configured. The analyzer treats this as an opaque
// string-in / string-out boundary.
//
// Supported providers (auto-detect order):
//
//	claude   — Anthropic Claude Code CLI
//	gemini   — Google Gemini CLI
//	openai   — OpenAI CLI
//	ollama   — local Ollama
//	generic  — any CLI specified via WATCHDOG_LLM_CMD
//
// The child process always receives WATCHDOG_DISABLE=1 in its env so
// any nested hook the LLM might trigger short-circuits and does not
// recursively re-invoke this analyzer.
package providers

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/Maxlemore97/watchdog/internal/parsers"
)

var ValidProviders = map[string]bool{
	"claude": true, "gemini": true, "openai": true, "ollama": true, "generic": true,
}

var AutoDetectOrder = []string{"claude", "gemini", "openai", "ollama"}

const DefaultTimeout = 60 * time.Second

// Provider describes one configured LLM CLI.
type Provider struct {
	Name         string
	Bin          string
	DefaultModel string
	Invoke       func(prompt string, cfg Config) (string, error)
}

// Config is the per-invocation settings derived from the env.
type Config struct {
	Bin          string
	Model        string
	SystemPrompt string
	AppendSystem bool
	Timeout      time.Duration
	Cmd          string // only for generic
}

// Registry holds all providers, addressable by name.
var Registry = map[string]Provider{
	"claude": {
		Name: "claude", Bin: "claude", DefaultModel: "claude-haiku-4-5-20251001",
		Invoke: invokeClaude,
	},
	"gemini": {
		Name: "gemini", Bin: "gemini", DefaultModel: "gemini-2.5-flash",
		Invoke: invokeGemini,
	},
	"openai": {
		Name: "openai", Bin: "openai", DefaultModel: "gpt-4.1-mini",
		Invoke: invokeOpenAI,
	},
	"ollama": {
		Name: "ollama", Bin: "ollama", DefaultModel: "llama3.1",
		Invoke: invokeOllama,
	},
	"generic": {
		Name: "generic", Bin: "", DefaultModel: "generic",
		Invoke: invokeGeneric,
	},
}

// ErrNoProvider is returned when no usable LLM CLI is available.
var ErrNoProvider = errors.New("providers: no usable LLM CLI on PATH")

// ResolveProvider picks a provider per WATCHDOG_LLM_PROVIDER, falling
// back to PATH auto-detect. Returns ErrNoProvider when none usable.
func ResolveProvider() (Provider, error) {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv("WATCHDOG_LLM_PROVIDER")))
	if raw == "" || raw == "auto" {
		return autoDetect()
	}
	if !ValidProviders[raw] {
		return autoDetect()
	}
	prov := Registry[raw]
	if prov.Name == "generic" {
		// generic always returns; its invoke rejects when
		// WATCHDOG_LLM_CMD is unset/unrunnable.
		return prov, nil
	}
	if _, err := exec.LookPath(prov.Bin); err != nil {
		return Provider{}, ErrNoProvider
	}
	return prov, nil
}

func autoDetect() (Provider, error) {
	for _, name := range AutoDetectOrder {
		prov := Registry[name]
		if _, err := exec.LookPath(prov.Bin); err == nil {
			return prov, nil
		}
	}
	return Provider{}, ErrNoProvider
}

// BuildConfig assembles per-call settings from env.
func BuildConfig(prov Provider, systemPrompt string) Config {
	bin := prov.Bin
	if override := strings.TrimSpace(os.Getenv("WATCHDOG_LLM_BIN")); override != "" {
		bin = override
	}
	model := strings.TrimSpace(os.Getenv("WATCHDOG_LLM_MODEL"))
	if model == "" {
		model = prov.DefaultModel
	}
	timeout := DefaultTimeout
	if raw := strings.TrimSpace(os.Getenv("WATCHDOG_LLM_TIMEOUT")); raw != "" {
		if v, err := strconv.ParseFloat(raw, 64); err == nil {
			timeout = time.Duration(v * float64(time.Second))
		}
	}
	appendSystem := true
	switch strings.ToLower(strings.TrimSpace(os.Getenv("WATCHDOG_LLM_APPEND_SYSTEM"))) {
	case "0", "false", "no", "off":
		appendSystem = false
	}
	return Config{
		Bin:          bin,
		Model:        model,
		SystemPrompt: systemPrompt,
		AppendSystem: appendSystem,
		Timeout:      timeout,
		Cmd:          os.Getenv("WATCHDOG_LLM_CMD"),
	}
}

// InvokeLLM resolves the provider, builds the config, and runs the
// CLI. Returns (stdout, provider, config, error). On no-provider:
// returns ErrNoProvider with zero-valued provider/config.
func InvokeLLM(prompt, systemPrompt string) (string, Provider, Config, error) {
	prov, err := ResolveProvider()
	if err != nil {
		return "", Provider{}, Config{}, err
	}
	cfg := BuildConfig(prov, systemPrompt)
	output, err := prov.Invoke(prompt, cfg)
	return output, prov, cfg, err
}

// ---------- per-provider invocations ------------------------------

func childEnv() []string {
	env := os.Environ()
	out := make([]string, 0, len(env)+1)
	for _, kv := range env {
		if !strings.HasPrefix(kv, "WATCHDOG_DISABLE=") {
			out = append(out, kv)
		}
	}
	out = append(out, "WATCHDOG_DISABLE=1")
	return out
}

// boundedBuffer caps stderr capture from LLM CLIs so a misbehaving
// provider (or a non-LLM binary the user pointed WATCHDOG_LLM_CMD at)
// can't OOM watchdog by flooding stderr.
type boundedBuffer struct {
	limit int
	buf   bytes.Buffer
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	remain := b.limit - b.buf.Len()
	if remain <= 0 {
		return len(p), nil
	}
	if len(p) > remain {
		b.buf.Write(p[:remain])
		return len(p), nil
	}
	return b.buf.Write(p)
}

func (b *boundedBuffer) String() string { return b.buf.String() }

const stderrCapBytes = 64 * 1024

func runCmd(ctx context.Context, name string, args []string, stdin string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = strings.NewReader(stdin)
	cmd.Env = childEnv()
	var stdout bytes.Buffer
	stderr := &boundedBuffer{limit: stderrCapBytes}
	cmd.Stdout = &stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s: %w (stderr: %s)", name, err, truncate(stderr.String(), 200))
	}
	return stdout.String(), nil
}

func invokeClaude(prompt string, cfg Config) (string, error) {
	if _, err := exec.LookPath(cfg.Bin); err != nil {
		return "", ErrNoProvider
	}
	args := []string{
		"-p",
		"--model", cfg.Model,
		"--output-format", "json",
		"--max-turns", "1",
		"--allowed-tools", "",
	}
	if cfg.AppendSystem {
		args = append(args, "--append-system-prompt", cfg.SystemPrompt)
	}
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()
	return runCmd(ctx, cfg.Bin, args, prompt)
}

func invokeGemini(prompt string, cfg Config) (string, error) {
	if _, err := exec.LookPath(cfg.Bin); err != nil {
		return "", ErrNoProvider
	}
	body := combineSystemUser(prompt, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()
	return runCmd(ctx, cfg.Bin, []string{"-m", cfg.Model}, body)
}

func invokeOpenAI(prompt string, cfg Config) (string, error) {
	if _, err := exec.LookPath(cfg.Bin); err != nil {
		return "", ErrNoProvider
	}
	args := []string{"api", "chat.completions.create", "-m", cfg.Model}
	if cfg.AppendSystem {
		args = append(args, "-g", "system", cfg.SystemPrompt)
	}
	args = append(args, "-g", "user", prompt)
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()
	return runCmd(ctx, cfg.Bin, args, "")
}

func invokeOllama(prompt string, cfg Config) (string, error) {
	if _, err := exec.LookPath(cfg.Bin); err != nil {
		return "", ErrNoProvider
	}
	body := combineSystemUser(prompt, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()
	return runCmd(ctx, cfg.Bin, []string{"run", cfg.Model}, body)
}

func invokeGeneric(prompt string, cfg Config) (string, error) {
	if cfg.Cmd == "" {
		return "", ErrNoProvider
	}
	argv, err := parsers.Tokenize(cfg.Cmd)
	if err != nil || len(argv) == 0 {
		return "", ErrNoProvider
	}
	if _, err := exec.LookPath(argv[0]); err != nil {
		return "", ErrNoProvider
	}
	body := combineSystemUser(prompt, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()
	return runCmd(ctx, argv[0], argv[1:], body)
}

func combineSystemUser(prompt string, cfg Config) string {
	if !cfg.AppendSystem || cfg.SystemPrompt == "" {
		return prompt
	}
	return "=== SYSTEM ===\n" + cfg.SystemPrompt + "\n=== USER ===\n" + prompt + "\n"
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
