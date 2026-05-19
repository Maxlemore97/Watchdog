// Package config centralizes Watchdog's environment-variable surface.
//
// Watchdog reads many WATCHDOG_* env vars from many packages (osv,
// providers, analyzer, preflight, ledger, paths, log). Before this
// package existed each read happened independently — meaning a typo
// in WATCHDOG_MIN_SEVERITY silently became "low", and there was no
// single point to document or validate the surface.
//
// MustLoad() is for cmd/ entrypoints: it validates and aborts on bad
// input so a typo in env config never silently degrades a security
// default. Downstream packages keep reading os.Getenv directly. Load
// does NOT mutate the process env — Setenv races with concurrent
// readers in goroutines (see runOSVParallel) and the "normalize-then-
// writeback" pattern offered false confidence: any package that ran
// before MustLoad still saw raw values.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds every WATCHDOG_* knob in one place. Each field
// documents its source env var and default.
//
// WATCHDOG_DISABLE and WATCHDOG_LOG are intentionally not on this
// struct — they're read in tight loops from low-level packages
// (recursion guard, opt-in event log) and threading them adds noise
// without value.
type Config struct {
	Mode             string        // WATCHDOG_MODE — both/osv/claude
	MinSeverity      string        // WATCHDOG_MIN_SEVERITY — none/low/medium/high/critical
	FailClosedVerdict string       // WATCHDOG_FAILCLOSED_VERDICT — allow/ask/deny (verdict when OSV unreachable / LLM CLI missing / analyzer error)
	MaxPackages      int           // WATCHDOG_MAX_PACKAGES
	LLMProvider      string        // WATCHDOG_LLM_PROVIDER
	LLMModel         string        // WATCHDOG_LLM_MODEL
	LLMBin           string        // WATCHDOG_LLM_BIN
	LLMCmd           string        // WATCHDOG_LLM_CMD
	LLMAppendSystem  bool          // WATCHDOG_LLM_APPEND_SYSTEM
	LLMTimeout       time.Duration // WATCHDOG_LLM_TIMEOUT (secs)
	CacheDir         string        // WATCHDOG_CACHE_DIR
	CacheTTL         time.Duration // WATCHDOG_CACHE_TTL (secs)
	LLMCacheTTL      time.Duration // WATCHDOG_LLM_CACHE_TTL (secs)
	HookBudget       time.Duration // WATCHDOG_HOOK_BUDGET_SECS
	SessionMaxScans  int           // WATCHDOG_SESSION_MAX_SCANS
	ActionFailOn     string        // WATCHDOG_ACTION_FAIL_ON — deny/ask/never
	ResolveLatest    string        // WATCHDOG_RESOLVE_LATEST — auto/1/0
	OSVEndpoint      string        // WATCHDOG_OSV_ENDPOINT
	PluginDirs       string        // WATCHDOG_PLUGIN_DIRS
	ShimDir          string        // WATCHDOG_SHIM_DIR
	HeadRef          string        // WATCHDOG_HEAD_REF
}

var (
	validModes        = map[string]bool{"osv": true, "claude": true, "both": true}
	validSeverities   = map[string]bool{"none": true, "low": true, "medium": true, "high": true, "critical": true}
	validFailClosed   = map[string]bool{"allow": true, "ask": true, "deny": true}
	validActionFailOn = map[string]bool{"deny": true, "ask": true, "never": true}
	validProviders    = map[string]bool{"auto": true, "claude": true, "gemini": true, "openai": true, "ollama": true, "generic": true}
)

// Load reads every WATCHDOG_* env var and validates it. Returns the
// first validation error. Does NOT mutate the process env.
func Load() (Config, error) {
	c := Config{
		Mode:            envLower("WATCHDOG_MODE", "both"),
		MinSeverity:     envLower("WATCHDOG_MIN_SEVERITY", "low"),
		FailClosedVerdict: envLower("WATCHDOG_FAILCLOSED_VERDICT", ""),
		LLMProvider:     envLower("WATCHDOG_LLM_PROVIDER", "auto"),
		LLMModel:        strings.TrimSpace(os.Getenv("WATCHDOG_LLM_MODEL")),
		LLMBin:          strings.TrimSpace(os.Getenv("WATCHDOG_LLM_BIN")),
		LLMCmd:          os.Getenv("WATCHDOG_LLM_CMD"),
		LLMAppendSystem: envBool("WATCHDOG_LLM_APPEND_SYSTEM", true),
		ActionFailOn:    envLower("WATCHDOG_ACTION_FAIL_ON", "deny"),
		ResolveLatest:   envLower("WATCHDOG_RESOLVE_LATEST", ""),
		OSVEndpoint:     strings.TrimSpace(os.Getenv("WATCHDOG_OSV_ENDPOINT")),
		CacheDir:        os.Getenv("WATCHDOG_CACHE_DIR"),
		PluginDirs:      os.Getenv("WATCHDOG_PLUGIN_DIRS"),
		ShimDir:         os.Getenv("WATCHDOG_SHIM_DIR"),
		HeadRef:         os.Getenv("WATCHDOG_HEAD_REF"),
	}

	var err error
	if c.MaxPackages, err = envInt("WATCHDOG_MAX_PACKAGES", 50); err != nil {
		return c, err
	}
	if c.SessionMaxScans, err = envInt("WATCHDOG_SESSION_MAX_SCANS", 10); err != nil {
		return c, err
	}
	if c.LLMTimeout, err = envSecs("WATCHDOG_LLM_TIMEOUT", 60*time.Second); err != nil {
		return c, err
	}
	if c.CacheTTL, err = envSecs("WATCHDOG_CACHE_TTL", 3600*time.Second); err != nil {
		return c, err
	}
	// 30 days: cache is content-addressed via bundle digest, so the
	// TTL is a paranoia floor not a freshness driver. Override with
	// WATCHDOG_LLM_CACHE_TTL.
	if c.LLMCacheTTL, err = envSecs("WATCHDOG_LLM_CACHE_TTL", 2592000*time.Second); err != nil {
		return c, err
	}
	if c.HookBudget, err = envSecs("WATCHDOG_HOOK_BUDGET_SECS", 30*time.Second); err != nil {
		return c, err
	}

	if !validModes[c.Mode] {
		return c, fmt.Errorf("WATCHDOG_MODE=%q: want one of osv/claude/both", c.Mode)
	}
	if !validSeverities[c.MinSeverity] {
		return c, fmt.Errorf("WATCHDOG_MIN_SEVERITY=%q: want one of none/low/medium/high/critical", c.MinSeverity)
	}
	if c.FailClosedVerdict != "" && !validFailClosed[c.FailClosedVerdict] {
		return c, fmt.Errorf("WATCHDOG_FAILCLOSED_VERDICT=%q: want one of allow/ask/deny", c.FailClosedVerdict)
	}
	if !validActionFailOn[c.ActionFailOn] {
		return c, fmt.Errorf("WATCHDOG_ACTION_FAIL_ON=%q: want one of deny/ask/never", c.ActionFailOn)
	}
	if !validProviders[c.LLMProvider] {
		return c, fmt.Errorf("WATCHDOG_LLM_PROVIDER=%q: want one of auto/claude/gemini/openai/ollama/generic", c.LLMProvider)
	}

	return c, nil
}

// EnvList reads a comma-separated env var, trims each entry, drops
// empties, and dedupes while preserving first-seen order. Returns nil
// when the var is unset or empty.
func EnvList(name string) []string {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, part := range strings.Split(raw, ",") {
		p := strings.TrimSpace(part)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// Disabled reports whether WATCHDOG_DISABLE is set to a truthy value.
// Hot path for hook entrypoints and the recursion guard inside
// childEnv(); centralized here so every adapter agrees on what
// "disabled" means.
func Disabled() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("WATCHDOG_DISABLE")))
	switch v {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// MustLoad calls Load and aborts the process on validation failure.
// cmd/ entrypoints use this so a typo in env config never silently
// degrades a security-critical default.
func MustLoad() Config {
	c, err := Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "watchdog: invalid config: %v\n", err)
		os.Exit(2)
	}
	return c
}

func envLower(name, def string) string {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	if v == "" {
		return def
	}
	return v
}

func envBool(name string, def bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	switch v {
	case "":
		return def
	case "0", "false", "no", "off":
		return false
	case "1", "true", "yes", "on":
		return true
	}
	return def
}

func envInt(name string, def int) (int, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return def, nil
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return def, fmt.Errorf("%s=%q: %w", name, raw, err)
	}
	if v <= 0 {
		return def, fmt.Errorf("%s=%d: must be > 0", name, v)
	}
	return v, nil
}

func envSecs(name string, def time.Duration) (time.Duration, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return def, nil
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return def, fmt.Errorf("%s=%q: %w", name, raw, err)
	}
	if v <= 0 {
		return def, errors.New(name + ": must be > 0 seconds")
	}
	return time.Duration(v * float64(time.Second)), nil
}
