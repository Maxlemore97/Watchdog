// Package config centralizes Watchdog's environment-variable surface.
//
// Watchdog reads many WATCHDOG_* env vars from many packages (osv,
// providers, analyzer, preflight, ledger, paths, log). Before this
// package existed each read happened independently — meaning a typo
// in WATCHDOG_MIN_SEVERITY silently became "low", and there was no
// single point to document or validate the surface.
//
// Pattern: env is the transport (children inherit env from parents,
// which the recursion guard at WATCHDOG_DISABLE relies on), but
// Load() reads, validates, and normalizes every value at startup.
// MustLoad() is for cmd/ entrypoints — bad config fails fast with a
// clear stderr message instead of silently degrading.
//
// Downstream packages keep their existing os.Getenv reads (the
// invasive alternative — threading *Config through every package —
// would change ~30 function signatures with marginal user-visible
// benefit). They observe the normalized values that Load wrote back
// to the process env.
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
	OfflineDecision  string        // WATCHDOG_OFFLINE_DECISION — allow/ask/deny
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
	validOffline      = map[string]bool{"allow": true, "ask": true, "deny": true}
	validActionFailOn = map[string]bool{"deny": true, "ask": true, "never": true}
	validProviders    = map[string]bool{"auto": true, "claude": true, "gemini": true, "openai": true, "ollama": true, "generic": true}
)

// Load reads every WATCHDOG_* env var, validates it, and writes
// normalized values back to the process env so downstream package
// reads observe them. Returns the first validation error.
func Load() (Config, error) {
	c := Config{
		Mode:            envLower("WATCHDOG_MODE", "both"),
		MinSeverity:     envLower("WATCHDOG_MIN_SEVERITY", "low"),
		OfflineDecision: envLower("WATCHDOG_OFFLINE_DECISION", ""),
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
	if c.LLMCacheTTL, err = envSecs("WATCHDOG_LLM_CACHE_TTL", 86400*time.Second); err != nil {
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
	if c.OfflineDecision != "" && !validOffline[c.OfflineDecision] {
		return c, fmt.Errorf("WATCHDOG_OFFLINE_DECISION=%q: want one of allow/ask/deny", c.OfflineDecision)
	}
	if !validActionFailOn[c.ActionFailOn] {
		return c, fmt.Errorf("WATCHDOG_ACTION_FAIL_ON=%q: want one of deny/ask/never", c.ActionFailOn)
	}
	if !validProviders[c.LLMProvider] {
		return c, fmt.Errorf("WATCHDOG_LLM_PROVIDER=%q: want one of auto/claude/gemini/openai/ollama/generic", c.LLMProvider)
	}

	c.writeBack()
	return c, nil
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

// writeBack stamps normalized values back into the process env so
// downstream packages that still read os.Getenv see the validated
// shape (lower-cased, defaults filled).
func (c Config) writeBack() {
	_ = os.Setenv("WATCHDOG_MODE", c.Mode)
	_ = os.Setenv("WATCHDOG_MIN_SEVERITY", c.MinSeverity)
	if c.OfflineDecision != "" {
		_ = os.Setenv("WATCHDOG_OFFLINE_DECISION", c.OfflineDecision)
	}
	_ = os.Setenv("WATCHDOG_LLM_PROVIDER", c.LLMProvider)
	_ = os.Setenv("WATCHDOG_ACTION_FAIL_ON", c.ActionFailOn)
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
