package config

import (
	"strings"
	"testing"
	"time"
)

func TestLoad_Defaults(t *testing.T) {
	// Clear every env we care about.
	for _, k := range []string{
		"WATCHDOG_MODE", "WATCHDOG_MIN_SEVERITY", "WATCHDOG_FAILCLOSED_VERDICT",
		"WATCHDOG_MAX_PACKAGES", "WATCHDOG_LLM_PROVIDER", "WATCHDOG_LLM_TIMEOUT",
		"WATCHDOG_CACHE_TTL", "WATCHDOG_LLM_CACHE_TTL", "WATCHDOG_HOOK_BUDGET_SECS",
		"WATCHDOG_SESSION_MAX_SCANS", "WATCHDOG_ACTION_FAIL_ON",
	} {
		t.Setenv(k, "")
	}
	c, err := Load()
	if err != nil {
		t.Fatalf("Load default: %v", err)
	}
	if c.Mode != "both" {
		t.Errorf("default Mode=%q", c.Mode)
	}
	if c.MinSeverity != "low" {
		t.Errorf("default MinSeverity=%q", c.MinSeverity)
	}
	if c.MaxPackages != 50 {
		t.Errorf("default MaxPackages=%d", c.MaxPackages)
	}
	if c.LLMTimeout != 60*time.Second {
		t.Errorf("default LLMTimeout=%v", c.LLMTimeout)
	}
	if c.ActionFailOn != "deny" {
		t.Errorf("default ActionFailOn=%q", c.ActionFailOn)
	}
}

func TestLoad_RejectsInvalidMode(t *testing.T) {
	t.Setenv("WATCHDOG_MODE", "bogus")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "WATCHDOG_MODE") {
		t.Errorf("want WATCHDOG_MODE error, got %v", err)
	}
}

func TestLoad_RejectsInvalidSeverity(t *testing.T) {
	t.Setenv("WATCHDOG_MIN_SEVERITY", "kinda-bad")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "MIN_SEVERITY") {
		t.Errorf("want severity error, got %v", err)
	}
}

func TestLoad_RejectsBadInt(t *testing.T) {
	t.Setenv("WATCHDOG_MAX_PACKAGES", "not-a-number")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "MAX_PACKAGES") {
		t.Errorf("want int parse error, got %v", err)
	}
}

func TestLoad_NormalizesCase(t *testing.T) {
	t.Setenv("WATCHDOG_MODE", "BOTH")
	t.Setenv("WATCHDOG_MIN_SEVERITY", "HIGH")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.Mode != "both" || c.MinSeverity != "high" {
		t.Errorf("not normalized: %+v", c)
	}
}

func TestDisabled(t *testing.T) {
	for _, v := range []string{"1", "true", "yes", "on", "TRUE", "Yes"} {
		t.Setenv("WATCHDOG_DISABLE", v)
		if !Disabled() {
			t.Errorf("Disabled(%q) = false, want true", v)
		}
	}
	for _, v := range []string{"", "0", "false", "no", "off"} {
		t.Setenv("WATCHDOG_DISABLE", v)
		if Disabled() {
			t.Errorf("Disabled(%q) = true, want false", v)
		}
	}
}

func TestLoad_AcceptsValidFailClosed(t *testing.T) {
	for _, v := range []string{"allow", "ask", "deny"} {
		t.Setenv("WATCHDOG_FAILCLOSED_VERDICT", v)
		c, err := Load()
		if err != nil {
			t.Errorf("failclosed=%q rejected: %v", v, err)
		}
		if c.FailClosedVerdict != v {
			t.Errorf("failclosed=%q not preserved: %q", v, c.FailClosedVerdict)
		}
	}
}
