package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// setupAudit redirects the audit log to a temp file and returns the
// path so callers can read what got written.
func setupAudit(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	t.Setenv("WATCHDOG_AUDIT_LOG", path)
	return path
}

// auditEvents returns the parsed JSONL lines from the audit log.
// Empty slice if the file is missing or empty.
func auditEvents(t *testing.T, path string) []map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []map[string]any
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e map[string]any
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("torn audit line: %v\nraw: %s", err, sc.Text())
		}
		out = append(out, e)
	}
	return out
}

func hasEvent(events []map[string]any, name string) bool {
	for _, e := range events {
		if e["event"] == name {
			return true
		}
	}
	return false
}

func TestGuard_NormalCallEmitsStartAndOK(t *testing.T) {
	log := setupAudit(t)
	v, err := Guard(context.Background(), "test_tool", func(_ context.Context) (any, error) {
		return map[string]any{"hello": "world"}, nil
	})
	if err != nil {
		t.Fatalf("Guard returned err: %v", err)
	}
	if m, ok := v.(map[string]any); !ok || m["hello"] != "world" {
		t.Errorf("result = %v", v)
	}
	ev := auditEvents(t, log)
	if !hasEvent(ev, "mcp.tool.start") {
		t.Error("missing mcp.tool.start")
	}
	if !hasEvent(ev, "mcp.tool.ok") {
		t.Error("missing mcp.tool.ok")
	}
}

func TestGuard_RecoversPanic(t *testing.T) {
	log := setupAudit(t)
	v, err := Guard(context.Background(), "panic_tool", func(_ context.Context) (any, error) {
		panic("boom")
	})
	if v != nil {
		t.Errorf("expected nil result on panic, got %v", v)
	}
	if err == nil {
		t.Fatal("expected error on panic")
	}
	if !strings.Contains(err.Error(), "panic_tool") {
		t.Errorf("error doesn't name the tool: %v", err)
	}
	ev := auditEvents(t, log)
	if !hasEvent(ev, "mcp.tool.panic") {
		t.Errorf("missing mcp.tool.panic event; got: %v", ev)
	}
}

func TestGuard_ReturnsErrorWhenHandlerErrs(t *testing.T) {
	log := setupAudit(t)
	want := errors.New("downstream failed")
	v, err := Guard(context.Background(), "err_tool", func(_ context.Context) (any, error) {
		return nil, want
	})
	if v != nil {
		t.Errorf("v = %v", v)
	}
	if !errors.Is(err, want) {
		t.Errorf("err = %v, want %v", err, want)
	}
	ev := auditEvents(t, log)
	if !hasEvent(ev, "mcp.tool.error") {
		t.Errorf("missing mcp.tool.error event")
	}
}

func TestGuard_TimeoutShortCircuits(t *testing.T) {
	log := setupAudit(t)
	// Force a tiny timeout so we don't slow tests.
	t.Setenv("WATCHDOG_MCP_HANDLER_TIMEOUT", "0.05")
	start := time.Now()
	v, err := Guard(context.Background(), "slow_tool", func(ctx context.Context) (any, error) {
		select {
		case <-time.After(2 * time.Second):
			return "should not reach", nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	elapsed := time.Since(start)
	if v != nil {
		t.Errorf("v = %v", v)
	}
	if err == nil || !strings.Contains(err.Error(), "timeout") {
		t.Errorf("expected timeout error, got %v", err)
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("Guard did not return promptly after timeout: %v", elapsed)
	}
	ev := auditEvents(t, log)
	if !hasEvent(ev, "mcp.tool.timeout") {
		t.Errorf("missing mcp.tool.timeout event; got: %v", ev)
	}
}

func TestHandlerTimeout_DefaultsAndOverride(t *testing.T) {
	t.Setenv("WATCHDOG_MCP_HANDLER_TIMEOUT", "")
	if got := HandlerTimeout(); got != DefaultHandlerTimeout {
		t.Errorf("default = %v, want %v", got, DefaultHandlerTimeout)
	}
	t.Setenv("WATCHDOG_MCP_HANDLER_TIMEOUT", "12.5")
	if got := HandlerTimeout(); got != 12500*time.Millisecond {
		t.Errorf("override = %v, want 12.5s", got)
	}
	t.Setenv("WATCHDOG_MCP_HANDLER_TIMEOUT", "garbage")
	if got := HandlerTimeout(); got != DefaultHandlerTimeout {
		t.Errorf("bogus value should fall back to default, got %v", got)
	}
}
