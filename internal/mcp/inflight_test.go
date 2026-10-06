package mcp

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Handlers that ignore cancellation keep running after Guard times
// out. They must keep holding a slot so the daemon cannot accumulate
// unbounded background work; once all slots are taken, new calls fail
// fast with "busy" instead of spawning more.
func TestGuard_BoundsInFlightWork(t *testing.T) {
	t.Setenv("WATCHDOG_MCP_HANDLER_TIMEOUT", "0.05")
	t.Setenv("WATCHDOG_AUDIT_LOG", t.TempDir()+"/audit.jsonl")
	release := make(chan struct{})
	stuck := func(context.Context) (any, error) { <-release; return nil, nil }

	for range MaxInFlight {
		if _, err := Guard(context.Background(), "stuck", stuck); err == nil {
			t.Fatal("stuck handler should time out")
		}
	}
	_, err := Guard(context.Background(), "extra", func(context.Context) (any, error) { return "ran", nil })
	if err == nil || !strings.Contains(err.Error(), "busy") {
		t.Fatalf("call beyond MaxInFlight: err=%v, want busy", err)
	}

	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for {
		v, err := Guard(context.Background(), "after", func(context.Context) (any, error) { return "ran", nil })
		if err == nil && v == "ran" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("slots not released after handlers finished: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
