package mcp

import (
	"context"
	"fmt"
	"os"
	"runtime/debug"
	"strconv"
	"time"

	"github.com/Maxlemore97/watchdog/internal/audit"
)

// DefaultHandlerTimeout is the per-tool ceiling for an MCP handler.
// 60s matches the LLM timeout default — a single MCP call should not
// exceed the longest reasonable downstream call.
const DefaultHandlerTimeout = 60 * time.Second

// HandlerTimeout returns the configured per-tool deadline. Override
// via WATCHDOG_MCP_HANDLER_TIMEOUT (in seconds, decimal allowed).
func HandlerTimeout() time.Duration {
	if raw := os.Getenv("WATCHDOG_MCP_HANDLER_TIMEOUT"); raw != "" {
		if v, err := strconv.ParseFloat(raw, 64); err == nil && v > 0 {
			return time.Duration(v * float64(time.Second))
		}
	}
	return DefaultHandlerTimeout
}

// Guard wraps fn with three behaviours every MCP handler needs:
//
//  1. Panic recovery — a panic in any handler is converted to a
//     structured error and a `mcp.tool.panic` audit-log entry. The
//     server keeps serving subsequent calls.
//  2. Bounded timeout — fn receives a context that fires after
//     HandlerTimeout(). If fn honours the context it returns
//     promptly. If it doesn't (because the underlying analyzer or
//     OSV call ignores cancellation), Guard returns to the caller
//     anyway and the goroutine drains in the background — a known
//     and accepted leak vs. forcibly killing in-flight work, which
//     Go cannot do safely.
//  3. Audit logging — start, ok/error/panic/timeout, and duration
//     are appended to ~/.watchdog/audit.jsonl so the absence of a
//     record around an install attempt is itself forensic evidence.
//
// fn returns (result, error). result is opaque; the MCP boundary
// marshals it to JSON.
func Guard(ctx context.Context, name string, fn func(ctx context.Context) (any, error)) (any, error) {
	audit.Record("mcp.tool.start", map[string]any{"tool": name})
	start := time.Now()

	ctx, cancel := context.WithTimeout(ctx, HandlerTimeout())
	defer cancel()

	type outcome struct {
		v   any
		err error
	}
	done := make(chan outcome, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				audit.Record("mcp.tool.panic", map[string]any{
					"tool":  name,
					"panic": fmt.Sprintf("%v", r),
					"stack": string(debug.Stack()),
				})
				// Buffered channel; safe even if Guard already returned
				// on a timeout race.
				done <- outcome{
					err: fmt.Errorf("watchdog: %s panicked: %v", name, r),
				}
			}
		}()
		v, err := fn(ctx)
		done <- outcome{v: v, err: err}
	}()

	select {
	case o := <-done:
		elapsed := time.Since(start).Seconds()
		switch {
		case o.err != nil:
			audit.Record("mcp.tool.error", map[string]any{
				"tool":     name,
				"error":    o.err.Error(),
				"duration": elapsed,
			})
		default:
			audit.Record("mcp.tool.ok", map[string]any{
				"tool":     name,
				"duration": elapsed,
			})
		}
		return o.v, o.err
	case <-ctx.Done():
		audit.Record("mcp.tool.timeout", map[string]any{
			"tool":    name,
			"timeout": HandlerTimeout().Seconds(),
		})
		return nil, fmt.Errorf("watchdog: %s exceeded %s timeout", name, HandlerTimeout())
	}
}
