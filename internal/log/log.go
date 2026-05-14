// Package log provides opt-in JSON-line event logging.
//
// Disabled by default. Set WATCHDOG_LOG to a writable file path to
// enable; events are appended as JSON lines so they survive across
// hook invocations and can be tailed live. Failures (path unwritable,
// disk full, etc.) are swallowed — diagnostics must never break a
// hook's primary contract.
package log

import (
	"encoding/json"
	"os"
	"time"
)

// Event appends one JSON line to the configured WATCHDOG_LOG path if
// set. No-op otherwise. fields is merged into the record alongside
// `ts`, `event`, and `pid`.
func Event(event string, fields map[string]any) {
	path := os.Getenv("WATCHDOG_LOG")
	if path == "" {
		return
	}
	record := map[string]any{
		"ts":    float64(time.Now().UnixNano()) / 1e9,
		"event": event,
		"pid":   os.Getpid(),
	}
	for k, v := range fields {
		record[k] = v
	}
	data, err := json.Marshal(record)
	if err != nil {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(data, '\n'))
}
