// Package audit appends tamper- and integrity-related events to a
// JSON-line audit log at ~/.watchdog/audit.jsonl (overridable via
// WATCHDOG_AUDIT_LOG for tests).
//
// Distinct from internal/log: this log is always on, lives next to
// the shim dir (not in the cache dir), and is read by `watchdog-shim
// doctor` and post-incident forensics. Like internal/log, failures
// are swallowed — auditing must never break a hook's primary contract.
package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/Maxlemore97/watchdog/internal/paths"
)

// Record appends one JSON-line event to the audit log. ts, pid, and
// event fields are auto-populated; fields is merged on top.
func Record(event string, fields map[string]any) {
	path := os.Getenv("WATCHDOG_AUDIT_LOG")
	if path == "" {
		path = paths.AuditLogPath()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
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
