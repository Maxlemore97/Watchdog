// watchdog-session: Claude Code SessionStart hook entry.
//
// Re-analyzes any plugin whose content hash has changed since the
// last session (or that has never been scanned). Findings are
// injected as additionalContext in the SessionStart hook response.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Maxlemore97/watchdog/internal/analyzer"
	"github.com/Maxlemore97/watchdog/internal/config"
	"github.com/Maxlemore97/watchdog/internal/ledger"
	"github.com/Maxlemore97/watchdog/internal/policy"
)

func emitContext(text string) {
	resp := map[string]any{
		"hookSpecificOutput": map[string]any{
			"hookEventName":     "SessionStart",
			"additionalContext": text,
		},
	}
	_ = json.NewEncoder(os.Stdout).Encode(resp)
}

func formatSummary(findings []ledger.ScanResult, skipped int) string {
	var b strings.Builder
	b.WriteString("watchdog session scan — new or updated plugins detected:\n")
	for _, f := range findings {
		v := f.Verdict
		verdict := "ask"
		if s, ok := v["verdict"].(string); ok && s != "" {
			verdict = s
		}
		risk := "?"
		if s, ok := v["risk"].(string); ok && s != "" {
			risk = s
		}
		reason := ""
		if s, ok := v["reason"].(string); ok {
			reason = s
		}
		if len(reason) > 200 {
			reason = reason[:200]
		}
		b.WriteString(fmt.Sprintf("  - %s: %s (%s) — %s\n", f.Name, verdict, risk, reason))
	}
	if skipped > 0 {
		b.WriteString(fmt.Sprintf("  (+ %d more pending; raise WATCHDOG_SESSION_MAX_SCANS to scan all)\n", skipped))
	}
	return strings.TrimRight(b.String(), "\n")
}

func main() {
	if config.Disabled() {
		return
	}
	_ = config.MustLoad()
	// Drain stdin (hook payload not used here).
	_, _ = io.Copy(io.Discard, os.Stdin)

	plugins := ledger.Discover(nil)
	if len(plugins) == 0 {
		return
	}
	var findings []ledger.ScanResult
	var skipped int
	ledger.WithLock(func() {
		l := ledger.Load()
		var dirty bool
		findings, dirty, skipped = ledger.Scan(plugins, &l, analyzer.AnalyzeLocalPlugin, 0)
		if dirty {
			ledger.Save(l)
		}
	})
	if len(findings) == 0 {
		return
	}
	verdicts := make([]string, 0, len(findings))
	for _, f := range findings {
		if s, ok := f.Verdict["verdict"].(string); ok {
			verdicts = append(verdicts, s)
		}
	}
	_ = policy.WorstVerdict(verdicts) // computed for future telemetry use
	emitContext(formatSummary(findings, skipped))
}
