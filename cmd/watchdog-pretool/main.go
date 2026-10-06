// watchdog-pretool: Claude Code PreToolUse hook entry.
//
// Reads the hook JSON payload from stdin, detects package-manager
// install commands on the Bash tool, runs OSV + LLM analysis via
// preflight.Packages, and writes the hook response on stdout.
// Pass-through cases (non-Bash, empty command, no install detected)
// exit silently with code 0 so other plugins' hook decisions are
// not overridden.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Maxlemore97/watchdog/internal/audit"
	"github.com/Maxlemore97/watchdog/internal/config"
	"github.com/Maxlemore97/watchdog/internal/integrity"
	"github.com/Maxlemore97/watchdog/internal/osv"
	"github.com/Maxlemore97/watchdog/internal/parsers"
	"github.com/Maxlemore97/watchdog/internal/paths"
	"github.com/Maxlemore97/watchdog/internal/preflight"
	"github.com/Maxlemore97/watchdog/internal/shim"
	"github.com/Maxlemore97/watchdog/internal/version"
)

func mode() string {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("WATCHDOG_MODE")))
	if !preflight.ValidModes[v] {
		return "both"
	}
	return v
}

// failClosedVerdict picks the verdict to emit when a check cannot run
// (OSV unreachable, LLM CLI missing, analyzer panic). Defaults to `ask`
// inside Claude Code because the host has a UI to surface a question.
func failClosedVerdict() string {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("WATCHDOG_FAILCLOSED_VERDICT")))
	switch v {
	case "allow", "deny", "ask":
		return v
	}
	return "ask"
}

func hookBudgetSecs() float64 {
	if raw := os.Getenv("WATCHDOG_HOOK_BUDGET_SECS"); raw != "" {
		if v, err := strconv.ParseFloat(raw, 64); err == nil {
			return v
		}
	}
	return 30.0
}

type hookPayload struct {
	SessionID string `json:"session_id"`
	ToolName  string `json:"tool_name"`
	ToolInput struct {
		Command      string `json:"command"`
		FilePath     string `json:"file_path"`
		NotebookPath string `json:"notebook_path"`
	} `json:"tool_input"`
}

// fileWriteTools write files without going through Bash, so neither
// the tamper patterns nor the shim see them.
var fileWriteTools = map[string]bool{
	"Edit": true, "Write": true, "MultiEdit": true, "NotebookEdit": true,
}

// guardFileWrite applies parsers.WritePathVerdict to an Edit/Write
// call. Returns true when it emitted a decision.
func guardFileWrite(p hookPayload) bool {
	target := p.ToolInput.FilePath
	if target == "" {
		target = p.ToolInput.NotebookPath
	}
	verdict, code := parsers.WritePathVerdict(target, paths.WatchdogDir(), shim.ResolveShimDir())
	if verdict == "" {
		return false
	}
	audit.Record("integrity."+verdict, map[string]any{
		"tool":    p.ToolName,
		"reason":  "protected_path_write",
		"pattern": code,
		"path":    truncate(target, 200),
	})
	switch verdict {
	case "deny":
		emit("deny", fmt.Sprintf("%s — %s may not modify Watchdog's own state (%s)", code, p.ToolName, target))
	default:
		emit("ask", fmt.Sprintf("%s — %s wants to modify an agent hook/MCP config (%s); confirm only if you asked for this", code, p.ToolName, target))
	}
	return true
}

// firstNoticeThisSession reports whether the degraded-integrity
// notice has not yet been shown in this session, and records it. The
// notice otherwise lands on every Bash call and costs context tokens
// each turn. Without a session id it always returns true.
func firstNoticeThisSession(sessionID string) bool {
	if sessionID == "" {
		return true
	}
	sum := sha256.Sum256([]byte(sessionID))
	marker := filepath.Join(paths.CacheDir(), "notices", hex.EncodeToString(sum[:8]))
	if _, err := os.Stat(marker); err == nil {
		return false
	}
	if err := os.MkdirAll(filepath.Dir(marker), 0o700); err == nil {
		_ = os.WriteFile(marker, nil, 0o600)
	}
	return true
}

type hookResponse struct {
	HookSpecificOutput map[string]any `json:"hookSpecificOutput"`
}

func emit(decision, reason string) {
	resp := hookResponse{
		HookSpecificOutput: map[string]any{
			"hookEventName":            "PreToolUse",
			"permissionDecision":       decision,
			"permissionDecisionReason": "watchdog: " + reason,
		},
	}
	enc := json.NewEncoder(os.Stdout)
	_ = enc.Encode(resp)
}

// emitContext attaches an informational note to the prompt without
// blocking the tool call. Used when integrity is degraded but the
// command is not install-shaped: the agent (and human reviewer) sees
// the warning while the call proceeds.
func emitContext(text string) {
	resp := hookResponse{
		HookSpecificOutput: map[string]any{
			"hookEventName":     "PreToolUse",
			"additionalContext": "watchdog: " + text,
		},
	}
	enc := json.NewEncoder(os.Stdout)
	_ = enc.Encode(resp)
}

// truncate returns at most n runes of s, suffixed with "…" if cut.
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// isInstallShaped reports whether command parses as a package-manager
// install invocation (possibly inside a subshell or compound). Notes
// also count — they cover the URL/path/requirements-file forms that
// the analyzer would have flagged.
func isInstallShaped(command string) bool {
	if command == "" {
		return false
	}
	pkgs, notes := parsers.CollectPackages(command, nil)
	return len(pkgs) > 0 || len(notes) > 0
}

func main() {
	if version.HandleFlag(os.Args[0], os.Args[1:], os.Stdout) {
		return
	}
	if config.Disabled() {
		return
	}
	// Validate config at startup so a typo'd env var fails fast
	// rather than silently degrading a security default.
	_ = config.MustLoad()

	var payload hookPayload
	dec := json.NewDecoder(os.Stdin)
	if err := dec.Decode(&payload); err != nil {
		return
	}
	if fileWriteTools[payload.ToolName] {
		guardFileWrite(payload)
		return
	}
	if payload.ToolName != "Bash" {
		return
	}
	command := payload.ToolInput.Command
	if command == "" {
		return
	}

	// Tamper-pattern gate. Caught here even when integrity is intact,
	// because patterns like `unset PATH` or `/opt/homebrew/bin/npm
	// install foo` bypass the shim by design — the shim never sees
	// them. This is the only chance to block.
	if tampers := parsers.TamperPatterns(command); len(tampers) > 0 {
		audit.Record("integrity.deny", map[string]any{
			"tool":     "Bash",
			"reason":   "tamper_pattern",
			"patterns": tampers,
			"command":  truncate(command, 200),
		})
		emit("deny", fmt.Sprintf("tamper pattern detected (%s) — refusing to run",
			strings.Join(tampers, ",")))
		return
	}

	// Integrity gate. ManifestMissing is back-compat with manual
	// installs (no `watchdog-shim install`); we do not fail-closed in
	// that case. Other failures (hash mismatch, PATH not first) fail
	// closed for install-shaped commands and emit a context warning
	// otherwise so the agent sees the degraded state.
	status := integrity.Verify()
	if !status.OK && !status.Disabled && !status.ManifestMissing {
		audit.Record("integrity.failed", map[string]any{
			"tool":     "Bash",
			"failures": status.Failures,
		})
		if isInstallShaped(command) {
			audit.Record("integrity.deny", map[string]any{
				"tool":    "Bash",
				"reason":  "integrity_failed",
				"command": truncate(command, 200),
			})
			emit("deny", "integrity check failed ("+status.FirstReason()+
				") — refusing install. Run `watchdog-shim doctor` to diagnose.")
			return
		}
		// Non-install Bash on a degraded install: surface the issue
		// to the agent / user without blocking — once per session.
		if firstNoticeThisSession(payload.SessionID) {
			emitContext("integrity degraded (" + status.FirstReason() +
				"); install commands will be denied until resolved. " +
				"Run `watchdog-shim doctor`.")
		}
		return
	}

	pkgs, notes := parsers.CollectPackages(command, osv.ResolveVersion)
	if len(pkgs) == 0 && len(notes) == 0 {
		return
	}
	r := preflight.Packages(pkgs, notes, preflight.Options{
		Mode:              mode(),
		FailClosedVerdict: failClosedVerdict(),
		BudgetSeconds:     hookBudgetSecs(),
	})
	emit(r.Verdict, r.Reason)
}
