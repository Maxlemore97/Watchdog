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
	"encoding/json"
	"os"
	"strconv"
	"strings"

	"github.com/Maxlemore97/watchdog/internal/osv"
	"github.com/Maxlemore97/watchdog/internal/parsers"
	"github.com/Maxlemore97/watchdog/internal/preflight"
)

func disabled() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("WATCHDOG_DISABLE")))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

func mode() string {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("WATCHDOG_MODE")))
	if !preflight.ValidModes[v] {
		return "both"
	}
	return v
}

func offlineDecision() string {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("WATCHDOG_OFFLINE_DECISION")))
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
	ToolName  string `json:"tool_name"`
	ToolInput struct {
		Command string `json:"command"`
	} `json:"tool_input"`
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

func main() {
	if disabled() {
		return
	}
	var payload hookPayload
	dec := json.NewDecoder(os.Stdin)
	if err := dec.Decode(&payload); err != nil {
		return
	}
	if payload.ToolName != "Bash" {
		return
	}
	command := payload.ToolInput.Command
	if command == "" {
		return
	}
	pkgs, notes := parsers.CollectPackages(command, osv.ResolveVersion)
	if len(pkgs) == 0 && len(notes) == 0 {
		return
	}
	r := preflight.Packages(pkgs, notes, preflight.Options{
		Mode:            mode(),
		OfflineDecision: offlineDecision(),
		BudgetSeconds:   hookBudgetSecs(),
	})
	emit(r.Verdict, r.Reason)
}
