// watchdog-prompt: Claude Code UserPromptSubmit hook entry.
//
// Intercepts `/plugin install <target>` and `/plugin marketplace add
// <git-url>` patterns, runs the LLM analyzer on the target, and
// either blocks (deny), asks (ask), or injects context (allow).
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/Maxlemore97/watchdog/internal/analyzer"
	"github.com/Maxlemore97/watchdog/internal/config"
	"github.com/Maxlemore97/watchdog/internal/parsers"
	"github.com/Maxlemore97/watchdog/internal/policy"
	"github.com/Maxlemore97/watchdog/internal/version"
)

type promptPayload struct {
	Prompt string `json:"prompt"`
}

func emit(decision, context string) {
	if decision == "" && context == "" {
		return
	}
	payload := map[string]any{}
	if decision != "" {
		payload["decision"] = decision
		if context != "" {
			payload["reason"] = context
		}
	} else if context != "" {
		payload["hookSpecificOutput"] = map[string]any{
			"hookEventName":     "UserPromptSubmit",
			"additionalContext": context,
		}
	}
	_ = json.NewEncoder(os.Stdout).Encode(payload)
}

type targetVerdict struct {
	target  string
	verdict map[string]any
}

func main() {
	if version.HandleFlag(os.Args[0], os.Args[1:], os.Stdout) {
		return
	}
	if config.Disabled() {
		return
	}
	_ = config.MustLoad()
	var payload promptPayload
	if err := json.NewDecoder(os.Stdin).Decode(&payload); err != nil {
		return
	}
	prompt := strings.TrimSpace(payload.Prompt)
	if prompt == "" {
		return
	}
	targets := parsers.ExtractPluginTargets(prompt)
	if len(targets) == 0 {
		return
	}

	var verdicts []targetVerdict
	for _, tgt := range targets {
		ecosystem, name, ver := parsers.ClassifyPluginTarget(tgt)
		v := analyzer.AnalyzePackage(ecosystem, name, ver)
		if v != nil {
			verdicts = append(verdicts, targetVerdict{target: tgt, verdict: v})
		}
	}

	if len(verdicts) == 0 {
		emit("", "watchdog: plugin install detected but analyzer unavailable.")
		return
	}

	worst := verdicts[0]
	for _, v := range verdicts[1:] {
		if policy.Rank(verdictStr(v.verdict)) > policy.Rank(verdictStr(worst.verdict)) {
			worst = v
		}
	}
	decision := verdictStr(worst.verdict)
	reason, _ := worst.verdict["reason"].(string)
	if reason == "" {
		reason = "no reason"
	}
	risk, _ := worst.verdict["risk"].(string)
	if risk == "" {
		risk = "?"
	}
	summary := fmt.Sprintf("watchdog plugin scan: %s -> %s (%s): %s",
		worst.target, decision, risk, reason)

	switch decision {
	case "deny":
		emit("block", summary)
	case "ask":
		emit("", summary+"  [proceed only if you trust this source]")
	default:
		emit("", summary)
	}
}

func verdictStr(v map[string]any) string {
	if s, ok := v["verdict"].(string); ok && s != "" {
		return s
	}
	return "ask"
}
