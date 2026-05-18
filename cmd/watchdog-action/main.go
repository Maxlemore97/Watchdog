// watchdog-action: GitHub Action entry.
//
// 1. Compute changed files between PR base and HEAD via `git diff`.
// 2. Filter to Claude plugin assets (.claude-plugin, skills/SKILL.md,
//    commands/*.md, hooks/*).
// 3. Group by plugin root and run AnalyzeLocalPlugin on each.
// 4. Emit workflow annotations and exit non-zero if any verdict is at
//    or above WATCHDOG_ACTION_FAIL_ON (default `deny`).
package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Maxlemore97/watchdog/internal/analyzer"
	"github.com/Maxlemore97/watchdog/internal/config"
	"github.com/Maxlemore97/watchdog/internal/ghaction"
	"github.com/Maxlemore97/watchdog/internal/policy"
	"github.com/Maxlemore97/watchdog/internal/version"
)

var validFailOn = map[string]bool{"deny": true, "ask": true, "never": true}

func workspace() string {
	for _, env := range []string{"WATCHDOG_WORKSPACE", "GITHUB_WORKSPACE"} {
		if v := os.Getenv(env); v != "" {
			return v
		}
	}
	wd, _ := os.Getwd()
	return wd
}

func baseRef() string {
	for _, env := range []string{"WATCHDOG_BASE_REF", "GITHUB_BASE_REF"} {
		if v := os.Getenv(env); v != "" {
			return v
		}
	}
	return "main"
}

func headRef() string {
	if v := os.Getenv("WATCHDOG_HEAD_REF"); v != "" {
		return v
	}
	return "HEAD"
}

func failOn() string {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("WATCHDOG_ACTION_FAIL_ON")))
	if !validFailOn[v] {
		return "deny"
	}
	return v
}

// changedFiles returns paths of added/modified/renamed files between
// base and head. Tries `origin/base...head` first; falls back to
// `base...head` for local invocations.
func changedFiles(base, head, ws string) []string {
	for _, spec := range []string{"origin/" + base + "..." + head, base + "..." + head} {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		cmd := exec.CommandContext(ctx, "git", "diff", "--name-only", "--diff-filter=AMR", spec)
		cmd.Dir = ws
		out, err := cmd.Output()
		cancel()
		if err == nil {
			var lines []string
			for _, line := range strings.Split(string(out), "\n") {
				if s := strings.TrimSpace(line); s != "" {
					lines = append(lines, s)
				}
			}
			return lines
		}
	}
	return nil
}

func pluginName(root string) string {
	if root != "" {
		base := filepath.Base(root)
		if base != "" && base != "." {
			return base
		}
		return root
	}
	if repo := os.Getenv("GITHUB_REPOSITORY"); repo != "" {
		idx := strings.LastIndex(repo, "/")
		return repo[idx+1:]
	}
	return "repo-root-plugin"
}

func emitFor(verdict, message string, a ghaction.Annotation) {
	switch verdict {
	case "deny":
		ghaction.Error(message, a)
	case "ask":
		ghaction.Warning(message, a)
	default:
		ghaction.Notice(message, a)
	}
}

func main() {
	if version.HandleFlag(os.Args[0], os.Args[1:], os.Stdout) {
		return
	}
	_ = config.MustLoad()
	base := baseRef()
	head := headRef()
	ws := workspace()
	fOn := failOn()

	files := changedFiles(base, head, ws)
	grouped := ghaction.GroupByPlugin(files)
	if len(grouped) == 0 {
		ghaction.Notice("No Claude plugin assets changed; skipping.", ghaction.Annotation{})
		return
	}

	roots := make([]string, 0, len(grouped))
	for r := range grouped {
		roots = append(roots, r)
	}
	sort.Strings(roots)

	var verdicts []string
	for _, root := range roots {
		touched := grouped[root]
		fullPath := ws
		if root != "" {
			fullPath = filepath.Join(ws, root)
		}
		name := pluginName(root)
		v := analyzer.AnalyzeLocalPlugin(name, fullPath, "")
		if v == nil {
			ghaction.Warning("watchdog: analyzer returned no result for "+name,
				ghaction.Annotation{File: touched[0], Title: "Watchdog"})
			verdicts = append(verdicts, "ask")
			continue
		}
		verdict, _ := v["verdict"].(string)
		if verdict == "" {
			verdict = "ask"
		}
		reason, _ := v["reason"].(string)
		if reason == "" {
			reason = "no reason"
		}
		msg := "watchdog [" + verdict + "] " + name + ": " + reason
		for _, f := range touched {
			emitFor(verdict, msg, ghaction.Annotation{
				File:  f,
				Title: "Watchdog: " + verdict,
			})
		}
		verdicts = append(verdicts, verdict)
	}

	if len(verdicts) == 0 {
		return
	}
	worst := policy.WorstVerdict(verdicts)

	if fOn == "never" {
		return
	}
	if policy.Rank(worst) >= policy.Rank(fOn) {
		os.Exit(1)
	}
}
