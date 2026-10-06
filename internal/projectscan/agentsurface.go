package projectscan

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Maxlemore97/watchdog/internal/hiddentext"
	"github.com/Maxlemore97/watchdog/internal/mcpconfig"
	"github.com/Maxlemore97/watchdog/internal/policy"
)

// Agent surface of a repository: files an AI coding agent loads as
// instructions, and project config that makes a host run commands on
// its own. A cloned repo can carry all of them, so they are checked
// deterministically (no LLM, fast enough for every session start).

// instructionBasenames are loaded as agent instructions wherever
// they appear (lowercased).
var instructionBasenames = map[string]bool{
	"claude.md": true, "claude.local.md": true, "agents.md": true, "gemini.md": true,
	".cursorrules": true, ".windsurfrules": true, ".clinerules": true,
	"copilot-instructions.md": true,
}

// instructionDirs hold instruction files, rules, skills, commands and
// subagents; every file below them is part of the agent surface.
var instructionDirs = []string{
	".cursor/rules/", ".windsurf/rules/", ".clinerules/", ".github/instructions/",
	".github/prompts/", ".claude/commands/", ".claude/agents/", ".claude/skills/",
	".agents/skills/", ".codex/skills/", ".gemini/commands/",
}

// mcpConfigPaths are project-level MCP server configs.
var mcpConfigPaths = map[string]bool{
	".mcp.json": true, ".vscode/mcp.json": true, ".cursor/mcp.json": true,
	".gemini/settings.json": true, "opencode.json": true, ".roo/mcp.json": true,
}

// AgentSurfaceFinding is one issue in one file.
type AgentSurfaceFinding struct {
	Path    string `json:"path"`
	Verdict string `json:"verdict"`
	Reason  string `json:"reason"`
}

// AgentSurfaceResult summarises the repository's agent surface.
type AgentSurfaceResult struct {
	Verdict  string                `json:"verdict"`
	Files    []string              `json:"files"`
	Findings []AgentSurfaceFinding `json:"findings,omitempty"`
}

// Limits keep the session-start path fast on huge repos.
const (
	agentSurfaceMaxFiles = 500
	agentSurfaceMaxBytes = 512 << 10
)

// ScanAgentSurface walks root (skipping vendored and build dirs) and
// checks every agent-surface file.
func ScanAgentSurface(root string, maxDepth int) AgentSurfaceResult {
	if maxDepth <= 0 {
		maxDepth = 6
	}
	res := AgentSurfaceResult{Verdict: "allow"}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return res
	}
	_ = filepath.WalkDir(absRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil || len(res.Files) >= agentSurfaceMaxFiles {
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(absRoot, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel != "." && (skipDirNames[strings.ToLower(d.Name())] || strings.Count(rel, "/") >= maxDepth) {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		kind := classifyAgentFile(rel)
		if kind == "" {
			return nil
		}
		res.Files = append(res.Files, rel)
		data, err := readCapped(p)
		if err != nil {
			return nil
		}
		res.Findings = append(res.Findings, checkAgentFile(rel, kind, p, data)...)
		return nil
	})
	sort.Strings(res.Files)
	verdicts := []string{"allow"}
	for _, f := range res.Findings {
		verdicts = append(verdicts, f.Verdict)
	}
	res.Verdict = policy.WorstVerdict(verdicts)
	return res
}

// classifyAgentFile returns "instructions", "settings", "tasks", "mcp"
// or "" for files outside the agent surface.
func classifyAgentFile(rel string) string {
	low := strings.ToLower(rel)
	switch {
	case low == ".claude/settings.json" || low == ".claude/settings.local.json" ||
		strings.HasSuffix(low, "/.claude/settings.json") || strings.HasSuffix(low, "/.claude/settings.local.json"):
		return "settings"
	case low == ".vscode/tasks.json" || strings.HasSuffix(low, "/.vscode/tasks.json"):
		return "tasks"
	case mcpConfigPaths[lastTwo(low)] || mcpConfigPaths[filepathBase(low)]:
		return "mcp"
	case instructionBasenames[filepathBase(low)]:
		return "instructions"
	}
	for _, d := range instructionDirs {
		if strings.HasPrefix(low, d) || strings.Contains(low, "/"+d) {
			return "instructions"
		}
	}
	return ""
}

func filepathBase(p string) string { return p[strings.LastIndex(p, "/")+1:] }

// lastTwo returns the last two path segments ("a/b/.vscode/mcp.json" →
// ".vscode/mcp.json").
func lastTwo(p string) string {
	i := strings.LastIndex(p, "/")
	if i <= 0 {
		return p
	}
	j := strings.LastIndex(p[:i], "/")
	return p[j+1:]
}

func readCapped(p string) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, agentSurfaceMaxBytes))
}

var codeExts = map[string]bool{
	".sh": true, ".bash": true, ".zsh": true, ".py": true, ".js": true, ".mjs": true,
	".cjs": true, ".ts": true, ".rb": true, ".ps1": true, ".pl": true, ".lua": true,
}

func checkAgentFile(rel, kind, abs string, data []byte) []AgentSurfaceFinding {
	var out []AgentSurfaceFinding
	add := func(verdict, reason string) {
		out = append(out, AgentSurfaceFinding{Path: rel, Verdict: verdict, Reason: reason})
	}
	if v, reason := hiddentext.Scan(string(data)).Verdict(codeExts[strings.ToLower(filepath.Ext(rel))]); v != "" {
		add(v, reason)
	}
	switch kind {
	case "settings":
		out = append(out, checkClaudeSettings(rel, data)...)
	case "tasks":
		out = append(out, checkVSCodeTasks(rel, data)...)
	case "mcp":
		servers, err := mcpconfig.Load(abs)
		if err != nil {
			add("ask", "unparseable MCP config: "+err.Error())
			break
		}
		for _, s := range servers {
			for _, f := range mcpconfig.Check(s) {
				add(f.Verdict, fmt.Sprintf("MCP server %q: %s", f.Server, f.Reason))
			}
		}
	}
	return out
}

// checkClaudeSettings flags project settings that run commands or
// widen permissions without the user acting: hooks fire on session
// start / tool use (a persistence trick seen in 2026 npm worms), and
// MCP auto-approval or bypass mode remove the confirmation step.
func checkClaudeSettings(rel string, data []byte) []AgentSurfaceFinding {
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		return []AgentSurfaceFinding{{Path: rel, Verdict: "ask", Reason: "unparseable Claude settings: " + err.Error()}}
	}
	var out []AgentSurfaceFinding
	if hooks, ok := cfg["hooks"].(map[string]any); ok {
		events := make([]string, 0, len(hooks))
		for ev := range hooks {
			events = append(events, ev)
		}
		sort.Strings(events)
		for _, ev := range events {
			for _, cmd := range hookCommands(hooks[ev]) {
				out = append(out, AgentSurfaceFinding{Path: rel, Verdict: "ask",
					Reason: fmt.Sprintf("project registers a %s hook that runs: %s", ev, truncateRunes(cmd, 160))})
			}
		}
	}
	if v, _ := cfg["enableAllProjectMcpServers"].(bool); v {
		out = append(out, AgentSurfaceFinding{Path: rel, Verdict: "ask",
			Reason: "enableAllProjectMcpServers auto-approves every MCP server in .mcp.json"})
	}
	if perms, ok := cfg["permissions"].(map[string]any); ok {
		if mode, _ := perms["defaultMode"].(string); mode == "bypassPermissions" {
			out = append(out, AgentSurfaceFinding{Path: rel, Verdict: "ask",
				Reason: "permissions.defaultMode=bypassPermissions disables all confirmations"})
		}
		if allow, ok := perms["allow"].([]any); ok {
			for _, a := range allow {
				if s, _ := a.(string); s == "Bash" || s == "Bash(*)" || s == "Bash(:*)" {
					out = append(out, AgentSurfaceFinding{Path: rel, Verdict: "ask",
						Reason: "permissions.allow grants unrestricted Bash: " + s})
				}
			}
		}
	}
	return out
}

// hookCommands extracts command strings from a hook event value:
// [{matcher, hooks:[{type:"command", command:"…"}]}].
func hookCommands(v any) []string {
	var out []string
	entries, _ := v.([]any)
	for _, e := range entries {
		em, _ := e.(map[string]any)
		hs, _ := em["hooks"].([]any)
		for _, h := range hs {
			hm, _ := h.(map[string]any)
			if c, ok := hm["command"].(string); ok && c != "" {
				out = append(out, c)
			} else if u, ok := hm["url"].(string); ok && u != "" {
				out = append(out, "HTTP "+u)
			}
		}
	}
	return out
}

// checkVSCodeTasks flags tasks that run automatically when the folder
// is opened (runOptions.runOn = folderOpen).
func checkVSCodeTasks(rel string, data []byte) []AgentSurfaceFinding {
	var cfg struct {
		Tasks []struct {
			Label      string `json:"label"`
			Command    string `json:"command"`
			Args       []any  `json:"args"`
			RunOptions struct {
				RunOn string `json:"runOn"`
			} `json:"runOptions"`
		} `json:"tasks"`
	}
	if err := json.Unmarshal(mcpconfig.StripJSONC(data), &cfg); err != nil {
		return nil
	}
	var out []AgentSurfaceFinding
	for _, t := range cfg.Tasks {
		if t.RunOptions.RunOn != "folderOpen" {
			continue
		}
		cmd := t.Command
		for _, a := range t.Args {
			if s, ok := a.(string); ok {
				cmd += " " + s
			}
		}
		out = append(out, AgentSurfaceFinding{Path: rel, Verdict: "ask",
			Reason: fmt.Sprintf("task %q runs automatically on folder open: %s", t.Label, truncateRunes(cmd, 160))})
	}
	return out
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
