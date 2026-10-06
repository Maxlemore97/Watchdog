package projectscan

import (
	"os"
	"path/filepath"

	"github.com/Maxlemore97/watchdog/internal/hosts"
	"github.com/Maxlemore97/watchdog/internal/mcpconfig"
	"github.com/Maxlemore97/watchdog/internal/osv"
	"github.com/Maxlemore97/watchdog/internal/parsers"
	"github.com/Maxlemore97/watchdog/internal/policy"
	"github.com/Maxlemore97/watchdog/internal/preflight"
)

// MCPAuditOpts controls AuditMCP.
type MCPAuditOpts struct {
	// Configs overrides the config files to read (tests). Empty means
	// UserMCPConfigs().
	Configs []string
	// Mode is the preflight mode for the packages servers launch:
	// "osv" (default, no LLM cost) or "both".
	Mode string
}

// MCPServerReport is one audited server.
type MCPServerReport struct {
	mcpconfig.Server
	Commandline string              `json:"commandline,omitempty"`
	Verdict     string              `json:"verdict"`
	Findings    []mcpconfig.Finding `json:"findings,omitempty"`
	Preflight   *preflight.Result   `json:"preflight,omitempty"`
}

// MCPAuditResult is the output of AuditMCP.
type MCPAuditResult struct {
	Verdict string            `json:"verdict"`
	Configs []string          `json:"configs"`
	Errors  []string          `json:"errors,omitempty"`
	Servers []MCPServerReport `json:"servers"`
}

// UserMCPConfigs lists the user-level MCP configs of every known host
// plus Claude Code's ~/.claude.json and OpenCode's global config.
func UserMCPConfigs() []string {
	var out []string
	for _, h := range hosts.All() {
		if p := h.ConfigPath(); p != "" {
			out = append(out, p)
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		out = append(out,
			filepath.Join(home, ".claude.json"),
			filepath.Join(home, ".config", "opencode", "opencode.json"),
		)
	}
	return out
}

// AuditMCP reads every existing config, checks each server
// deterministically (pinning, transport, literal secrets) and runs the
// package each server launches through preflight.
func AuditMCP(opts MCPAuditOpts) MCPAuditResult {
	configs := opts.Configs
	if len(configs) == 0 {
		configs = UserMCPConfigs()
	}
	mode := opts.Mode
	if mode == "" {
		mode = "osv"
	}
	res := MCPAuditResult{Verdict: "allow", Configs: []string{}, Servers: []MCPServerReport{}}
	verdicts := []string{"allow"}
	for _, path := range configs {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		servers, err := mcpconfig.Load(path)
		if err != nil {
			res.Errors = append(res.Errors, err.Error())
			verdicts = append(verdicts, "ask")
			continue
		}
		res.Configs = append(res.Configs, path)
		for _, s := range servers {
			if s.Name == hosts.EntryName {
				continue // our own registration
			}
			rep := MCPServerReport{Server: s, Commandline: s.Commandline(), Findings: mcpconfig.Check(s)}
			sv := []string{"allow"}
			for _, f := range rep.Findings {
				sv = append(sv, f.Verdict)
			}
			if rep.Commandline != "" {
				pkgs, notes := parsers.CollectPackages(rep.Commandline, osv.ResolveVersion)
				if len(pkgs) > 0 {
					pre := preflight.Packages(pkgs, notes, preflight.Options{Mode: mode, FailClosedVerdict: "ask"})
					rep.Preflight = &pre
					sv = append(sv, pre.Verdict)
				}
			}
			rep.Verdict = policy.WorstVerdict(sv)
			verdicts = append(verdicts, rep.Verdict)
			res.Servers = append(res.Servers, rep)
		}
	}
	res.Verdict = policy.WorstVerdict(verdicts)
	return res
}
