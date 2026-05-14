// Package mcp implements the six pure-Go tool handlers that the
// watchdog-mcp binary exposes via stdio MCP. Pulling them out of the
// cmd/main means we can unit-test them without standing up the
// mark3labs/mcp-go SDK — only the thin SDK plumbing lives in
// cmd/watchdog-mcp/main.go.
package mcp

import (
	"github.com/Maxlemore97/watchdog/internal/analyzer"
	"github.com/Maxlemore97/watchdog/internal/ledger"
	"github.com/Maxlemore97/watchdog/internal/osv"
	"github.com/Maxlemore97/watchdog/internal/parsers"
	"github.com/Maxlemore97/watchdog/internal/preflight"
	"github.com/Maxlemore97/watchdog/internal/types"
)

// PreflightInstall parses an install command line and runs the shared
// preflight aggregator. Returns the structured Result for the MCP
// boundary to marshal.
func PreflightInstall(command, mode string) preflight.Result {
	pkgs, notes := parsers.CollectPackages(command, osv.ResolveVersion)
	return preflight.Packages(pkgs, notes, preflight.Options{
		Mode:            mode,
		OfflineDecision: "ask",
	})
}

// ScanPackage runs LLM source review on one published package. Falls
// back to {verdict:ask} when the analyzer cannot produce a verdict.
func ScanPackage(ecosystem, name, version string) map[string]any {
	v := analyzer.AnalyzePackage(ecosystem, name, version)
	if v == nil {
		return map[string]any{"verdict": "ask", "reason": "no result"}
	}
	return v
}

// AuditPlugin classifies a plugin target (git URL, name, name@ver)
// and routes it through AnalyzePackage with ecosystem="plugin".
func AuditPlugin(target string) map[string]any {
	ecosystem, name, version := parsers.ClassifyPluginTarget(target)
	v := analyzer.AnalyzePackage(ecosystem, name, version)
	if v == nil {
		return map[string]any{"verdict": "ask", "reason": "no result"}
	}
	return v
}

// AuditPluginLocal audits an already-installed plugin directory (no
// clone, no network).
func AuditPluginLocal(name, path string) map[string]any {
	v := analyzer.AnalyzeLocalPlugin(name, path, "")
	if v == nil {
		return map[string]any{"verdict": "ask", "reason": "no result"}
	}
	return v
}

// ListVettedPlugins returns the persistent vetted-plugins ledger.
func ListVettedPlugins() ledger.Ledger {
	return ledger.Load()
}

// OSVQueryResult is the structured response shape for the
// watchdog_osv_query MCP tool. Includes a non-empty `error` field
// when the OSV endpoint is unreachable.
type OSVQueryResult struct {
	Error     string           `json:"error,omitempty"`
	Vulns     []map[string]any `json:"vulns"`
	Filtered  []map[string]any `json:"filtered"`
	Threshold string           `json:"threshold"`
}

// OSVQuery returns the raw OSV.dev result + a filtered list at the
// configured severity floor.
func OSVQuery(ecosystem, name, version string) OSVQueryResult {
	pkg := types.Package{Ecosystem: ecosystem, Name: name, Version: version}
	vulns, err := osv.Query(pkg)
	if err != nil {
		return OSVQueryResult{
			Error:     err.Error(),
			Vulns:     []map[string]any{},
			Filtered:  []map[string]any{},
			Threshold: osv.MinSeverity(),
		}
	}
	return OSVQueryResult{
		Vulns:     vulns,
		Filtered:  osv.FilterBySeverity(vulns),
		Threshold: osv.MinSeverity(),
	}
}
