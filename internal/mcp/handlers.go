// Package mcp implements the pure-Go tool handlers that the
// watchdog-mcp binary exposes via stdio MCP. Pulling them out of the
// cmd/main means we can unit-test them without standing up the
// mark3labs/mcp-go SDK — only the thin SDK plumbing lives in
// cmd/watchdog-mcp/main.go.
package mcp

import (
	"time"

	"github.com/Maxlemore97/watchdog/internal/analyzer"
	"github.com/Maxlemore97/watchdog/internal/integrity"
	"github.com/Maxlemore97/watchdog/internal/ledger"
	"github.com/Maxlemore97/watchdog/internal/osv"
	"github.com/Maxlemore97/watchdog/internal/parsers"
	"github.com/Maxlemore97/watchdog/internal/preflight"
	"github.com/Maxlemore97/watchdog/internal/types"
	"github.com/Maxlemore97/watchdog/internal/version"
)

// startedAt records when this process began serving. The
// watchdog_health tool surfaces it as uptime.
var startedAt = time.Now()

// PreflightInstall parses an install command line and runs the shared
// preflight aggregator. Returns the structured Result for the MCP
// boundary to marshal.
func PreflightInstall(command, mode string) preflight.Result {
	pkgs, notes := parsers.CollectPackages(command, osv.ResolveVersion)
	return preflight.Packages(pkgs, notes, preflight.Options{
		Mode:              mode,
		FailClosedVerdict: "ask",
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
func OSVQuery(ecosystem, name, ver string) OSVQueryResult {
	pkg := types.Package{Ecosystem: ecosystem, Name: name, Version: ver}
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

// HealthResult is the structured output of the watchdog_health tool.
// Agents should call this once at session start and refuse to proceed
// with package work if Status != "ok".
type HealthResult struct {
	// Version of the watchdog-mcp binary (ldflag-stamped at build).
	Version string `json:"version"`
	// Status is "ok" (fully protective), "degraded" (some integrity
	// check failed but server is up), or "disabled" (WATCHDOG_DISABLE).
	Status string `json:"status"`
	// ManifestPresent indicates whether `watchdog-shim install` has
	// been run. False means no integrity enforcement is in effect.
	ManifestPresent bool `json:"manifest_present"`
	// Integrity carries the full VerifyDeep result. Agents can inspect
	// Integrity.Failures for fine-grained reasons.
	Integrity integrity.Status `json:"integrity"`
	// HandlerTimeoutSec is the per-tool ceiling enforced by Guard.
	HandlerTimeoutSec float64 `json:"handler_timeout_sec"`
	// UptimeSec is how long this server process has been running.
	UptimeSec float64 `json:"uptime_sec"`
}

// Health returns a structured health snapshot for the agent. Always
// safe to call; never blocks on network.
func Health() HealthResult {
	st := integrity.VerifyDeep()
	status := "ok"
	switch {
	case st.Disabled:
		status = "disabled"
	case !st.OK:
		status = "degraded"
	}
	return HealthResult{
		Version:           version.String(),
		Status:            status,
		ManifestPresent:   !st.ManifestMissing,
		Integrity:         st,
		HandlerTimeoutSec: HandlerTimeout().Seconds(),
		UptimeSec:         time.Since(startedAt).Seconds(),
	}
}
