// watchdog-mcp: MCP server exposing the Watchdog engine to any
// MCP-aware agent (Claude Desktop, Cursor, Continue, ...).
//
// Six tools mirror the Python adapter:
//
//	watchdog_preflight_install     parse + OSV + (optional) LLM
//	watchdog_scan_package          LLM source review of one package
//	watchdog_audit_plugin          audit a plugin git URL / name@ver
//	watchdog_audit_plugin_local    audit an already-installed plugin dir
//	watchdog_list_vetted_plugins   read the persistent ledger
//	watchdog_osv_query             raw OSV.dev query (no LLM, no caching)
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/Maxlemore97/watchdog/internal/analyzer"
	"github.com/Maxlemore97/watchdog/internal/ledger"
	"github.com/Maxlemore97/watchdog/internal/osv"
	"github.com/Maxlemore97/watchdog/internal/parsers"
	"github.com/Maxlemore97/watchdog/internal/preflight"
	"github.com/Maxlemore97/watchdog/internal/types"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func main() {
	s := server.NewMCPServer("watchdog", "0.4.0")

	s.AddTool(
		mcp.NewTool("watchdog_preflight_install",
			mcp.WithDescription(
				"Pre-flight a package-manager install command. "+
					"Detects npm/pip/cargo/gem/composer installs, runs OSV CVE lookups, "+
					"optionally invokes the LLM analyzer, and returns an aggregated verdict: "+
					"allow, ask, or deny. Use BEFORE the host runs the install."),
			mcp.WithString("command",
				mcp.Description("The full install command line, e.g. `npm install lodash@4.17.21`"),
				mcp.Required()),
			mcp.WithString("mode",
				mcp.Description("`osv`, `claude`, or `both` (default `both`)"),
				mcp.DefaultString("both")),
		),
		handlePreflightInstall,
	)

	s.AddTool(
		mcp.NewTool("watchdog_scan_package",
			mcp.WithDescription("LLM source review of one published package."),
			mcp.WithString("ecosystem",
				mcp.Description("npm, PyPI, crates.io, RubyGems, or Packagist"),
				mcp.Required()),
			mcp.WithString("name", mcp.Description("Package name"), mcp.Required()),
			mcp.WithString("version", mcp.Description("Version (optional; resolves latest if omitted)")),
		),
		handleScanPackage,
	)

	s.AddTool(
		mcp.NewTool("watchdog_audit_plugin",
			mcp.WithDescription("Audit a Claude Code plugin target (git URL, name, or name@version)."),
			mcp.WithString("target",
				mcp.Description("git URL, plugin name, or name@version"),
				mcp.Required()),
		),
		handleAuditPlugin,
	)

	s.AddTool(
		mcp.NewTool("watchdog_audit_plugin_local",
			mcp.WithDescription("Audit a plugin directory already on disk (no clone, no network)."),
			mcp.WithString("name", mcp.Description("Plugin name"), mcp.Required()),
			mcp.WithString("path", mcp.Description("Absolute path to the plugin directory"), mcp.Required()),
		),
		handleAuditPluginLocal,
	)

	s.AddTool(
		mcp.NewTool("watchdog_list_vetted_plugins",
			mcp.WithDescription("Return the persistent vetted-plugins ledger contents.")),
		handleListVettedPlugins,
	)

	s.AddTool(
		mcp.NewTool("watchdog_osv_query",
			mcp.WithDescription("Raw OSV.dev vulnerability query for diagnostics (no LLM, no caching of verdict)."),
			mcp.WithString("ecosystem", mcp.Description("npm, PyPI, …"), mcp.Required()),
			mcp.WithString("name", mcp.Description("Package name"), mcp.Required()),
			mcp.WithString("version", mcp.Description("Version (optional)")),
		),
		handleOSVQuery,
	)

	if err := server.ServeStdio(s); err != nil {
		fmt.Fprintf(os.Stderr, "watchdog-mcp: serve: %v\n", err)
		os.Exit(1)
	}
}

// ---------- handlers ----------------------------------------------

func handlePreflightInstall(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	command, err := req.RequireString("command")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	mode := req.GetString("mode", "both")
	pkgs, notes := parsers.CollectPackages(command, osv.ResolveVersion)
	r := preflight.Packages(pkgs, notes, preflight.Options{
		Mode:            mode,
		OfflineDecision: "ask",
	})
	return mcp.NewToolResultJSON(r)
}

func handleScanPackage(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ecosystem, err := req.RequireString("ecosystem")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	name, err := req.RequireString("name")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	version := req.GetString("version", "")
	v := analyzer.AnalyzePackage(ecosystem, name, version)
	if v == nil {
		v = map[string]any{"verdict": "ask", "reason": "no result"}
	}
	return mcp.NewToolResultJSON(v)
}

func handleAuditPlugin(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	target, err := req.RequireString("target")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	ecosystem, name, version := parsers.ClassifyPluginTarget(target)
	v := analyzer.AnalyzePackage(ecosystem, name, version)
	if v == nil {
		v = map[string]any{"verdict": "ask", "reason": "no result"}
	}
	return mcp.NewToolResultJSON(v)
}

func handleAuditPluginLocal(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	name, err := req.RequireString("name")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	path, err := req.RequireString("path")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	v := analyzer.AnalyzeLocalPlugin(name, path, "")
	if v == nil {
		v = map[string]any{"verdict": "ask", "reason": "no result"}
	}
	return mcp.NewToolResultJSON(v)
}

func handleListVettedPlugins(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return mcp.NewToolResultJSON(ledger.Load())
}

func handleOSVQuery(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ecosystem, err := req.RequireString("ecosystem")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	name, err := req.RequireString("name")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	version := req.GetString("version", "")
	pkg := types.Package{Ecosystem: ecosystem, Name: name, Version: version}
	vulns := osv.Query(pkg)
	return mcp.NewToolResultJSON(map[string]any{
		"vulns":     vulns,
		"filtered":  osv.FilterBySeverity(vulns),
		"threshold": osv.MinSeverity(),
	})
}
