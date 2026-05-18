// watchdog-mcp: MCP server exposing the Watchdog engine to any
// MCP-aware agent (Claude Desktop, Cursor, Continue, ...).
//
// Tools:
//
//	watchdog_preflight_install     parse + OSV + (optional) LLM
//	watchdog_scan_package          LLM source review of one package
//	watchdog_audit_plugin          audit a plugin git URL / name@ver
//	watchdog_audit_plugin_local    audit an already-installed plugin dir
//	watchdog_list_vetted_plugins   read the persistent ledger
//	watchdog_osv_query             raw OSV.dev query (no LLM, no caching)
//	watchdog_health                self-check: integrity + uptime + version
//
// Every tool runs through wmcp.Guard, which adds panic recovery, a
// bounded timeout, and audit-log entries. Handler business logic
// lives in internal/mcp/handlers.go so it can be unit-tested without
// the SDK; this file is only SDK glue.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/Maxlemore97/watchdog/internal/config"
	wmcp "github.com/Maxlemore97/watchdog/internal/mcp"
	"github.com/Maxlemore97/watchdog/internal/version"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func main() {
	if version.HandleFlag(os.Args[0], os.Args[1:], os.Stdout) {
		return
	}
	_ = config.MustLoad()
	s := server.NewMCPServer("watchdog", version.String())

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

	s.AddTool(
		mcp.NewTool("watchdog_health",
			mcp.WithDescription(
				"Return the Watchdog server's self-check: version, uptime, "+
					"and integrity-manifest status. Call this once at session "+
					"start; if `status` is not `\"ok\"`, refuse to install or "+
					"vet packages and surface `integrity.failures` to the user.")),
		handleHealth,
	)

	if err := server.ServeStdio(s); err != nil {
		fmt.Fprintf(os.Stderr, "watchdog-mcp: serve: %v\n", err)
		os.Exit(1)
	}
}

// ---------- SDK glue: argument extraction + Result marshaling -----
//
// Every handler runs its business call inside wmcp.Guard so a panic,
// a hung downstream, or a slow LLM returns a structured error rather
// than killing the server. wrapResult adapts (any, error) into the
// SDK's (*mcp.CallToolResult, error) — a tool error becomes a
// CallToolResult with isError=true (no transport error).

func wrapResult(v any, err error) (*mcp.CallToolResult, error) {
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	return mcp.NewToolResultJSON(v)
}

func handlePreflightInstall(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	command, err := req.RequireString("command")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	mode := req.GetString("mode", "both")
	return wrapResult(wmcp.Guard(ctx, "watchdog_preflight_install", func(_ context.Context) (any, error) {
		return wmcp.PreflightInstall(command, mode), nil
	}))
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
	ver := req.GetString("version", "")
	return wrapResult(wmcp.Guard(ctx, "watchdog_scan_package", func(_ context.Context) (any, error) {
		return wmcp.ScanPackage(ecosystem, name, ver), nil
	}))
}

func handleAuditPlugin(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	target, err := req.RequireString("target")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	return wrapResult(wmcp.Guard(ctx, "watchdog_audit_plugin", func(_ context.Context) (any, error) {
		return wmcp.AuditPlugin(target), nil
	}))
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
	return wrapResult(wmcp.Guard(ctx, "watchdog_audit_plugin_local", func(_ context.Context) (any, error) {
		return wmcp.AuditPluginLocal(name, path), nil
	}))
}

func handleListVettedPlugins(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return wrapResult(wmcp.Guard(ctx, "watchdog_list_vetted_plugins", func(_ context.Context) (any, error) {
		return wmcp.ListVettedPlugins(), nil
	}))
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
	ver := req.GetString("version", "")
	return wrapResult(wmcp.Guard(ctx, "watchdog_osv_query", func(_ context.Context) (any, error) {
		return wmcp.OSVQuery(ecosystem, name, ver), nil
	}))
}

func handleHealth(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return wrapResult(wmcp.Guard(ctx, "watchdog_health", func(_ context.Context) (any, error) {
		return wmcp.Health(), nil
	}))
}
