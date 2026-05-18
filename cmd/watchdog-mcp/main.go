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
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/Maxlemore97/watchdog/internal/audit"
	"github.com/Maxlemore97/watchdog/internal/config"
	"github.com/Maxlemore97/watchdog/internal/decisions"
	wmcp "github.com/Maxlemore97/watchdog/internal/mcp"
	"github.com/Maxlemore97/watchdog/internal/paths"
	"github.com/Maxlemore97/watchdog/internal/version"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// listenAddr is the configured value of --listen (or
// $WATCHDOG_DAEMON_LISTEN). Empty means stdio mode (default). Special
// values:
//
//	"auto"             → unix://$WATCHDOG_DIR/mcp.sock
//	"unix:///abs.sock" → AF_UNIX listener at /abs.sock (mode 0600)
//	"tcp://host:port"  → TCP listener; refused unless host is loopback
var listenAddr string

func main() {
	if version.HandleFlag(os.Args[0], os.Args[1:], os.Stdout) {
		return
	}
	flag.StringVar(&listenAddr, "listen", os.Getenv("WATCHDOG_DAEMON_LISTEN"),
		"address to serve over HTTP+SSE instead of stdio; "+
			"e.g., 'auto', 'unix:///path/to/sock', 'tcp://127.0.0.1:7274'")
	flag.Parse()

	_ = config.MustLoad()
	// Sweep stale decision tokens at startup — keeps the cache dir
	// bounded if a previous MCP run died before its tokens expired.
	_ = decisions.Cleanup()
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

	if listenAddr == "" {
		if err := server.ServeStdio(s); err != nil {
			fmt.Fprintf(os.Stderr, "watchdog-mcp: serve: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if err := serveDaemon(s, listenAddr); err != nil {
		fmt.Fprintf(os.Stderr, "watchdog-mcp daemon: %v\n", err)
		os.Exit(1)
	}
}

// serveDaemon listens at addr and serves the MCP protocol over
// Streamable HTTP (POST + SSE) on the `/mcp` path. Supports two
// transports:
//
//   - unix://PATH — AF_UNIX socket. Filesystem perms (0600) act as
//     authentication; only the owning user can connect.
//   - tcp://HOST:PORT — Non-loopback hosts are refused to avoid
//     accidentally exposing watchdog-mcp to the network. Token-based
//     auth for TCP is a follow-up.
//
// "auto" expands to unix://$WATCHDOG_DIR/mcp.sock.
func serveDaemon(s *server.MCPServer, addr string) error {
	listener, displayAddr, err := buildDaemonListener(addr)
	if err != nil {
		return err
	}

	httpServer := server.NewStreamableHTTPServer(s)
	mux := http.NewServeMux()
	mux.Handle("/mcp", httpServer)
	mux.Handle("/mcp/", httpServer)

	srv := &http.Server{Handler: mux}

	audit.Record("daemon.start", map[string]any{
		"addr": displayAddr,
	})
	fmt.Fprintf(os.Stderr, "watchdog-mcp daemon: listening on %s\n", displayAddr)

	defer func() {
		audit.Record("daemon.stop", map[string]any{"addr": displayAddr})
	}()
	return srv.Serve(listener)
}

// buildDaemonListener parses addr and returns a net.Listener plus a
// human-readable display string for logs. The display string is the
// canonical scheme://path form, even for "auto".
func buildDaemonListener(addr string) (net.Listener, string, error) {
	if addr == "auto" {
		addr = "unix://" + filepath.Join(paths.WatchdogDir(), "mcp.sock")
	}
	if strings.HasPrefix(addr, "unix://") {
		sockPath := strings.TrimPrefix(addr, "unix://")
		if sockPath == "" {
			return nil, "", fmt.Errorf("unix:// scheme needs a socket path")
		}
		// Remove a leftover socket from a previous run; Listen would
		// otherwise fail with EADDRINUSE.
		_ = os.Remove(sockPath)
		if err := os.MkdirAll(filepath.Dir(sockPath), 0o755); err != nil {
			return nil, "", fmt.Errorf("mkdir for socket: %w", err)
		}
		l, err := net.Listen("unix", sockPath)
		if err != nil {
			return nil, "", fmt.Errorf("listen unix %s: %w", sockPath, err)
		}
		// Restrict to owner so other local users can't connect.
		if err := os.Chmod(sockPath, 0o600); err != nil {
			_ = l.Close()
			return nil, "", fmt.Errorf("chmod 0600 %s: %w", sockPath, err)
		}
		return l, "unix://" + sockPath, nil
	}

	if strings.HasPrefix(addr, "tcp://") {
		raw := strings.TrimPrefix(addr, "tcp://")
		u, err := url.Parse("tcp://" + raw)
		if err != nil || u.Host == "" {
			return nil, "", fmt.Errorf("tcp:// scheme needs host:port, got %q", addr)
		}
		host := u.Hostname()
		if !isLoopback(host) {
			return nil, "", fmt.Errorf("tcp:// must bind to a loopback host (127.0.0.1 / ::1 / localhost), got %q", host)
		}
		l, err := net.Listen("tcp", u.Host)
		if err != nil {
			return nil, "", fmt.Errorf("listen tcp %s: %w", u.Host, err)
		}
		return l, "tcp://" + u.Host, nil
	}

	return nil, "", fmt.Errorf("unsupported --listen scheme: %q (want auto, unix://, or tcp://)", addr)
}

// isLoopback reports whether host resolves to a loopback address.
// Accepts hostnames as well as literal IPs.
func isLoopback(host string) bool {
	switch strings.ToLower(host) {
	case "127.0.0.1", "::1", "localhost":
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
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
