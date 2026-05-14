"""MCP server adapter for Watchdog.

Exposes the engine as Model Context Protocol tools so any MCP-aware client
(Claude Code, Cursor, Continue, etc.) can call Watchdog without
host-specific glue. Runs as a local stdio subprocess; no network listener,
no daemon, no shared service.

Each tool is a thin wrapper around a pure-Python function in this module.
The pure functions are unit-testable without the `mcp` SDK installed; the
SDK is only loaded inside `_build_app()` when the server actually runs.

Install:
    pip install watchdog-scanner[mcp]

Configure (Claude Code / Cursor / Continue MCP settings):
    {
      "mcpServers": {
        "watchdog": {
          "command": "watchdog-mcp"
        }
      }
    }
"""
from __future__ import annotations

import sys
from typing import Any

from adapters._shared.preflight import preflight_packages
from watchdog_core import (
    analyze_local_plugin,
    analyze_package,
    classify_plugin_target,
    collect_packages,
    filter_by_severity,
    load_ledger,
    query_osv,
)
from watchdog_core.osv import min_severity
from watchdog_core.types import Package


# ---------- pure-Python tool implementations ------------------------------

def preflight_install(command: str, mode: str = "both") -> dict[str, Any]:
    """Pre-flight check for a package-manager install command.

    Parses the command (npm/pnpm/yarn, pip/pip3/uv/poetry, cargo, gem,
    composer; chained via `&&`/`;`/`||`; nested in `bash -c "..."`),
    runs OSV CVE lookups, and (in mode "claude" or "both") invokes the
    Claude analyzer for LLM source review.

    Returns:
        {
          "verdict": "allow" | "ask" | "deny",
          "reason": "<short summary>",
          "mode": <mode used>,
          "packages": [{"ecosystem","name","version"}, ...],
          "notes": [<unsupported install forms>, ...],
          "findings": [<per-package detail>, ...]
        }
    """
    pkgs, notes = collect_packages(command)
    return preflight_packages(pkgs, notes, mode=mode, offline_decision="ask")


def scan_package(ecosystem: str, name: str, version: str | None = None) -> dict[str, Any]:
    """Run the LLM analyzer on one published package.

    Ecosystem must be one of: npm, PyPI, crates.io, RubyGems, Packagist.
    """
    verdict = analyze_package(ecosystem, name, version)
    return verdict or {"verdict": "ask", "reason": "no result"}


def audit_plugin(target: str) -> dict[str, Any]:
    """Audit a Claude Code plugin target (git URL, plugin name, or
    name@version). Targets are classified, fetched, and reviewed by the
    LLM analyzer.
    """
    ecosystem, name, version = classify_plugin_target(target)
    verdict = analyze_package(ecosystem, name, version)
    return verdict or {"verdict": "ask", "reason": "no result"}


def audit_plugin_local(name: str, path: str) -> dict[str, Any]:
    """Audit a plugin directory already on disk (no clone, no network)."""
    verdict = analyze_local_plugin(name, path)
    return verdict or {"verdict": "ask", "reason": "no result"}


def list_vetted_plugins() -> dict[str, Any]:
    """Return the persistent vetted-plugins ledger contents.

    The ledger is maintained by the SessionStart hook of the Claude Code
    adapter; reading it here lets non-Claude-Code agents see the same
    audit history.
    """
    return load_ledger()


def osv_query(ecosystem: str, name: str, version: str | None = None) -> dict[str, Any]:
    """Raw OSV.dev vulnerability query (no LLM, no caching of verdict).

    Returns all advisories from OSV plus a filtered list with only those
    at or above `WATCHDOG_MIN_SEVERITY`.
    """
    pkg = Package(ecosystem=ecosystem, name=name, version=version)
    try:
        vulns = query_osv(pkg)
    except Exception as exc:
        return {"error": str(exc), "vulns": [], "filtered": []}
    return {
        "vulns": vulns,
        "filtered": filter_by_severity(vulns),
        "threshold": min_severity(),
    }


# ---------- MCP wrapper ---------------------------------------------------

def _build_app():
    """Construct the FastMCP application. Imported lazily so the `mcp`
    SDK is only required when actually running the server."""
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:
        raise SystemExit(
            "watchdog-mcp: the 'mcp' package is not installed. "
            "Install with: pip install watchdog-scanner[mcp]"
        ) from exc

    app = FastMCP("watchdog")

    @app.tool()
    def watchdog_preflight_install(command: str, mode: str = "both") -> dict[str, Any]:
        """Pre-flight a package-manager install command.

        Detects npm/pip/cargo/gem/composer installs in the command
        string, runs OSV CVE lookups, optionally invokes the LLM
        analyzer, and returns an aggregated verdict: allow, ask, or
        deny.

        Use BEFORE the host runs the install. Treat "deny" as a hard
        stop; "ask" means human review required; "allow" means clean.
        """
        return preflight_install(command, mode=mode)

    @app.tool()
    def watchdog_scan_package(
        ecosystem: str,
        name: str,
        version: str | None = None,
    ) -> dict[str, Any]:
        """LLM source review of one published package."""
        return scan_package(ecosystem, name, version)

    @app.tool()
    def watchdog_audit_plugin(target: str) -> dict[str, Any]:
        """Audit a Claude Code plugin (git URL, name, or name@version)."""
        return audit_plugin(target)

    @app.tool()
    def watchdog_audit_plugin_local(name: str, path: str) -> dict[str, Any]:
        """Audit an already-installed plugin directory."""
        return audit_plugin_local(name, path)

    @app.tool()
    def watchdog_list_vetted_plugins() -> dict[str, Any]:
        """Return the persistent vetted-plugins ledger contents."""
        return list_vetted_plugins()

    @app.tool()
    def watchdog_osv_query(
        ecosystem: str,
        name: str,
        version: str | None = None,
    ) -> dict[str, Any]:
        """Raw OSV.dev vulnerability query for diagnostics."""
        return osv_query(ecosystem, name, version)

    return app


def main() -> int:
    app = _build_app()
    app.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
