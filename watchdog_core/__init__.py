"""Watchdog core engine — platform-agnostic library.

Adapters in `adapters/` use this package to implement host-specific hooks:
- adapters/claude_code: Claude Code plugin (PreToolUse, UserPromptSubmit, SessionStart hooks)
- adapters/mcp_server: Model Context Protocol server, any MCP-aware agent
- adapters/path_shim: PATH-prepend wrapper for package-manager
  binaries; catches installs from agents that don't expose hooks
- adapters/github_action: PR-time scan of added/modified Claude
  plugin/skill/command/hook files for repos that ship them (narrow,
  not a generic dependency scanner)

Public API (re-exported at the package top level). Internal helpers
remain available via their submodules (`watchdog_core.osv`,
`watchdog_core.fetchers`, `watchdog_core.ledger`, ...).
"""
from .types import ArtifactBundle, Package
from .parsers import (
    classify_plugin_target,
    collect_packages,
    extract_plugin_targets,
    parse_install,
    parse_packages,
)
from .osv import (
    filter_by_severity,
    min_severity,
    query_osv,
    summarize,
)


def __getattr__(name: str):
    # Back-compat: `from watchdog_core import MIN_SEVERITY` keeps working
    # but now reads env each time so tests can override.
    if name == "MIN_SEVERITY":
        return min_severity()
    raise AttributeError(f"module 'watchdog_core' has no attribute {name!r}")
from .analyzer import (
    analyze_local_plugin,
    analyze_package,
)
from .ledger import (
    discover_plugins,
    load_ledger,
    save_ledger,
    scan_plugins,
)
from .policy import rank, worst_verdict
from . import mascot

__version__ = "0.3.0"

__all__ = [
    "ArtifactBundle",
    "Package",
    "classify_plugin_target",
    "collect_packages",
    "extract_plugin_targets",
    "parse_install",
    "parse_packages",
    "MIN_SEVERITY",
    "filter_by_severity",
    "min_severity",
    "query_osv",
    "summarize",
    "analyze_local_plugin",
    "analyze_package",
    "discover_plugins",
    "load_ledger",
    "save_ledger",
    "scan_plugins",
    "rank",
    "worst_verdict",
    "mascot",
    "__version__",
]
