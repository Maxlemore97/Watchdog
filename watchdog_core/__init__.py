"""Watchdog core engine — platform-agnostic library.

Adapters in `adapters/` use this package to implement host-specific hooks:
- adapters/claude_code: Claude Code plugin (PreToolUse, UserPromptSubmit, SessionStart hooks)
- adapters/mcp_server: Model Context Protocol server, any MCP-aware agent
- adapters/path_shim: PATH-prepend wrapper for package-manager
  binaries; catches installs from agents that don't expose hooks
- adapters/github_action: PR-time scan of added/modified Claude
  plugin/skill/command/hook files for repos that ship them (narrow,
  not a generic dependency scanner)

Public API:
- parse_install / parse_packages / collect_packages: install-command parser
- classify_plugin_target / extract_plugin_targets: /plugin install prompt parser
- query_osv / resolve_version / filter_by_severity: OSV.dev client
- fetch / fetch_plugin_local / fetch_plugin_git: artifact fetchers
- analyze_package / analyze_local_plugin: LLM-driven source review
- discover_plugins / scan_plugins / content_hash / load_ledger / save_ledger: plugin ledger
- worst_verdict / VERDICT_RANK: verdict aggregation
- mascot: ASCII police-dog UI
"""
from .types import ArtifactBundle, Package
from .parsers import (
    PLUGIN_PROMPT_PATTERNS,
    GIT_URL_PATTERN,
    classify_plugin_target,
    collect_packages,
    extract_plugin_targets,
    parse_install,
    parse_packages,
    split_name_version,
)
from .osv import (
    MIN_SEVERITY,
    MIN_SEVERITY_RANK,
    SEVERITY_RANK,
    fetch_latest_version,
    filter_by_severity,
    query_osv,
    resolve_version,
    severity_label,
    severity_rank,
    summarize,
)
from .fetchers import (
    fetch,
    fetch_crates,
    fetch_npm,
    fetch_packagist,
    fetch_plugin_git,
    fetch_plugin_local,
    fetch_pypi,
    fetch_rubygems,
)
from .analyzer import (
    SYSTEM_PROMPT,
    analyze_local_plugin,
    analyze_package,
)
from .ledger import (
    LEDGER_PATH,
    LEDGER_VERSION,
    content_hash,
    discover_plugins,
    load_ledger,
    read_manifest,
    save_ledger,
    scan_plugins,
)
from .policy import VERDICT_RANK, rank, worst_verdict
from . import mascot

__version__ = "0.3.0"

__all__ = [
    "ArtifactBundle",
    "Package",
    "PLUGIN_PROMPT_PATTERNS",
    "GIT_URL_PATTERN",
    "classify_plugin_target",
    "collect_packages",
    "extract_plugin_targets",
    "parse_install",
    "parse_packages",
    "split_name_version",
    "MIN_SEVERITY",
    "MIN_SEVERITY_RANK",
    "SEVERITY_RANK",
    "fetch_latest_version",
    "filter_by_severity",
    "query_osv",
    "resolve_version",
    "severity_label",
    "severity_rank",
    "summarize",
    "fetch",
    "fetch_crates",
    "fetch_npm",
    "fetch_packagist",
    "fetch_plugin_git",
    "fetch_plugin_local",
    "fetch_pypi",
    "fetch_rubygems",
    "SYSTEM_PROMPT",
    "analyze_local_plugin",
    "analyze_package",
    "LEDGER_PATH",
    "LEDGER_VERSION",
    "content_hash",
    "discover_plugins",
    "load_ledger",
    "read_manifest",
    "save_ledger",
    "scan_plugins",
    "VERDICT_RANK",
    "rank",
    "worst_verdict",
    "mascot",
    "__version__",
]
