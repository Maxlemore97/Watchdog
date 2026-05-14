"""Aggregate OSV + LLM verdicts for a pre-parsed list of Packages.

This is the adapter-agnostic core of the preflight decision: callers
that have already parsed an install command (path_shim, github_action,
future adapters) hand in `Package` objects and get back a single
(verdict, reason, findings) triple.

The Claude Code and MCP adapters predate this helper and inline the
same logic; they may migrate later but are not required to. Behaviour
here mirrors `adapters.mcp_server.server.preflight_install` so adapters
agree on aggregation rules.
"""
from __future__ import annotations

from typing import Any, Iterable

from watchdog_core import (
    analyze_package,
    filter_by_severity,
    query_osv,
    summarize,
    worst_verdict,
)
from watchdog_core.osv import MIN_SEVERITY
from watchdog_core.types import Package

VALID_MODES = {"osv", "claude", "both"}


def _pkg_label(p: Package) -> str:
    return f"{p.ecosystem}:{p.name}{('@' + p.version) if p.version else ''}"


def preflight_packages(
    pkgs: Iterable[Package],
    notes: list[str] | None = None,
    mode: str = "both",
    offline_decision: str = "ask",
) -> dict[str, Any]:
    """Run OSV + LLM analysis on a list of already-parsed Packages.

    Returns a dict with keys: verdict, reason, mode, findings, notes.
    Verdict ranks `allow < ask < deny` and the worst across packages
    wins. OSV `deny` short-circuits the LLM in mode="both".

    `offline_decision` is the verdict to emit when OSV or the analyzer
    raises (network down, claude CLI missing, etc.).
    """
    if mode not in VALID_MODES:
        mode = "both"
    notes = list(notes or [])
    pkg_list = list(pkgs)

    if not pkg_list and not notes:
        return {
            "verdict": "allow",
            "reason": "no install command detected",
            "mode": mode,
            "findings": [],
            "notes": [],
        }
    if not pkg_list:
        return {
            "verdict": "ask",
            "reason": "unsupported install form: " + "; ".join(notes),
            "mode": mode,
            "findings": [],
            "notes": notes,
        }

    findings: list[dict[str, Any]] = []
    decisions: list[tuple[str, str]] = []

    if mode in {"osv", "both"}:
        for pkg in pkg_list:
            try:
                vulns = query_osv(pkg)
            except Exception as exc:
                decisions.append((offline_decision, f"OSV unreachable for {_pkg_label(pkg)}: {exc}"))
                continue
            if not vulns:
                continue
            filtered = filter_by_severity(vulns)
            if filtered:
                decisions.append(("deny", f"{_pkg_label(pkg)} -> {summarize(filtered)}"))
                findings.append({
                    "package": _pkg_label(pkg),
                    "source": "osv",
                    "vulns": [v.get("id", "?") for v in filtered],
                    "severity_threshold": MIN_SEVERITY,
                })

    osv_denied = any(d[0] == "deny" for d in decisions)
    if mode in {"claude", "both"} and not osv_denied:
        for pkg in pkg_list:
            try:
                verdict = analyze_package(pkg.ecosystem, pkg.name, pkg.version)
            except Exception as exc:
                decisions.append((offline_decision, f"analyzer error for {_pkg_label(pkg)}: {exc}"))
                continue
            if verdict is None:
                continue
            d = verdict.get("verdict", "ask")
            decisions.append((d, f"[claude] {_pkg_label(pkg)}: {verdict.get('reason', '')}"))
            findings.append({"package": _pkg_label(pkg), "source": "claude", **verdict})

    if not decisions:
        return {
            "verdict": "allow",
            "reason": f"clean (mode={mode}, threshold={MIN_SEVERITY})",
            "mode": mode,
            "findings": findings,
            "notes": notes,
        }

    worst = worst_verdict(d[0] for d in decisions)
    relevant = [reason for d, reason in decisions if d == worst]
    reason = "; ".join(relevant[:5])
    if notes and worst == "allow":
        reason += f"; also: {'; '.join(notes)}"
    return {
        "verdict": worst,
        "reason": reason,
        "mode": mode,
        "findings": findings,
        "notes": notes,
    }
