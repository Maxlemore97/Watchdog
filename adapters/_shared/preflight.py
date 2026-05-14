"""Aggregate OSV + LLM verdicts for a pre-parsed list of Packages.

Single source of truth for the preflight decision. Every adapter
(Claude Code PreToolUse, MCP, path_shim, github_action) collapses to a
call into `preflight_packages`.

Verdict precedence: `allow < ask < deny`, worst wins. In mode="both",
an OSV deny short-circuits the LLM pass. A `budget_secs` cap lets the
caller bail out cleanly with an `ask` instead of hanging the host.
"""
from __future__ import annotations

import time
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


def _pkg_dict(p: Package) -> dict[str, Any]:
    return {"ecosystem": p.ecosystem, "name": p.name, "version": p.version}


def preflight_packages(
    pkgs: Iterable[Package],
    notes: list[str] | None = None,
    mode: str = "both",
    offline_decision: str = "ask",
    budget_secs: float | None = None,
) -> dict[str, Any]:
    """Run OSV + LLM analysis on a list of already-parsed Packages.

    Returns a dict with keys: verdict, reason, mode, packages, findings,
    notes. Verdict ranks `allow < ask < deny` and the worst across
    packages wins. OSV `deny` short-circuits the LLM in mode="both".

    `offline_decision` is the verdict to emit when OSV or the analyzer
    raises (network down, claude CLI missing, etc.).

    `budget_secs`, if set, caps wall-clock spent in this function.
    When exceeded, remaining packages are skipped and the verdict is
    `ask` with a budget-exceeded reason.
    """
    if mode not in VALID_MODES:
        mode = "both"
    notes = list(notes or [])
    pkg_list = list(pkgs)

    deadline: float | None = (
        time.monotonic() + budget_secs if budget_secs is not None else None
    )

    def _over_budget() -> bool:
        return deadline is not None and time.monotonic() >= deadline

    base = {
        "mode": mode,
        "packages": [_pkg_dict(p) for p in pkg_list],
        "notes": notes,
    }

    if not pkg_list and not notes:
        return {
            **base,
            "verdict": "allow",
            "reason": "no install command detected",
            "findings": [],
        }
    if not pkg_list:
        return {
            **base,
            "verdict": "ask",
            "reason": "unsupported install form: " + "; ".join(notes),
            "findings": [],
        }

    findings: list[dict[str, Any]] = []
    decisions: list[tuple[str, str]] = []
    budget_hit = False
    processed_osv = 0
    processed_claude = 0

    if mode in {"osv", "both"}:
        for pkg in pkg_list:
            if _over_budget():
                budget_hit = True
                break
            processed_osv += 1
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
    if mode in {"claude", "both"} and not osv_denied and not budget_hit:
        for pkg in pkg_list:
            if _over_budget():
                budget_hit = True
                break
            processed_claude += 1
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

    if budget_hit:
        scanned = max(processed_claude, processed_osv)
        return {
            **base,
            "verdict": "ask",
            "reason": (
                f"scan budget exceeded after {scanned}/{len(pkg_list)} packages "
                f"(budget={budget_secs}s)"
            ),
            "findings": findings,
        }

    if not decisions:
        return {
            **base,
            "verdict": "allow",
            "reason": f"clean (mode={mode}, threshold={MIN_SEVERITY})",
            "findings": findings,
        }

    worst = worst_verdict(d[0] for d in decisions)
    relevant = [reason for d, reason in decisions if d == worst]
    reason = "; ".join(relevant[:5])
    if notes and worst == "allow":
        reason += f"; also: {'; '.join(notes)}"
    return {
        **base,
        "verdict": worst,
        "reason": reason,
        "findings": findings,
    }
