"""PreToolUse hook entry: detect package-manager install commands on the
`Bash` tool and emit a permission decision.

Reads the hook JSON payload from stdin, dispatches to watchdog_core for
parsing / OSV lookup / Claude analysis, and writes the hook response on
stdout. Pass-through cases (not our concern: non-Bash tool, empty
command, no install detected) exit silently so other plugins' hook
decisions are not overridden.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
from pathlib import Path

# Ensure repo root is importable when invoked as a standalone script by
# the Claude Code hook shim.
_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from watchdog_core import (
    analyze_package,
    collect_packages,
    filter_by_severity,
    mascot,
    query_osv,
    summarize,
)
from watchdog_core.osv import MIN_SEVERITY

VALID_MODES = {"osv", "claude", "both"}
MODE = os.environ.get("WATCHDOG_MODE", "both").strip().lower()
if MODE not in VALID_MODES:
    MODE = "both"

OFFLINE_DECISION = os.environ.get("WATCHDOG_OFFLINE_DECISION", "ask").strip().lower()
if OFFLINE_DECISION not in {"allow", "deny", "ask"}:
    OFFLINE_DECISION = "ask"

WATCHDOG_DISABLE = os.environ.get("WATCHDOG_DISABLE", "0").strip().lower() in {"1", "true", "yes", "on"}


def emit(decision: str, reason: str) -> None:
    payload = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": f"watchdog: {reason}",
        }
    }
    json.dump(payload, sys.stdout)
    sys.stdout.write("\n")


def _run_osv(pkgs):
    findings = []
    for pkg in pkgs:
        try:
            vulns = query_osv(pkg)
        except (urllib.error.URLError, TimeoutError) as exc:
            return (OFFLINE_DECISION, f"OSV unreachable ({exc})")
        if vulns:
            filtered = filter_by_severity(vulns)
            if filtered:
                findings.append((pkg, filtered))
    if not findings:
        return None
    parts = [
        f"{pkg.ecosystem}:{pkg.name}{('@' + pkg.version) if pkg.version else ''} -> {summarize(vulns)}"
        for pkg, vulns in findings
    ]
    return ("deny", f"vulnerable packages (>= {MIN_SEVERITY}): " + "; ".join(parts))


def _run_claude(pkgs):
    worst = None
    rank = {"allow": 0, "ask": 1, "deny": 2}
    for pkg in pkgs:
        try:
            verdict = analyze_package(pkg.ecosystem, pkg.name, pkg.version)
        except Exception as exc:
            return (OFFLINE_DECISION, f"claude analyzer error: {exc}")
        if verdict is None:
            continue
        decision = verdict.get("verdict", "ask")
        reason = verdict.get("reason", "no reason")
        label = f"{pkg.ecosystem}:{pkg.name}{('@' + pkg.version) if pkg.version else ''}"
        candidate = (decision, f"[claude] {label}: {reason}")
        if worst is None or rank.get(decision, 1) > rank.get(worst[0], 1):
            worst = candidate
    return worst


def main() -> int:
    if WATCHDOG_DISABLE:
        return 0
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        return 0
    if payload.get("tool_name") != "Bash":
        return 0
    command = (payload.get("tool_input") or {}).get("command", "")
    if not command:
        return 0

    pkgs, notes = collect_packages(command)
    if not pkgs and not notes:
        return 0

    if not pkgs and notes:
        reason = "unsupported install form, cannot analyze: " + "; ".join(notes)
        mascot.show(mascot.EVENT_PLUGIN_INFO, ["Install-Befehl abgefangen.", *notes])
        emit("ask", reason)
        return 0

    pkg_labels = [
        f"{p.ecosystem}:{p.name}{('@' + p.version) if p.version else ''}" for p in pkgs
    ]
    mascot.show(
        mascot.EVENT_INTERCEPT,
        ["Install-Befehl abgefangen.", f"Mode: {MODE}, Schwelle: {MIN_SEVERITY}", *pkg_labels, *notes],
    )
    mascot.show(mascot.EVENT_PLUGIN_INFO, pkg_labels)

    osv_result = None
    if MODE in {"osv", "both"}:
        osv_result = _run_osv(pkgs)
        if osv_result and osv_result[0] == "deny":
            mascot.show(mascot.EVENT_PLUGIN_UNSAFE, [osv_result[1]])
            emit(*osv_result)
            return 0

    if MODE in {"claude", "both"}:
        claude_result = _run_claude(pkgs)
        if claude_result is not None:
            event = (
                mascot.EVENT_PLUGIN_UNSAFE
                if claude_result[0] == "deny"
                else mascot.EVENT_PLUGIN_SAFE
                if claude_result[0] == "allow"
                else mascot.EVENT_PLUGIN_INFO
            )
            mascot.show(event, [claude_result[1]])
            emit(*claude_result)
            return 0

    if osv_result is not None:
        mascot.show(mascot.EVENT_PLUGIN_INFO, [osv_result[1]])
        emit(*osv_result)
        return 0

    if notes:
        reason = (
            f"resolved packages clean (mode={MODE}, threshold={MIN_SEVERITY}); "
            f"but also: {'; '.join(notes)}"
        )
        mascot.show(mascot.EVENT_PLUGIN_INFO, [reason, *pkg_labels])
        emit("ask", reason)
        return 0

    mascot.show(
        mascot.EVENT_PLUGIN_SAFE,
        [f"clean (mode={MODE}, threshold={MIN_SEVERITY})", *pkg_labels],
    )
    emit("allow", f"clean (mode={MODE}, threshold={MIN_SEVERITY})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
