"""PreToolUse hook entry: detect package-manager install commands on the
`Bash` tool and emit a permission decision.

Reads the hook JSON payload from stdin, dispatches to
`adapters._shared.preflight.preflight_packages` for parsing / OSV
lookup / Claude analysis, and writes the hook response on stdout.
Pass-through cases (not our concern: non-Bash tool, empty command,
no install detected) exit silently so other plugins' hook decisions
are not overridden.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from adapters._shared.preflight import preflight_packages
from watchdog_core import collect_packages, mascot
from watchdog_core.osv import MIN_SEVERITY

VALID_MODES = {"osv", "claude", "both"}
VALID_DECISIONS = {"allow", "deny", "ask"}


def _mode() -> str:
    val = os.environ.get("WATCHDOG_MODE", "both").strip().lower()
    return val if val in VALID_MODES else "both"


def _offline_decision() -> str:
    val = os.environ.get("WATCHDOG_OFFLINE_DECISION", "ask").strip().lower()
    return val if val in VALID_DECISIONS else "ask"


def _disabled() -> bool:
    return os.environ.get("WATCHDOG_DISABLE", "0").strip().lower() in {"1", "true", "yes", "on"}


def _hook_budget_secs() -> float:
    try:
        return float(os.environ.get("WATCHDOG_HOOK_BUDGET_SECS", "30"))
    except ValueError:
        return 30.0


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


def _event_for(verdict: str) -> str:
    if verdict == "deny":
        return mascot.EVENT_PLUGIN_UNSAFE
    if verdict == "allow":
        return mascot.EVENT_PLUGIN_SAFE
    return mascot.EVENT_PLUGIN_INFO


def main() -> int:
    if _disabled():
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

    mode = _mode()
    pkg_labels = [
        f"{p.ecosystem}:{p.name}{('@' + p.version) if p.version else ''}" for p in pkgs
    ]
    mascot.show(
        mascot.EVENT_INTERCEPT,
        ["Install command intercepted.", f"Mode: {mode}, threshold: {MIN_SEVERITY}", *pkg_labels, *notes],
    )
    if pkg_labels:
        mascot.show(mascot.EVENT_PLUGIN_INFO, pkg_labels)

    result = preflight_packages(
        pkgs,
        notes,
        mode=mode,
        offline_decision=_offline_decision(),
        budget_secs=_hook_budget_secs(),
    )

    verdict = result["verdict"]
    reason = result["reason"]
    mascot.show(_event_for(verdict), [f"{verdict}: {reason}"])
    emit(verdict, reason)
    return 0


if __name__ == "__main__":
    sys.exit(main())
