"""SessionStart hook entry: scan installed Claude Code plugins.

Re-analyzes any plugin whose content hash has changed since the last
session (or that has never been scanned). Findings are injected as
`additionalContext` in the SessionStart hook response so the user sees
them at the top of the session.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from watchdog_core import discover_plugins, load_ledger, mascot, save_ledger, scan_plugins
from watchdog_core.policy import rank


def _emit_session_context(text: str) -> None:
    payload = {
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": text,
        }
    }
    json.dump(payload, sys.stdout)
    sys.stdout.write("\n")


def _format_summary(findings, skipped: int) -> str:
    lines = ["watchdog session scan — new or updated plugins detected:"]
    for name, v in findings:
        lines.append(
            f"  - {name}: {v.get('verdict','ask')} ({v.get('risk','?')}) — {(v.get('reason') or '')[:200]}"
        )
    if skipped:
        lines.append(
            f"  (+ {skipped} more pending; raise WATCHDOG_SESSION_MAX_SCANS to scan all)"
        )
    return "\n".join(lines)


def main() -> int:
    if os.environ.get("WATCHDOG_DISABLE", "").strip().lower() in {"1", "true", "yes", "on"}:
        return 0
    try:
        sys.stdin.read()
    except Exception:
        pass

    plugins = discover_plugins()
    if not plugins:
        return 0

    ledger = load_ledger()
    findings, dirty, skipped = scan_plugins(plugins, ledger)
    if dirty:
        save_ledger(ledger)
    if not findings:
        return 0

    summary = _format_summary(findings, skipped)
    worst = max(
        (v.get("verdict", "ask") for _, v in findings),
        key=rank,
    )
    event = {
        "deny": mascot.EVENT_PLUGIN_UNSAFE,
        "allow": mascot.EVENT_PLUGIN_SAFE,
    }.get(worst, mascot.EVENT_PLUGIN_INFO)
    mascot.show(
        event,
        ["Session scan complete.", *[f"{n}: {v.get('verdict','ask')}" for n, v in findings]],
    )
    _emit_session_context(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
