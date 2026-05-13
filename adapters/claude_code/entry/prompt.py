"""UserPromptSubmit hook entry: intercept `/plugin install <target>` and
`/plugin marketplace add <git-url>` patterns, run Claude security
analysis on the target, and either block, ask, or inject context.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from watchdog_core import (
    analyze_package,
    classify_plugin_target,
    extract_plugin_targets,
    mascot,
)


def _emit(decision: str | None, additional_context: str | None) -> None:
    payload: dict = {}
    if decision:
        payload["decision"] = decision
        if additional_context:
            payload["reason"] = additional_context
    elif additional_context:
        payload["hookSpecificOutput"] = {
            "hookEventName": "UserPromptSubmit",
            "additionalContext": additional_context,
        }
    if payload:
        json.dump(payload, sys.stdout)
        sys.stdout.write("\n")


def main() -> int:
    if os.environ.get("WATCHDOG_DISABLE", "").lower() in {"1", "true", "yes"}:
        return 0
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        return 0

    prompt = (payload.get("prompt") or "").strip()
    if not prompt:
        return 0

    targets = extract_plugin_targets(prompt)
    if not targets:
        return 0

    mascot.show(mascot.EVENT_INTERCEPT, ["/plugin install abgefangen.", *targets])

    verdicts: list[tuple[str, dict]] = []
    for tgt in targets:
        ecosystem, name, version = classify_plugin_target(tgt)
        mascot.show(
            mascot.EVENT_PLUGIN_INFO,
            [f"target: {tgt}", f"name: {name}", f"version: {version or 'unknown'}"],
        )
        result = analyze_package(ecosystem, name, version)
        if result:
            verdicts.append((tgt, result))

    if not verdicts:
        mascot.show(mascot.EVENT_PLUGIN_INFO, ["Analyzer nicht verfuegbar."])
        _emit(None, "watchdog: plugin install detected but analyzer unavailable.")
        return 0

    worst = max(
        verdicts,
        key=lambda kv: {"allow": 0, "ask": 1, "deny": 2}.get(kv[1].get("verdict", "ask"), 1),
    )
    target, verdict = worst
    decision = verdict.get("verdict", "ask")
    reason = verdict.get("reason", "no reason")
    summary = f"watchdog plugin scan: {target} -> {decision} ({verdict.get('risk', '?')}): {reason}"

    event = {
        "deny": mascot.EVENT_PLUGIN_UNSAFE,
        "allow": mascot.EVENT_PLUGIN_SAFE,
    }.get(decision, mascot.EVENT_PLUGIN_INFO)
    mascot.show(event, [target, f"verdict: {decision} ({verdict.get('risk', '?')})", reason])

    if decision == "deny":
        _emit("block", summary)
    elif decision == "ask":
        _emit(None, summary + "  [proceed only if you trust this source]")
    else:
        _emit(None, summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
