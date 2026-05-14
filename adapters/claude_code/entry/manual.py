"""Manual scan entry used by the /watchdog-scan slash command.

Usage:
    python3 manual.py <target>

Where <target> is one of:
  - <name>           (try as npm then PyPI then plugin git URL)
  - <name>@<version>
  - <git-url>        (treated as a Claude plugin source)
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from watchdog_core import analyze_package, mascot
from watchdog_core.policy import rank

GIT_URL = re.compile(r"^(https?://|git@|ssh://).+")


def main() -> int:
    if len(sys.argv) < 2:
        print(json.dumps({"verdict": "ask", "reason": "no target supplied"}))
        return 0
    target = sys.argv[1].strip()

    mascot.show(mascot.EVENT_INTERCEPT, ["Manual scan started.", f"target: {target}"])

    if GIT_URL.match(target) or target.endswith(".git"):
        ecosystems = [("plugin", target, None)]
    elif "/" in target and target.startswith(("http", "git@", "ssh")):
        ecosystems = [("plugin", target, None)]
    else:
        if "@" in target and not target.startswith("@"):
            name, _, version = target.partition("@")
            version = version or None
        else:
            name, version = target, None
        ecosystems = [
            ("npm", name, version),
            ("PyPI", name, version),
        ]

    results = []
    for eco, name, version in ecosystems:
        mascot.show(
            mascot.EVENT_PLUGIN_INFO,
            [f"ecosystem: {eco}", f"name: {name}", f"version: {version or 'unknown'}"],
        )
        verdict = analyze_package(eco, name, version)
        if verdict:
            results.append({"ecosystem": eco, "name": name, "version": version, **verdict})

    worst = max(results, key=lambda r: rank(r.get("verdict", "ask")), default=None)
    if worst is not None:
        decision = worst.get("verdict", "ask")
        event = {
            "deny": mascot.EVENT_PLUGIN_UNSAFE,
            "allow": mascot.EVENT_PLUGIN_SAFE,
        }.get(decision, mascot.EVENT_PLUGIN_INFO)
        mascot.show(
            event,
            [
                f"{worst.get('ecosystem')}:{worst.get('name')}"
                f"{('@' + worst['version']) if worst.get('version') else ''}",
                f"verdict: {decision} ({worst.get('risk', '?')})",
                worst.get("reason", ""),
            ],
        )

    print(json.dumps({"target": target, "results": results}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
