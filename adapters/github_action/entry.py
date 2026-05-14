"""`watchdog-action` — entry point for the GitHub Action.

Workflow:
1. Compute the list of changed files between the PR base and HEAD via
   `git diff --name-only --diff-filter=AMR`.
2. Filter to files that belong to Claude plugin assets (.claude-plugin,
   skills, commands, hooks) per the per-directory rules.
3. Group changed files by plugin root (the directory containing the
   asset subdirectory).
4. Run `analyze_local_plugin` on each plugin root.
5. Emit workflow annotations and exit non-zero if any verdict is
   at or above `WATCHDOG_ACTION_FAIL_ON` (default `deny`).

Configuration (via env, normally set by `action.yml`):
- `WATCHDOG_BASE_REF`     base ref for the diff (default `$GITHUB_BASE_REF` or `main`)
- `WATCHDOG_HEAD_REF`     head ref for the diff (default `HEAD`)
- `WATCHDOG_WORKSPACE`    repo checkout dir (default `$GITHUB_WORKSPACE` or cwd)
- `WATCHDOG_ACTION_FAIL_ON`   `deny` | `ask` | `never` (default `deny`)
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

# Repo root importable when invoked outside an installed wheel.
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from adapters.github_action import PLUGIN_ASSET_DIRS, annotations
from watchdog_core import analyze_local_plugin
from watchdog_core.policy import rank, worst_verdict

VALID_FAIL_ON = {"deny", "ask", "never"}


def _workspace() -> Path:
    return Path(
        os.environ.get("WATCHDOG_WORKSPACE")
        or os.environ.get("GITHUB_WORKSPACE")
        or os.getcwd()
    )


def _base_ref() -> str:
    return (
        os.environ.get("WATCHDOG_BASE_REF")
        or os.environ.get("GITHUB_BASE_REF")
        or "main"
    )


def _head_ref() -> str:
    return os.environ.get("WATCHDOG_HEAD_REF", "HEAD")


def _fail_on() -> str:
    val = os.environ.get("WATCHDOG_ACTION_FAIL_ON", "deny").strip().lower()
    return val if val in VALID_FAIL_ON else "deny"


def changed_files(base: str, head: str, workspace: Path) -> list[str]:
    """Return paths (relative to workspace) of files added, modified,
    or renamed between `base` and `head`. Empty list if git fails."""
    try:
        out = subprocess.check_output(
            [
                "git",
                "diff",
                "--name-only",
                "--diff-filter=AMR",
                f"origin/{base}...{head}",
            ],
            cwd=str(workspace),
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        # Fall back to non-origin base (e.g. local invocations).
        try:
            out = subprocess.check_output(
                [
                    "git",
                    "diff",
                    "--name-only",
                    "--diff-filter=AMR",
                    f"{base}...{head}",
                ],
                cwd=str(workspace),
                stderr=subprocess.DEVNULL,
                text=True,
            )
        except (subprocess.CalledProcessError, FileNotFoundError):
            return []
    return [line for line in out.splitlines() if line.strip()]


def is_plugin_asset(path: str) -> bool:
    """Per-directory rules from the spec:
    - **/.claude-plugin/**     anything
    - **/skills/**/SKILL.md    only SKILL.md
    - **/commands/**.md        only .md files
    - **/hooks/**              anything
    """
    parts = Path(path).parts
    for i, segment in enumerate(parts):
        rest = parts[i + 1 :]
        if segment == ".claude-plugin" and rest:
            return True
        if segment == "hooks" and rest:
            return True
        if segment == "commands" and rest:
            return path.endswith(".md")
        if segment == "skills" and rest:
            return Path(path).name == "SKILL.md"
    return False


def plugin_root_for(path: str) -> str:
    """Return the directory above the first plugin-asset segment.
    Empty string means the asset lives at the repo root.
    """
    parts = Path(path).parts
    for i, segment in enumerate(parts):
        if segment in PLUGIN_ASSET_DIRS:
            return str(Path(*parts[:i])) if i > 0 else ""
    return ""


def group_by_plugin(paths: list[str]) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = {}
    for p in paths:
        if not is_plugin_asset(p):
            continue
        root = plugin_root_for(p)
        grouped.setdefault(root, []).append(p)
    return grouped


def _plugin_name(root: str) -> str:
    if root:
        return Path(root).name or root
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    return repo.split("/")[-1] if repo else "repo-root-plugin"


def _verdict_emitter(verdict: str):
    if verdict == "deny":
        return annotations.error
    if verdict == "ask":
        return annotations.warning
    return annotations.notice


def run(
    base: str | None = None,
    head: str | None = None,
    workspace: Path | None = None,
    fail_on: str | None = None,
) -> int:
    base = base or _base_ref()
    head = head or _head_ref()
    workspace = workspace or _workspace()
    fail_on = fail_on or _fail_on()

    files = changed_files(base, head, workspace)
    grouped = group_by_plugin(files)

    if not grouped:
        annotations.notice("No Claude plugin assets changed; skipping.")
        return 0

    verdicts: list[str] = []
    for root, touched in sorted(grouped.items()):
        full_path = workspace / root if root else workspace
        name = _plugin_name(root)
        result = analyze_local_plugin(name, str(full_path))
        if result is None:
            annotations.warning(
                f"watchdog: analyzer returned no result for {name}",
                file=touched[0],
                title="Watchdog",
            )
            verdicts.append("ask")
            continue
        verdict = result.get("verdict", "ask")
        reason = result.get("reason", "no reason")
        emit = _verdict_emitter(verdict)
        for f in touched:
            emit(
                f"watchdog [{verdict}] {name}: {reason}",
                file=f,
                title=f"Watchdog: {verdict}",
            )
        verdicts.append(verdict)

    if not verdicts:
        return 0
    worst = worst_verdict(verdicts)

    if fail_on == "never":
        return 0
    threshold = rank(fail_on)
    return 1 if rank(worst) >= threshold else 0


def main(argv: list[str] | None = None) -> int:
    return run()


if __name__ == "__main__":
    sys.exit(main())
