"""Per-call shim entry: invoked as `watchdog-shim-exec <toolname> <args...>`.

Each installed wrapper executable in `~/.watchdog/bin/<toolname>` runs:

    exec watchdog-shim-exec <toolname> "$@"

This module:
1. Reconstructs the original install command string.
2. Asks `watchdog_core` to parse it.
3. If no install is detected -> exec the real binary immediately
   (cheap pass-through for `npm test`, `pip --version`, ...).
4. Otherwise runs the shared preflight (OSV + optional LLM) and either
   execs the real binary (allow), exits 1 (deny), or interactively
   prompts on a TTY (ask). Falls back to `WATCHDOG_OFFLINE_DECISION`
   when not on a TTY; default is `deny` for the shim because, unlike
   the Claude Code hook, there is no host UI to surface the question.
"""
from __future__ import annotations

import os
import shlex
import sys
from pathlib import Path

# Ensure repo root is importable when invoked outside an installed wheel.
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from adapters._shared.preflight import preflight_packages
from adapters.path_shim import SHIMMED_TOOLS
from adapters.path_shim.resolver import find_real_binary
from watchdog_core import collect_packages, mascot

SHIM_DIR_ENV = "WATCHDOG_SHIM_DIR"
DEFAULT_SHIM_DIR = Path.home() / ".watchdog" / "bin"
DISABLE_ENV = "WATCHDOG_DISABLE"

VALID_OFFLINE = {"allow", "deny", "ask"}


def _shim_dir() -> Path:
    return Path(os.environ.get(SHIM_DIR_ENV, str(DEFAULT_SHIM_DIR)))


def _disabled() -> bool:
    return os.environ.get(DISABLE_ENV, "0").strip().lower() in {"1", "true", "yes", "on"}


def _offline_decision() -> str:
    val = os.environ.get("WATCHDOG_OFFLINE_DECISION", "deny").strip().lower()
    return val if val in VALID_OFFLINE else "deny"


def _mode() -> str:
    val = os.environ.get("WATCHDOG_MODE", "both").strip().lower()
    return val if val in {"osv", "claude", "both"} else "both"


def _exec_real(real: str, toolname: str, args: list[str]) -> int:
    """Replace this process with the real binary. Returns nonzero only
    if execv itself fails."""
    try:
        os.execv(real, [toolname, *args])
    except OSError as exc:
        sys.stderr.write(f"watchdog-shim: failed to exec {real}: {exc}\n")
        return 127
    return 0  # unreachable


def _confirm_tty(reason: str) -> bool:
    """Interactive [y/N] prompt. Returns True if user accepts."""
    sys.stderr.write(f"watchdog: {reason}\n")
    sys.stderr.write("Proceed with install? [y/N]: ")
    sys.stderr.flush()
    try:
        answer = sys.stdin.readline().strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return answer in {"y", "yes"}


def _resolve_decision(verdict: str, reason: str) -> bool:
    """Translate verdict into proceed/deny. `ask` consults a TTY or the
    offline policy. Returns True to allow exec of the real binary."""
    if verdict == "allow":
        return True
    if verdict == "deny":
        mascot.show(mascot.EVENT_PLUGIN_UNSAFE, [reason])
        sys.stderr.write(f"watchdog: blocked install. {reason}\n")
        return False
    # ask
    if sys.stdin.isatty() and sys.stderr.isatty():
        return _confirm_tty(reason)
    fallback = _offline_decision()
    sys.stderr.write(f"watchdog: {reason} (no TTY, falling back to {fallback})\n")
    if fallback == "allow":
        return True
    return False


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv if argv is None else argv)
    if len(argv) < 2:
        sys.stderr.write("watchdog-shim-exec: missing tool name\n")
        return 2

    toolname = os.path.basename(argv[1])
    tool_args = argv[2:]

    real = find_real_binary(toolname, [str(_shim_dir())])
    if real is None:
        sys.stderr.write(
            f"watchdog-shim-exec: real binary {toolname!r} not found on PATH "
            f"(after excluding shim dir {_shim_dir()})\n"
        )
        return 127

    if _disabled():
        return _exec_real(real, toolname, tool_args)

    if toolname not in SHIMMED_TOOLS:
        return _exec_real(real, toolname, tool_args)

    cmd = shlex.join([toolname, *tool_args])
    pkgs, notes = collect_packages(cmd)

    if not pkgs and not notes:
        return _exec_real(real, toolname, tool_args)

    mascot.show(
        mascot.EVENT_INTERCEPT,
        [f"shim: {toolname}", f"mode: {_mode()}"]
        + [f"{p.ecosystem}:{p.name}{('@' + p.version) if p.version else ''}" for p in pkgs]
        + notes,
    )

    result = preflight_packages(
        pkgs,
        notes,
        mode=_mode(),
        offline_decision=_offline_decision(),
    )

    if _resolve_decision(result["verdict"], result["reason"]):
        return _exec_real(real, toolname, tool_args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
