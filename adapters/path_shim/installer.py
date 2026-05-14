"""Install / uninstall the per-tool shim wrappers.

Each shim is a tiny POSIX shell script:

    #!/usr/bin/env bash
    exec "${WATCHDOG_PYTHON:-python3}" -m adapters.path_shim.shim "<tool>" "$@"

Bash is required because `os.execv` semantics in the underlying shim
depend on argv[0] being the tool name. Windows is out of scope for
the v1 path_shim adapter.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

from . import SHIMMED_TOOLS

DEFAULT_SHIM_DIR = Path.home() / ".watchdog" / "bin"

WRAPPER_TEMPLATE = """#!/usr/bin/env bash
# Watchdog shim for {tool}. Do not edit by hand; regenerate via
# `watchdog-shim install`.
exec "${{WATCHDOG_PYTHON:-python3}}" -m adapters.path_shim.shim "{tool}" "$@"
"""


def _shim_dir(custom: str | os.PathLike | None) -> Path:
    return Path(custom) if custom else DEFAULT_SHIM_DIR


def install_shims(
    tools: list[str] | None = None,
    shim_dir: str | os.PathLike | None = None,
    overwrite: bool = True,
) -> list[Path]:
    """Write a shim wrapper for each tool. Returns list of written paths."""
    target_dir = _shim_dir(shim_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for tool in tools or SHIMMED_TOOLS:
        path = target_dir / tool
        if path.exists() and not overwrite:
            continue
        path.write_text(WRAPPER_TEMPLATE.format(tool=tool))
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        written.append(path)
    return written


def uninstall_shims(
    tools: list[str] | None = None,
    shim_dir: str | os.PathLike | None = None,
) -> list[Path]:
    """Remove shim wrappers Watchdog wrote. Only deletes files that
    look like our wrappers (contain the marker comment) so we never
    nuke a user-authored binary that happens to share a name."""
    target_dir = _shim_dir(shim_dir)
    if not target_dir.exists():
        return []
    removed: list[Path] = []
    for tool in tools or SHIMMED_TOOLS:
        path = target_dir / tool
        if not path.is_file():
            continue
        try:
            head = path.read_text(errors="replace")[:200]
        except OSError:
            continue
        if "Watchdog shim" not in head:
            continue
        path.unlink()
        removed.append(path)
    return removed


def status(
    tools: list[str] | None = None,
    shim_dir: str | os.PathLike | None = None,
) -> dict[str, bool]:
    """Return {tool: installed} for each tool."""
    target_dir = _shim_dir(shim_dir)
    result: dict[str, bool] = {}
    for tool in tools or SHIMMED_TOOLS:
        path = target_dir / tool
        result[tool] = path.is_file() and os.access(path, os.X_OK)
    return result
