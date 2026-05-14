"""Locate the real package-manager binary on PATH, skipping the shim
directory so `os.execv` does not loop back into Watchdog.
"""
from __future__ import annotations

import os
from pathlib import Path


def find_real_binary(name: str, exclude_dirs: list[str]) -> str | None:
    """Walk PATH and return the first executable named `name` whose
    parent directory is NOT in `exclude_dirs`. Returns an absolute path
    or None if no real binary is found.

    Both `exclude_dirs` and PATH entries are normalised via `os.path.realpath`
    so symlinked shim dirs still match.
    """
    excluded = {os.path.realpath(d) for d in exclude_dirs}
    path = os.environ.get("PATH", "")
    for entry in path.split(os.pathsep):
        if not entry:
            continue
        try:
            real_entry = os.path.realpath(entry)
        except OSError:
            continue
        if real_entry in excluded:
            continue
        candidate = Path(entry) / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate.resolve())
    return None
