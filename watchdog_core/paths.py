"""Filesystem path helpers shared across watchdog_core modules.

Centralises the on-disk cache directory resolution so analyzer, osv,
and ledger agree on where they persist state without copy-pasting the
env-var fallbacks.
"""
from __future__ import annotations

import os
from pathlib import Path


def cache_dir() -> Path:
    """Return the directory Watchdog uses for OSV/LLM caches and the
    plugin ledger. Resolution order:

    1. `WATCHDOG_CACHE_DIR` env var (absolute path)
    2. `$XDG_CACHE_HOME/watchdog`
    3. `~/.cache/watchdog`
    """
    override = os.environ.get("WATCHDOG_CACHE_DIR")
    if override:
        return Path(override)
    xdg = os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache")
    return Path(xdg) / "watchdog"
