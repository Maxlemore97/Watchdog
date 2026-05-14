"""Opt-in structured logging for debugging Watchdog in the field.

Disabled by default. Set `WATCHDOG_LOG` to a writable file path to
enable; events are appended as JSON lines so they survive across hook
invocations and can be tailed live.

Failures (path unwritable, disk full, etc.) are swallowed — diagnostics
must never break a hook's primary contract (stdout JSON decision).
"""
from __future__ import annotations

import json
import os
import time
from typing import Any


def _log_path() -> str | None:
    raw = os.environ.get("WATCHDOG_LOG", "").strip()
    return raw or None


def log_event(event: str, **fields: Any) -> None:
    """Append one JSON line to `WATCHDOG_LOG` if set. No-op otherwise.

    Each line is one event: `{"ts": <unix>, "event": "<name>", **fields}`.
    """
    path = _log_path()
    if not path:
        return
    record = {"ts": time.time(), "event": event, "pid": os.getpid(), **fields}
    try:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, default=str) + "\n")
    except OSError:
        pass
