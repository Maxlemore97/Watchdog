"""Persistent plugin-vetting ledger.

Stores per-plugin content hashes and last-known verdicts under
`${WATCHDOG_CACHE_DIR}/vetted_plugins.json`. Used by the SessionStart
adapter to skip plugins whose on-disk contents have not changed since
they were last reviewed.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

from .paths import cache_dir

CACHE_DIR = cache_dir()
LEDGER_PATH = CACHE_DIR / "vetted_plugins.json"
LEDGER_VERSION = 1

SELF_NAME = "watchdog"

MAX_SCANS_PER_SESSION = int(os.environ.get("WATCHDOG_SESSION_MAX_SCANS", "10"))

HASH_DIRS = (".claude-plugin", "hooks", "commands", "skills")
HASH_FILES = ("plugin.json",)


def plugin_dirs() -> list[Path]:
    raw_list: list[str] = []
    env_dirs = os.environ.get("WATCHDOG_PLUGIN_DIRS")
    if env_dirs:
        raw_list.extend(p for p in env_dirs.split(os.pathsep) if p)
    raw_list.append(os.environ.get("CLAUDE_PLUGINS_DIR", ""))
    raw_list.append("~/.claude/plugins")
    out: list[Path] = []
    seen: set[Path] = set()
    for raw in raw_list:
        if not raw:
            continue
        p = Path(os.path.expanduser(raw)).resolve()
        if p in seen:
            continue
        seen.add(p)
        if p.is_dir():
            out.append(p)
    return out


def load_ledger() -> dict:
    try:
        with LEDGER_PATH.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict) and isinstance(data.get("entries"), dict):
            return data
    except (OSError, json.JSONDecodeError):
        pass
    return {"version": LEDGER_VERSION, "entries": {}}


def save_ledger(ledger: dict) -> None:
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        tmp = LEDGER_PATH.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as fh:
            json.dump(ledger, fh, indent=2, sort_keys=True)
        os.replace(tmp, LEDGER_PATH)
    except OSError:
        pass


def content_hash(plugin_root: Path) -> str:
    targets: list[Path] = []
    for name in HASH_DIRS:
        d = plugin_root / name
        if d.is_dir():
            for f in d.rglob("*"):
                if f.is_file() and not f.is_symlink():
                    targets.append(f)
    for name in HASH_FILES:
        f = plugin_root / name
        if f.is_file():
            targets.append(f)
    targets.sort(key=lambda p: str(p.relative_to(plugin_root)))
    h = hashlib.sha256()
    for f in targets:
        try:
            data = f.read_bytes()
        except OSError:
            continue
        rel = str(f.relative_to(plugin_root)).encode("utf-8")
        h.update(rel + b"\0")
        h.update(hashlib.sha256(data).digest())
    return h.hexdigest()


def read_manifest(plugin_root: Path) -> dict:
    for candidate in (".claude-plugin/plugin.json", "plugin.json"):
        path = plugin_root / candidate
        if path.is_file():
            try:
                with path.open("r", encoding="utf-8") as fh:
                    data = json.load(fh)
                if isinstance(data, dict):
                    return data
            except (OSError, json.JSONDecodeError):
                continue
    return {}


def discover_plugins(roots: list[Path] | None = None) -> list[tuple[str, Path, dict]]:
    """Return (name, path, manifest) for every plugin found beneath `roots`."""
    if roots is None:
        roots = plugin_dirs()
    seen: set[Path] = set()
    out: list[tuple[str, Path, dict]] = []
    for root in roots:
        if not root.is_dir():
            continue
        for child in sorted(root.iterdir()):
            if not child.is_dir():
                continue
            manifest = read_manifest(child)
            if not manifest:
                continue
            resolved = child.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            name = manifest.get("name") or child.name
            if not isinstance(name, str):
                name = child.name
            if name == SELF_NAME:
                continue
            out.append((name, child, manifest))
    return out


def scan_plugins(
    plugins: list[tuple[str, Path, dict]],
    ledger: dict,
    analyzer=None,
    max_scans: int | None = None,
) -> tuple[list[tuple[str, dict]], bool, int]:
    """Run analyzer on plugins whose hash is new/changed.

    Returns (findings, ledger_dirty, skipped_due_to_cap).

    `analyzer` defaults to `watchdog_core.analyzer.analyze_local_plugin`,
    imported lazily so callers that only need the ledger (or pass their
    own analyzer) avoid dragging in the LLM analyzer + fetchers.
    """
    if analyzer is None:
        from .analyzer import analyze_local_plugin as analyzer
    if max_scans is None:
        max_scans = MAX_SCANS_PER_SESSION
    entries = ledger.setdefault("entries", {})
    findings: list[tuple[str, dict]] = []
    dirty = False
    scans_used = 0
    skipped = 0
    for name, path, manifest in plugins:
        h = content_hash(path)
        prev = entries.get(name)
        if isinstance(prev, dict) and prev.get("content_hash") == h:
            continue
        if scans_used >= max_scans:
            skipped += 1
            continue
        scans_used += 1
        verdict = analyzer(name, str(path), h) or {
            "verdict": "ask",
            "reason": "analyzer returned no result",
        }
        entries[name] = {
            "name": name,
            "path": str(path),
            "manifest_version": manifest.get("version"),
            "content_hash": h,
            "verdict": verdict.get("verdict", "ask"),
            "risk": verdict.get("risk", "?"),
            "reason": (verdict.get("reason") or "")[:300],
            "scanned_at": int(time.time()),
        }
        findings.append((name, verdict))
        dirty = True
    return findings, dirty, skipped
