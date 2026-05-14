"""OSV.dev vulnerability lookup, version resolution per ecosystem, and
severity helpers.

All HTTP requests are short-timeout, stdlib-only. Successful OSV responses
are cached on disk under `WATCHDOG_CACHE_DIR` for `WATCHDOG_CACHE_TTL`
seconds.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Iterable

from .paths import cache_dir
from .types import Package

OSV_ENDPOINT = "https://api.osv.dev/v1/query"
HTTP_TIMEOUT = 5.0

CACHE_DIR = cache_dir()
CACHE_TTL_SECONDS = int(os.environ.get("WATCHDOG_CACHE_TTL", "3600"))

SEVERITY_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
UNKNOWN_SEVERITY_RANK = SEVERITY_RANK["high"]
MIN_SEVERITY = os.environ.get("WATCHDOG_MIN_SEVERITY", "low").strip().lower()
if MIN_SEVERITY not in SEVERITY_RANK:
    MIN_SEVERITY = "low"
MIN_SEVERITY_RANK = SEVERITY_RANK[MIN_SEVERITY]

RESOLVE_LATEST = os.environ.get("WATCHDOG_RESOLVE_LATEST", "1").strip().lower() not in {
    "0",
    "false",
    "no",
    "off",
}

USER_AGENT = "watchdog-scanner/0.3 (+https://github.com/)"


def cache_path(pkg: Package) -> Path:
    key = f"{pkg.ecosystem}|{pkg.name}|{pkg.version or ''}".lower()
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]
    return CACHE_DIR / f"{digest}.json"


def cache_load(pkg: Package) -> list[dict] | None:
    path = cache_path(pkg)
    try:
        st = path.stat()
    except FileNotFoundError:
        return None
    if time.time() - st.st_mtime > CACHE_TTL_SECONDS:
        return None
    try:
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None


def cache_store(pkg: Package, vulns: list[dict]) -> None:
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        path = cache_path(pkg)
        tmp = path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as fh:
            json.dump(vulns, fh)
        os.replace(tmp, path)
    except OSError:
        pass


def _http_get_json(url: str) -> dict | None:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            return json.load(resp)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return None


def fetch_latest_version(pkg: Package) -> str | None:
    if pkg.ecosystem == "npm":
        data = _http_get_json(f"https://registry.npmjs.org/{urllib.parse.quote(pkg.name, safe='@/')}/latest")
        if isinstance(data, dict):
            v = data.get("version")
            return v if isinstance(v, str) else None
    if pkg.ecosystem == "PyPI":
        data = _http_get_json(f"https://pypi.org/pypi/{urllib.parse.quote(pkg.name)}/json")
        if isinstance(data, dict):
            v = (data.get("info") or {}).get("version")
            return v if isinstance(v, str) else None
    if pkg.ecosystem == "crates.io":
        data = _http_get_json(f"https://crates.io/api/v1/crates/{urllib.parse.quote(pkg.name)}")
        if isinstance(data, dict):
            crate = data.get("crate") or {}
            v = crate.get("max_stable_version") or crate.get("newest_version")
            return v if isinstance(v, str) else None
    if pkg.ecosystem == "RubyGems":
        data = _http_get_json(f"https://rubygems.org/api/v1/gems/{urllib.parse.quote(pkg.name)}.json")
        if isinstance(data, dict):
            v = data.get("version")
            return v if isinstance(v, str) else None
    if pkg.ecosystem == "Packagist":
        data = _http_get_json(
            f"https://repo.packagist.org/p2/{urllib.parse.quote(pkg.name, safe='/')}.json"
        )
        if isinstance(data, dict):
            packages = data.get("packages") or {}
            entries = packages.get(pkg.name) or next(iter(packages.values()), None)
            if isinstance(entries, list) and entries:
                v = entries[0].get("version") if isinstance(entries[0], dict) else None
                return v if isinstance(v, str) and not v.startswith("dev-") else None
    return None


def resolve_version(pkg: Package) -> Package:
    if pkg.version or not RESOLVE_LATEST:
        return pkg
    latest = fetch_latest_version(pkg)
    if not latest:
        return pkg
    return Package(ecosystem=pkg.ecosystem, name=pkg.name, version=latest)


def query_osv(pkg: Package) -> list[dict]:
    cached = cache_load(pkg)
    if cached is not None:
        return cached

    body: dict = {"package": {"name": pkg.name, "ecosystem": pkg.ecosystem}}
    if pkg.version:
        body["version"] = pkg.version
    req = urllib.request.Request(
        OSV_ENDPOINT,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
        data = json.load(resp)
    vulns = data.get("vulns", []) or []
    cache_store(pkg, vulns)
    return vulns


def _score_to_rank(score: float) -> int:
    if score >= 9.0:
        return SEVERITY_RANK["critical"]
    if score >= 7.0:
        return SEVERITY_RANK["high"]
    if score >= 4.0:
        return SEVERITY_RANK["medium"]
    if score > 0.0:
        return SEVERITY_RANK["low"]
    return SEVERITY_RANK["none"]


def severity_rank(vuln: dict) -> int:
    label = (vuln.get("database_specific") or {}).get("severity")
    if isinstance(label, str) and label.strip().lower() in SEVERITY_RANK:
        return SEVERITY_RANK[label.strip().lower()]

    best: int | None = None
    for entry in vuln.get("severity") or []:
        score_str = entry.get("score") if isinstance(entry, dict) else None
        if not score_str:
            continue
        try:
            numeric = float(score_str)
        except (TypeError, ValueError):
            continue
        rank = _score_to_rank(numeric)
        if best is None or rank > best:
            best = rank
    if best is not None:
        return best
    return UNKNOWN_SEVERITY_RANK


def severity_label(rank: int) -> str:
    for name, value in SEVERITY_RANK.items():
        if value == rank:
            return name
    return "unknown"


def filter_by_severity(vulns: list[dict]) -> list[dict]:
    return [v for v in vulns if severity_rank(v) >= MIN_SEVERITY_RANK]


def summarize(vulns: Iterable[dict]) -> str:
    items = [(v.get("id", "?"), severity_label(severity_rank(v))) for v in vulns]
    rendered = [f"{vid}[{sev}]" for vid, sev in items[:5]]
    return ", ".join(rendered) + (" ..." if len(items) > 5 else "")
