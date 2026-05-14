"""Parsers for install-shaped Bash commands and Claude Code plugin
prompt patterns.

The install-command parser turns strings like
    "npm install lodash@4.17.20 && pip install -r reqs.txt"
into a list of `Package` objects (resolved targets) and a list of notes
(unsupported install forms that should still trigger an "ask" decision).

The plugin-prompt parser recognises `/plugin install` and
`/plugin marketplace add` slash commands.
"""
from __future__ import annotations

import re
import shlex
from typing import Callable, Iterable, Tuple

from .types import Package


# ---------- install-command parser ----------------------------------------

ECOSYSTEM_BY_CMD = {
    "npm": "npm",
    "pnpm": "npm",
    "yarn": "npm",
    "pip": "PyPI",
    "pip3": "PyPI",
    "uv": "PyPI",
    "uv-pip": "PyPI",
    "poetry": "PyPI",
    "cargo": "crates.io",
    "gem": "RubyGems",
    "composer": "Packagist",
}

INSTALL_SUBCMDS = {
    "npm": {"install", "i", "add"},
    "pnpm": {"add", "install", "i"},
    "yarn": {"add"},
    "pip": {"install"},
    "pip3": {"install"},
    "uv": {"add"},
    "uv-pip": {"install"},
    "poetry": {"add"},
    "cargo": {"add", "install"},
    "gem": {"install"},
    "composer": {"require"},
}

SHELL_BINARIES = {"bash", "sh", "zsh", "dash", "ash", "ksh"}

PIP_LIKE = {"pip", "pip3", "uv-pip"}

FLAGS_WITH_ARG: dict[str, set[str]] = {
    "pip": {"-r", "--requirement", "-c", "--constraint", "-e", "--editable",
            "-t", "--target", "-i", "--index-url", "--extra-index-url",
            "-f", "--find-links", "--prefix", "--root", "--src"},
    "pip3": {"-r", "--requirement", "-c", "--constraint", "-e", "--editable",
             "-t", "--target", "-i", "--index-url", "--extra-index-url",
             "-f", "--find-links", "--prefix", "--root", "--src"},
    "uv-pip": {"-r", "--requirement", "-c", "--constraint", "-e", "--editable",
               "--index-url", "--extra-index-url", "--find-links"},
    "uv": {"--index-url", "--extra-index-url", "--find-links"},
    "poetry": {"--source", "--python", "-E", "--extras"},
    "npm": {"--registry", "--prefix", "--cache", "--userconfig",
            "--globalconfig", "--workspace", "-w"},
    "pnpm": {"--registry", "--prefix", "--cache", "--workspace", "-w",
             "--filter"},
    "yarn": {"--registry", "--cache-folder", "--modules-folder"},
    "cargo": {"--registry", "--index", "--path", "--git", "--branch",
              "--tag", "--rev", "--root", "--target", "--profile", "-Z"},
    "gem": {"--source", "--bindir", "--install-dir", "-i", "-n"},
    "composer": {"--working-dir", "-d", "--repository", "--repository-url"},
}

URL_PATH_PREFIXES = (
    "./", "../", "/", "~/", "~", ".\\",
    "git+", "http://", "https://", "ftp://", "file://",
    "svn+", "hg+", "bzr+",
)
ARCHIVE_SUFFIXES = (
    ".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".tbz2",
    ".zip", ".whl", ".gem",
)


def _is_url_or_path(token: str) -> bool:
    if token.startswith(URL_PATH_PREFIXES):
        return True
    low = token.lower()
    return low.endswith(ARCHIVE_SUFFIXES)


def split_name_version(token: str, binary: str) -> tuple[str | None, str | None]:
    if binary in {"npm", "pnpm", "yarn"}:
        if token.startswith("@"):
            scope, _, rest = token.partition("/")
            if not rest:
                return token, None
            name_part, _, version = rest.partition("@")
            return f"{scope}/{name_part}", version or None
        name, _, version = token.partition("@")
        return name, version or None
    if binary in {"pip", "pip3", "uv", "uv-pip", "poetry"}:
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(?:==|@)\s*([A-Za-z0-9_.\-]+)$", token)
        if m:
            return m.group(1), m.group(2)
        return re.split(r"[<>=!~]", token, maxsplit=1)[0] or None, None
    if binary == "cargo":
        name, _, version = token.partition("@")
        return name, version or None
    if binary == "gem":
        return token, None
    if binary == "composer":
        name, _, version = token.partition(":")
        return name, version or None
    return token, None


def parse_install(command: str) -> tuple[list[Package], list[str]]:
    """Parse one install-shaped command. Return (packages, notes).

    Notes describe unsupported install forms that should still trigger an
    "ask" decision: requirements files, editable installs, URLs, local paths.
    """
    try:
        tokens = shlex.split(command.strip(), posix=True)
    except ValueError:
        return [], []
    if len(tokens) < 3:
        return [], []

    binary = tokens[0].split("/")[-1]
    if binary == "uv" and tokens[1] == "pip":
        if len(tokens) < 4:
            return [], []
        effective_binary = "uv-pip"
        subcmd = tokens[2]
        args = tokens[3:]
    else:
        effective_binary = binary
        subcmd = tokens[1]
        args = tokens[2:]

    ecosystem = ECOSYSTEM_BY_CMD.get(effective_binary)
    if not ecosystem:
        return [], []
    if subcmd not in INSTALL_SUBCMDS.get(effective_binary, set()):
        return [], []

    flag_args = FLAGS_WITH_ARG.get(effective_binary, set())
    pkgs: list[Package] = []
    notes: list[str] = []
    i = 0
    while i < len(args):
        tok = args[i]
        if tok.startswith("-"):
            flag_name, _, inline_val = tok.partition("=")
            if flag_name in flag_args:
                consumed = inline_val if inline_val else (args[i + 1] if i + 1 < len(args) else "")
                if flag_name in {"-r", "--requirement"} and consumed:
                    notes.append(f"requirements file: {consumed}")
                elif flag_name in {"-c", "--constraint"} and consumed:
                    notes.append(f"constraints file: {consumed}")
                elif flag_name in {"-e", "--editable"} and consumed:
                    notes.append(f"editable install: {consumed}")
                i += 1 if inline_val else 2
                continue
            i += 1
            continue
        if _is_url_or_path(tok):
            notes.append(f"url/path install: {tok}")
            i += 1
            continue
        name, version = split_name_version(tok, effective_binary)
        if not name:
            i += 1
            continue
        pkgs.append(Package(ecosystem=ecosystem, name=name, version=version))
        i += 1
    return pkgs, notes


def parse_packages(command: str) -> list[Package]:
    pkgs, _ = parse_install(command)
    return pkgs


def _extract_subshells(command: str) -> list[str]:
    """Return inner commands from shell -c wrappers."""
    try:
        tokens = shlex.split(command.strip(), posix=True)
    except ValueError:
        return []
    if not tokens:
        return []
    binary = tokens[0].split("/")[-1]
    if binary not in SHELL_BINARIES:
        return []
    out: list[str] = []
    for idx, tok in enumerate(tokens):
        if tok == "-c" and idx + 1 < len(tokens):
            out.append(tokens[idx + 1])
    return out


def collect_packages(
    command: str,
    resolve_version_fn: Callable[[Package], Package] | None = None,
) -> Tuple[list[Package], list[str]]:
    """Recursive walker: splits on shell operators, extracts subshells from
    `bash -c "..."` wrappers, parses each segment, resolves versions.

    `resolve_version_fn` defaults to `watchdog_core.osv.resolve_version`
    (late-imported to avoid import cycles). Tests can pass `lambda p: p`
    for a pure-parsing run without network calls.

    Version resolution for multiple packages runs in parallel via a
    thread pool so a 5-package install does not stack 5 sequential
    registry latencies onto the user.
    """
    if resolve_version_fn is None:
        from .osv import resolve_version as _rv
        resolve_version_fn = _rv

    raw_pkgs: list[Package] = []
    notes: list[str] = []
    seen: set[str] = set()

    def _walk(cmd: str, depth: int) -> None:
        if depth > 3:
            return
        for inner in _extract_subshells(cmd):
            _walk(inner, depth + 1)
        for segment in re.split(r"&&|;|\|\|", cmd):
            seg = segment.strip()
            if not seg or seg in seen:
                continue
            seen.add(seg)
            seg_pkgs, seg_notes = parse_install(seg)
            raw_pkgs.extend(seg_pkgs)
            notes.extend(seg_notes)
            for inner in _extract_subshells(seg):
                _walk(inner, depth + 1)

    _walk(command, 0)

    if not raw_pkgs:
        return [], notes
    if len(raw_pkgs) == 1:
        return [resolve_version_fn(raw_pkgs[0])], notes

    from concurrent.futures import ThreadPoolExecutor
    workers = min(len(raw_pkgs), 8)
    with ThreadPoolExecutor(max_workers=workers) as ex:
        resolved = list(ex.map(resolve_version_fn, raw_pkgs))
    return resolved, notes


# ---------- plugin-prompt parser ------------------------------------------

PLUGIN_PROMPT_PATTERNS = [
    re.compile(r"^/plugin\s+install\s+(?P<target>\S+)", re.IGNORECASE),
    re.compile(r"^/plugin\s+marketplace\s+add\s+(?P<target>\S+)", re.IGNORECASE),
]

GIT_URL_PATTERN = re.compile(r"^(https?://|git@|ssh://).+")


def classify_plugin_target(target: str) -> tuple[str, str, str | None]:
    """Classify a /plugin install argument into (ecosystem, name, version).

    Always returns ecosystem="plugin"; "name" is either a registry name
    (rare) or a git URL.
    """
    if GIT_URL_PATTERN.match(target) or target.endswith(".git"):
        return ("plugin", target, None)
    if "@" in target and not target.startswith("@"):
        name, _, version = target.partition("@")
        return ("plugin", name, version or None)
    return ("plugin", target, None)


def extract_plugin_targets(prompt: str) -> list[str]:
    """Return list of /plugin install / /plugin marketplace add targets
    found in the prompt text."""
    targets: list[str] = []
    for pat in PLUGIN_PROMPT_PATTERNS:
        m = pat.match(prompt.strip())
        if m:
            targets.append(m.group("target"))
    return targets
