"""Per-ecosystem artifact fetchers.

Each `fetch_<ecosystem>` returns an `ArtifactBundle` carrying a curated,
size-capped subset of files from the published artifact and a metadata
dict. The dispatcher `fetch(ecosystem, name, version)` picks the right
fetcher by ecosystem string.

Plugin fetchers cover both git-cloned plugin sources (`fetch_plugin_git`)
and already-installed plugin directories (`fetch_plugin_local`).
"""
from __future__ import annotations

import io
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

from .types import ArtifactBundle

HTTP_TIMEOUT = 10.0
USER_AGENT = "watchdog-scanner/0.3"
MAX_FILE_BYTES = 10_000
MAX_BUNDLE_BYTES = 50_000
MAX_DOWNLOAD_BYTES = 5_000_000

NPM_INTERESTING_NAMES = {"package.json", "readme", "readme.md", "index.js", "index.mjs", "index.cjs"}
NPM_SCRIPT_KEYS = {"preinstall", "install", "postinstall", "prepare", "preuninstall"}

PYPI_INTERESTING_NAMES = {"setup.py", "setup.cfg", "pyproject.toml", "readme", "readme.md", "readme.rst", "__init__.py"}

CARGO_INTERESTING_NAMES = {"cargo.toml", "build.rs", "readme.md", "readme", "lib.rs", "main.rs"}
GEM_INTERESTING_EXT_NAMES = {"extconf.rb", "rakefile", "rakefile.rb"}
GEM_INTERESTING_NAMES = {"readme.md", "readme", "readme.rdoc"}
COMPOSER_INTERESTING_NAMES = {"composer.json", "readme.md", "readme"}
COMPOSER_SCRIPT_KEYS = {
    "pre-install-cmd",
    "post-install-cmd",
    "pre-update-cmd",
    "post-update-cmd",
    "pre-autoload-dump",
    "post-autoload-dump",
    "pre-package-install",
    "post-package-install",
}
CARGO_SCRIPT_FILES = {"build.rs"}

PLUGIN_INTERESTING_DIRS = {"hooks", "commands", "skills", ".claude-plugin"}


def _http_get(url: str) -> bytes | None:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            return resp.read(MAX_DOWNLOAD_BYTES + 1)
    except (urllib.error.URLError, TimeoutError):
        return None


def _http_get_json(url: str) -> dict | None:
    raw = _http_get(url)
    if not raw:
        return None
    try:
        return json.loads(raw.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        return None


def _truncate(text: str, limit: int = MAX_FILE_BYTES) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... [truncated, total {len(text)} bytes]"


def _read_member(extract_dir: Path, rel: Path) -> str | None:
    try:
        data = (extract_dir / rel).read_bytes()
    except (OSError, FileNotFoundError):
        return None
    try:
        return data.decode("utf-8", errors="replace")
    except UnicodeDecodeError:
        return None


def _apply_tar_filter(tf):
    """Set the safest extraction filter available so future Python
    versions cannot silently allow path traversal or device files via
    a hostile tar member. No-op on Python < 3.12."""
    try:
        tf.extraction_filter = tarfile.data_filter  # type: ignore[attr-defined]
    except AttributeError:
        try:
            tf.extraction_filter = "data"  # type: ignore[assignment]
        except (AttributeError, TypeError):
            pass
    return tf


def _open_archive(raw: bytes, kind: str):
    """Open an in-memory archive. `kind` is one of:
    - "tar.gz"    gzip-compressed tar (npm, crates, gem inner)
    - "tar"       uncompressed tar (gem outer)
    - "tar.any"   any tar variant (PyPI sdist that may be .tar.* or .tar)
    - "zip"       zip archive (Packagist, PyPI .zip sdist)
    """
    if kind == "zip":
        return zipfile.ZipFile(io.BytesIO(raw))
    if kind == "tar":
        return _apply_tar_filter(tarfile.open(fileobj=io.BytesIO(raw), mode="r:"))
    if kind == "tar.any":
        return _apply_tar_filter(tarfile.open(fileobj=io.BytesIO(raw), mode="r:*"))
    return _apply_tar_filter(tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz"))


def _extract_tar(
    tf, predicate, key_fn=lambda m, parts: "/".join(parts),
) -> dict[str, str]:
    """Walk a tar archive, keeping members for which `predicate(member, parts)`
    is True. `parts` is the cleaned member path tuple (leading "package/"
    stripped for npm). Returns {key: decoded-content}."""
    files: dict[str, str] = {}
    for member in tf.getmembers():
        if not member.isfile():
            continue
        rel = Path(member.name)
        parts = (
            rel.parts[1:] if rel.parts and rel.parts[0] == "package" else rel.parts
        )
        if not parts:
            continue
        if not predicate(member, parts):
            continue
        try:
            fh = tf.extractfile(member)
            if not fh:
                continue
            content = fh.read(MAX_FILE_BYTES * 2).decode("utf-8", errors="replace")
        except (OSError, KeyError, UnicodeDecodeError):
            continue
        files[key_fn(member, parts)] = content
    return files


def _extract_zip(zf, predicate) -> dict[str, str]:
    files: dict[str, str] = {}
    for member in zf.namelist():
        if not predicate(member):
            continue
        try:
            files[member] = zf.read(member).decode("utf-8", errors="replace")
        except (KeyError, UnicodeDecodeError):
            continue
    return files


def _fit_bundle(files: dict[str, str]) -> dict[str, str]:
    fit: dict[str, str] = {}
    used = 0
    for name, content in files.items():
        snippet = _truncate(content)
        if used + len(snippet) > MAX_BUNDLE_BYTES:
            snippet = snippet[: max(0, MAX_BUNDLE_BYTES - used)] + "\n... [bundle cap reached]"
        fit[name] = snippet
        used += len(snippet)
        if used >= MAX_BUNDLE_BYTES:
            break
    return fit


# ---------- npm ------------------------------------------------------------

def fetch_npm(name: str, version: str | None) -> ArtifactBundle | None:
    safe = urllib.parse.quote(name, safe="@/")
    if version:
        meta = _http_get_json(f"https://registry.npmjs.org/{safe}/{urllib.parse.quote(version)}")
    else:
        meta = _http_get_json(f"https://registry.npmjs.org/{safe}/latest")
    if not isinstance(meta, dict):
        return None

    tarball_url = (meta.get("dist") or {}).get("tarball")
    files: dict[str, str] = {}
    notes: list[str] = []

    scripts = (meta.get("scripts") or {})
    risky_scripts = {k: v for k, v in scripts.items() if k.lower() in NPM_SCRIPT_KEYS}
    if risky_scripts:
        files["package.json#scripts"] = json.dumps(risky_scripts, indent=2)

    if tarball_url:
        raw = _http_get(tarball_url)
        if raw:
            try:
                with _open_archive(raw, "tar.gz") as tf:
                    files.update(_extract_tar(
                        tf,
                        lambda m, parts: parts[-1].lower() in NPM_INTERESTING_NAMES,
                    ))
            except (tarfile.TarError, EOFError) as exc:
                notes.append(f"tarball read failed: {exc}")
        else:
            notes.append("tarball download failed")

    metadata = {
        "version": meta.get("version") or version,
        "author": meta.get("author") or meta.get("maintainers"),
        "license": meta.get("license"),
        "repository": meta.get("repository"),
        "homepage": meta.get("homepage"),
        "dependencies_count": len(meta.get("dependencies") or {}),
        "description": meta.get("description"),
    }
    return ArtifactBundle("npm", name, metadata.get("version"), _fit_bundle(files), metadata, notes)


# ---------- PyPI -----------------------------------------------------------

def fetch_pypi(name: str, version: str | None) -> ArtifactBundle | None:
    safe = urllib.parse.quote(name)
    if version:
        meta = _http_get_json(f"https://pypi.org/pypi/{safe}/{urllib.parse.quote(version)}/json")
    else:
        meta = _http_get_json(f"https://pypi.org/pypi/{safe}/json")
    if not isinstance(meta, dict):
        return None

    info = meta.get("info") or {}
    urls = meta.get("urls") or []
    files: dict[str, str] = {}
    notes: list[str] = []

    sdist_url = None
    for entry in urls:
        if entry.get("packagetype") == "sdist":
            sdist_url = entry.get("url")
            break

    if sdist_url:
        raw = _http_get(sdist_url)
        if raw:
            try:
                if sdist_url.endswith(".zip"):
                    with _open_archive(raw, "zip") as zf:
                        files.update(_extract_zip(
                            zf,
                            lambda m: m.rsplit("/", 1)[-1].lower() in PYPI_INTERESTING_NAMES,
                        ))
                else:
                    with _open_archive(raw, "tar.any") as tf:
                        files.update(_extract_tar(
                            tf,
                            lambda m, parts: parts[-1].lower() in PYPI_INTERESTING_NAMES,
                            key_fn=lambda m, parts: m.name,
                        ))
            except (tarfile.TarError, zipfile.BadZipFile, EOFError) as exc:
                notes.append(f"sdist read failed: {exc}")
        else:
            notes.append("sdist download failed")
    else:
        notes.append("no sdist available (wheel-only)")

    metadata = {
        "version": info.get("version") or version,
        "author": info.get("author"),
        "author_email": info.get("author_email"),
        "license": info.get("license"),
        "summary": info.get("summary"),
        "home_page": info.get("home_page"),
        "project_urls": info.get("project_urls"),
    }
    return ArtifactBundle("PyPI", name, metadata.get("version"), _fit_bundle(files), metadata, notes)


# ---------- crates.io ------------------------------------------------------

def fetch_crates(name: str, version: str | None) -> ArtifactBundle | None:
    safe = urllib.parse.quote(name, safe="")
    if version:
        meta_url = f"https://crates.io/api/v1/crates/{safe}/{urllib.parse.quote(version)}"
        meta = _http_get_json(meta_url)
        version_info = (meta or {}).get("version") if isinstance(meta, dict) else None
    else:
        meta = _http_get_json(f"https://crates.io/api/v1/crates/{safe}")
        version_info = None
        if isinstance(meta, dict):
            crate = meta.get("crate") or {}
            version_info = {"num": crate.get("max_stable_version") or crate.get("newest_version")}
    if not isinstance(meta, dict):
        return None

    crate_info = meta.get("crate") if isinstance(meta.get("crate"), dict) else {}
    chosen_version = (version_info or {}).get("num") if isinstance(version_info, dict) else version
    if not chosen_version:
        chosen_version = crate_info.get("max_stable_version") or crate_info.get("newest_version")

    files: dict[str, str] = {}
    notes: list[str] = []

    if chosen_version:
        dl_url = f"https://crates.io/api/v1/crates/{safe}/{urllib.parse.quote(chosen_version)}/download"
        raw = _http_get(dl_url)
        if raw:
            def _crate_pred(m, parts):
                leaf = parts[-1].lower()
                is_src_entry = len(parts) >= 2 and parts[-2] == "src" and leaf in {"lib.rs", "main.rs"}
                return leaf in CARGO_INTERESTING_NAMES or is_src_entry

            try:
                with _open_archive(raw, "tar.gz") as tf:
                    files.update(_extract_tar(
                        tf, _crate_pred, key_fn=lambda m, parts: m.name,
                    ))
            except (tarfile.TarError, EOFError) as exc:
                notes.append(f"crate tarball read failed: {exc}")
        else:
            notes.append("crate download failed")
    else:
        notes.append("no resolvable version")

    metadata = {
        "version": chosen_version,
        "description": crate_info.get("description"),
        "homepage": crate_info.get("homepage"),
        "repository": crate_info.get("repository"),
        "documentation": crate_info.get("documentation"),
        "downloads": crate_info.get("downloads"),
        "created_at": crate_info.get("created_at"),
        "has_build_script": any(Path(p).name.lower() in CARGO_SCRIPT_FILES for p in files),
    }
    return ArtifactBundle("crates.io", name, chosen_version, _fit_bundle(files), metadata, notes)


# ---------- RubyGems -------------------------------------------------------

def fetch_rubygems(name: str, version: str | None) -> ArtifactBundle | None:
    safe = urllib.parse.quote(name, safe="")
    meta = _http_get_json(f"https://rubygems.org/api/v1/gems/{safe}.json")
    if not isinstance(meta, dict):
        return None

    chosen_version = version or (meta.get("version") if isinstance(meta.get("version"), str) else None)
    if not chosen_version:
        return None

    files: dict[str, str] = {}
    notes: list[str] = []

    gem_url = f"https://rubygems.org/downloads/{safe}-{urllib.parse.quote(chosen_version)}.gem"
    raw = _http_get(gem_url)
    if raw:
        def _gem_pred(m, parts):
            leaf = parts[-1].lower()
            is_ext = "/ext/" in ("/" + m.name) and leaf in GEM_INTERESTING_EXT_NAMES
            is_lib_entry = m.name.endswith(f"lib/{name}.rb")
            is_gemspec = leaf.endswith(".gemspec")
            return (
                leaf in GEM_INTERESTING_NAMES
                or leaf in GEM_INTERESTING_EXT_NAMES
                or is_ext
                or is_lib_entry
                or is_gemspec
            )

        try:
            with _open_archive(raw, "tar") as outer:
                data_member = next(
                    (m for m in outer.getmembers() if m.name == "data.tar.gz"), None
                )
                if data_member is None:
                    notes.append("gem missing data.tar.gz")
                else:
                    fh = outer.extractfile(data_member)
                    if fh is None:
                        notes.append("could not read data.tar.gz")
                    else:
                        inner_bytes = fh.read()
                        try:
                            with _open_archive(inner_bytes, "tar.gz") as inner:
                                files.update(_extract_tar(
                                    inner, _gem_pred,
                                    key_fn=lambda m, parts: m.name,
                                ))
                        except (tarfile.TarError, EOFError) as exc:
                            notes.append(f"inner gem tarball failed: {exc}")
        except (tarfile.TarError, EOFError) as exc:
            notes.append(f"outer gem read failed: {exc}")
    else:
        notes.append("gem download failed")

    metadata = {
        "version": chosen_version,
        "authors": meta.get("authors"),
        "info": meta.get("info"),
        "licenses": meta.get("licenses"),
        "homepage_uri": meta.get("homepage_uri"),
        "source_code_uri": meta.get("source_code_uri"),
        "downloads": meta.get("downloads"),
        "has_native_extension": any("/ext/" in ("/" + p) for p in files),
    }
    return ArtifactBundle("RubyGems", name, chosen_version, _fit_bundle(files), metadata, notes)


# ---------- Packagist ------------------------------------------------------

def fetch_packagist(name: str, version: str | None) -> ArtifactBundle | None:
    safe = urllib.parse.quote(name, safe="/")
    meta = _http_get_json(f"https://repo.packagist.org/p2/{safe}.json")
    if not isinstance(meta, dict):
        return None

    packages = meta.get("packages") or {}
    entries = packages.get(name) or next(iter(packages.values()), None)
    if not isinstance(entries, list) or not entries:
        return None

    chosen_entry: dict | None = None
    if version:
        for e in entries:
            if isinstance(e, dict) and e.get("version") == version:
                chosen_entry = e
                break
    if chosen_entry is None:
        for e in entries:
            if isinstance(e, dict) and not str(e.get("version", "")).startswith("dev-"):
                chosen_entry = e
                break
    if chosen_entry is None:
        chosen_entry = entries[0] if isinstance(entries[0], dict) else None
    if chosen_entry is None:
        return None

    chosen_version = chosen_entry.get("version")
    dist = chosen_entry.get("dist") or {}
    dist_url = dist.get("url")

    files: dict[str, str] = {}
    notes: list[str] = []

    composer_scripts = (chosen_entry.get("scripts") or {})
    risky_scripts = {k: v for k, v in composer_scripts.items() if k in COMPOSER_SCRIPT_KEYS}
    if risky_scripts:
        files["composer.json#scripts"] = json.dumps(risky_scripts, indent=2)

    if dist_url:
        raw = _http_get(dist_url)
        if raw:
            try:
                with _open_archive(raw, "zip") as zf:
                    files.update(_extract_zip(
                        zf,
                        lambda m: m.rsplit("/", 1)[-1].lower() in COMPOSER_INTERESTING_NAMES,
                    ))
            except (zipfile.BadZipFile, EOFError) as exc:
                notes.append(f"zip read failed: {exc}")
        else:
            notes.append("zip download failed")
    else:
        notes.append("no dist url")

    metadata = {
        "version": chosen_version,
        "type": chosen_entry.get("type"),
        "description": chosen_entry.get("description"),
        "authors": chosen_entry.get("authors"),
        "license": chosen_entry.get("license"),
        "require": chosen_entry.get("require"),
        "has_install_scripts": bool(risky_scripts),
    }
    return ArtifactBundle("Packagist", name, chosen_version, _fit_bundle(files), metadata, notes)


# ---------- plugin (git clone) --------------------------------------------

def _git_env() -> dict[str, str]:
    """Subprocess env that disables interactive auth prompts. Hostile URLs
    must not be able to hang waiting for credentials or host-key approval."""
    return {
        **os.environ,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "/bin/true",
        "GIT_SSH_COMMAND": "ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new",
    }


def fetch_plugin_git(git_url: str, ref: str | None = None) -> ArtifactBundle | None:
    if not re.match(r"^(https://|git@|ssh://)", git_url):
        return None
    tmp = Path(tempfile.mkdtemp(prefix="watchdog-clone-"))
    notes: list[str] = []
    files: dict[str, str] = {}
    try:
        cmd = ["git", "clone", "--depth=1", "--filter=blob:none"]
        if ref:
            cmd += ["--branch", ref]
        cmd += ["--", git_url, str(tmp)]
        try:
            subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                timeout=20,
                env=_git_env(),
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as exc:
            notes.append(f"git clone failed: {exc}")
            return ArtifactBundle("plugin", git_url, ref, {}, {}, notes)

        for sub in PLUGIN_INTERESTING_DIRS:
            d = tmp / sub
            if not d.is_dir():
                continue
            for path in d.rglob("*"):
                if path.is_symlink() or not path.is_file():
                    continue
                rel = path.relative_to(tmp)
                content = _read_member(tmp, rel)
                if content is None:
                    continue
                files[str(rel)] = content

        root_manifest = tmp / "plugin.json"
        if root_manifest.is_file():
            content = _read_member(tmp, Path("plugin.json"))
            if content:
                files["plugin.json"] = content
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    metadata: dict = {}
    if "plugin.json" in files or ".claude-plugin/plugin.json" in files:
        manifest_key = "plugin.json" if "plugin.json" in files else ".claude-plugin/plugin.json"
        try:
            metadata = json.loads(files[manifest_key])
        except json.JSONDecodeError:
            notes.append("plugin.json not valid JSON")

    return ArtifactBundle("plugin", git_url, ref, _fit_bundle(files), metadata, notes)


# ---------- plugin (already on disk) --------------------------------------

def fetch_plugin_local(name: str, path: str) -> ArtifactBundle | None:
    """Bundle a plugin that already lives on disk (no clone, no network)."""
    root = Path(path)
    if not root.is_dir():
        return None

    files: dict[str, str] = {}
    notes: list[str] = []

    for sub in PLUGIN_INTERESTING_DIRS:
        d = root / sub
        if not d.is_dir():
            continue
        for fp in d.rglob("*"):
            if fp.is_symlink() or not fp.is_file():
                continue
            rel = fp.relative_to(root)
            content = _read_member(root, rel)
            if content is None:
                continue
            files[str(rel)] = content

    for candidate in ("plugin.json", ".claude-plugin/plugin.json"):
        candidate_path = root / candidate
        if candidate_path.is_symlink() or not candidate_path.is_file():
            continue
        content = _read_member(root, Path(candidate))
        if content is not None:
            files[candidate] = content

    metadata: dict = {"local": True, "path": str(root)}
    for key in (".claude-plugin/plugin.json", "plugin.json"):
        if key in files:
            try:
                parsed = json.loads(files[key])
                if isinstance(parsed, dict):
                    metadata.update(parsed)
                break
            except json.JSONDecodeError:
                notes.append(f"{key} not valid JSON")

    version = metadata.get("version") if isinstance(metadata.get("version"), str) else None
    return ArtifactBundle("plugin", name, version, _fit_bundle(files), metadata, notes)


# ---------- dispatcher -----------------------------------------------------

def fetch(ecosystem: str, name: str, version: str | None = None) -> ArtifactBundle | None:
    if ecosystem == "npm":
        return fetch_npm(name, version)
    if ecosystem == "PyPI":
        return fetch_pypi(name, version)
    if ecosystem == "crates.io":
        return fetch_crates(name, version)
    if ecosystem == "RubyGems":
        return fetch_rubygems(name, version)
    if ecosystem == "Packagist":
        return fetch_packagist(name, version)
    if ecosystem == "plugin":
        return fetch_plugin_git(name, version)
    return None
