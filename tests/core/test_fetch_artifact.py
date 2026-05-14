import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import watchdog_core.fetchers as fa  # noqa: E402


def make_targz(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, content in files.items():
            data = content.encode("utf-8")
            ti = tarfile.TarInfo(name=name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def make_zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def make_gem(data_files: dict[str, str]) -> bytes:
    inner = make_targz(data_files)
    outer = io.BytesIO()
    with tarfile.open(fileobj=outer, mode="w:") as tf:
        ti = tarfile.TarInfo(name="data.tar.gz")
        ti.size = len(inner)
        tf.addfile(ti, io.BytesIO(inner))
        meta = b"---\nname: dummy\n"
        mi = tarfile.TarInfo(name="metadata.gz")
        mi.size = len(meta)
        tf.addfile(mi, io.BytesIO(meta))
    return outer.getvalue()


class HelpersTests(unittest.TestCase):
    def test_truncate_no_op_when_short(self):
        self.assertEqual(fa._truncate("hello", limit=100), "hello")

    def test_truncate_appends_marker(self):
        result = fa._truncate("x" * 50, limit=10)
        self.assertTrue(result.startswith("x" * 10))
        self.assertIn("truncated", result)

    def test_fit_bundle_enforces_cap(self):
        big = "x" * (fa.MAX_FILE_BYTES + 100)
        files = {f"f{i}.txt": big for i in range(20)}
        fit = fa._fit_bundle(files)
        total = sum(len(v) for v in fit.values())
        self.assertLessEqual(total, fa.MAX_BUNDLE_BYTES + 200)


class NpmFetcherTests(unittest.TestCase):
    def test_extracts_interesting_files(self):
        tar = make_targz({
            "package/package.json": json.dumps({"name": "x", "scripts": {"postinstall": "node ./e.js"}}),
            "package/index.js": "console.log('hi')",
            "package/lib/internal.js": "// not interesting",
            "package/README.md": "readme body",
        })
        meta = {
            "name": "x",
            "version": "1.0.0",
            "dist": {"tarball": "https://example/x.tgz"},
            "scripts": {"postinstall": "node ./e.js"},
            "description": "test",
            "license": "MIT",
        }
        with patch.object(fa, "_http_get_json", return_value=meta), \
             patch.object(fa, "_http_get", return_value=tar):
            bundle = fa.fetch_npm("x", "1.0.0")
        self.assertIsNotNone(bundle)
        self.assertIn("package.json", bundle.files)
        self.assertIn("index.js", bundle.files)
        self.assertIn("README.md", bundle.files)
        self.assertNotIn("lib/internal.js", bundle.files)
        self.assertIn("package.json#scripts", bundle.files)
        self.assertEqual(bundle.metadata["version"], "1.0.0")

    def test_returns_none_when_meta_missing(self):
        with patch.object(fa, "_http_get_json", return_value=None):
            self.assertIsNone(fa.fetch_npm("x", "1.0.0"))

    def test_notes_when_tarball_fails(self):
        meta = {"name": "x", "version": "1.0.0", "dist": {"tarball": "https://example/x.tgz"}}
        with patch.object(fa, "_http_get_json", return_value=meta), \
             patch.object(fa, "_http_get", return_value=None):
            bundle = fa.fetch_npm("x", "1.0.0")
        self.assertIn("tarball download failed", bundle.notes)


class PypiFetcherTests(unittest.TestCase):
    def test_extracts_from_sdist_targz(self):
        tar = make_targz({
            "pkg-1.0/setup.py": "from setuptools import setup",
            "pkg-1.0/pyproject.toml": "[project]",
            "pkg-1.0/pkg/__init__.py": "VERSION = '1.0'",
            "pkg-1.0/README.md": "readme",
            "pkg-1.0/docs/foo.md": "not interesting",
        })
        meta = {
            "info": {"version": "1.0", "author": "a", "summary": "s"},
            "urls": [{"packagetype": "sdist", "url": "https://example/pkg.tar.gz"}],
        }
        with patch.object(fa, "_http_get_json", return_value=meta), \
             patch.object(fa, "_http_get", return_value=tar):
            bundle = fa.fetch_pypi("pkg", "1.0")
        names = list(bundle.files.keys())
        self.assertTrue(any(n.endswith("setup.py") for n in names))
        self.assertTrue(any(n.endswith("pyproject.toml") for n in names))
        self.assertTrue(any(n.endswith("__init__.py") for n in names))
        self.assertFalse(any(n.endswith("foo.md") for n in names))

    def test_notes_when_wheel_only(self):
        meta = {"info": {"version": "1.0"}, "urls": [{"packagetype": "bdist_wheel", "url": "x.whl"}]}
        with patch.object(fa, "_http_get_json", return_value=meta):
            bundle = fa.fetch_pypi("pkg", "1.0")
        self.assertIn("no sdist available (wheel-only)", bundle.notes)


class CratesFetcherTests(unittest.TestCase):
    def test_extracts_and_flags_build_script(self):
        tar = make_targz({
            "serde-1.0.0/Cargo.toml": "[package]\nname = \"serde\"",
            "serde-1.0.0/build.rs": "fn main() {}",
            "serde-1.0.0/src/lib.rs": "// lib",
            "serde-1.0.0/src/inner.rs": "// not extracted",
            "serde-1.0.0/README.md": "readme",
        })
        meta = {
            "crate": {"max_stable_version": "1.0.0", "description": "d"},
            "version": {"num": "1.0.0"},
        }
        with patch.object(fa, "_http_get_json", return_value=meta), \
             patch.object(fa, "_http_get", return_value=tar):
            bundle = fa.fetch_crates("serde", "1.0.0")
        self.assertTrue(bundle.metadata["has_build_script"])
        names = list(bundle.files.keys())
        self.assertTrue(any(n.endswith("build.rs") for n in names))
        self.assertTrue(any(n.endswith("src/lib.rs") for n in names))
        self.assertFalse(any(n.endswith("src/inner.rs") for n in names))


class RubygemsFetcherTests(unittest.TestCase):
    def test_extracts_native_extension_flag(self):
        gem = make_gem({
            "lib/mygem.rb": "module Mygem; end",
            "ext/mygem/extconf.rb": "require 'mkmf'; create_makefile('mygem')",
            "mygem.gemspec": "Gem::Specification.new",
            "test/test_x.rb": "ignored",
        })
        meta = {"name": "mygem", "version": "1.0.0", "authors": "a", "info": "i"}
        with patch.object(fa, "_http_get_json", return_value=meta), \
             patch.object(fa, "_http_get", return_value=gem):
            bundle = fa.fetch_rubygems("mygem", "1.0.0")
        self.assertTrue(bundle.metadata["has_native_extension"])
        names = list(bundle.files.keys())
        self.assertTrue(any(n.endswith("extconf.rb") for n in names))
        self.assertTrue(any(n.endswith("mygem.gemspec") for n in names))
        self.assertTrue(any(n.endswith("lib/mygem.rb") for n in names))
        self.assertFalse(any("test_x" in n for n in names))


class PackagistFetcherTests(unittest.TestCase):
    def test_flags_install_scripts(self):
        zip_bytes = make_zip({
            "vendor-pkg-abc/composer.json": json.dumps({"name": "foo/bar"}),
            "vendor-pkg-abc/README.md": "readme",
        })
        meta = {
            "packages": {
                "foo/bar": [
                    {
                        "version": "2.0.0",
                        "type": "library",
                        "scripts": {"post-install-cmd": "echo hi"},
                        "dist": {"url": "https://example/foo.zip"},
                    },
                    {"version": "dev-main", "dist": {"url": "x"}},
                ]
            }
        }
        with patch.object(fa, "_http_get_json", return_value=meta), \
             patch.object(fa, "_http_get", return_value=zip_bytes):
            bundle = fa.fetch_packagist("foo/bar", None)
        self.assertEqual(bundle.version, "2.0.0")
        self.assertTrue(bundle.metadata["has_install_scripts"])
        self.assertIn("composer.json#scripts", bundle.files)
        names = list(bundle.files.keys())
        self.assertTrue(any(n.endswith("composer.json") for n in names))

    def test_skips_dev_only_versions(self):
        meta = {"packages": {"foo/bar": [{"version": "dev-main", "dist": {"url": "x"}}]}}
        with patch.object(fa, "_http_get_json", return_value=meta), \
             patch.object(fa, "_http_get", return_value=b""):
            bundle = fa.fetch_packagist("foo/bar", None)
        self.assertEqual(bundle.version, "dev-main")


class DispatcherTests(unittest.TestCase):
    def test_dispatcher_routes_by_ecosystem(self):
        with patch.object(fa, "fetch_npm", return_value="NPM") as a, \
             patch.object(fa, "fetch_pypi", return_value="PY") as b, \
             patch.object(fa, "fetch_crates", return_value="C") as c, \
             patch.object(fa, "fetch_rubygems", return_value="R") as d, \
             patch.object(fa, "fetch_packagist", return_value="P") as e, \
             patch.object(fa, "fetch_plugin_git", return_value="G") as f:
            self.assertEqual(fa.fetch("npm", "x"), "NPM")
            self.assertEqual(fa.fetch("PyPI", "x"), "PY")
            self.assertEqual(fa.fetch("crates.io", "x"), "C")
            self.assertEqual(fa.fetch("RubyGems", "x"), "R")
            self.assertEqual(fa.fetch("Packagist", "x"), "P")
            self.assertEqual(fa.fetch("plugin", "https://x"), "G")
            self.assertIsNone(fa.fetch("unknown", "x"))
        a.assert_called_once()
        b.assert_called_once()
        c.assert_called_once()
        d.assert_called_once()
        e.assert_called_once()
        f.assert_called_once()

    def test_plugin_git_rejects_non_url(self):
        bundle = fa.fetch_plugin_git("not-a-url")
        self.assertIsNone(bundle)


class FetchPluginGitHardeningTests(unittest.TestCase):
    """S2: git clone must run with credential prompts disabled and use
    blob:none filtering to limit what attacker-controlled URLs can pull."""

    def test_subprocess_env_disables_auth_prompts(self):
        captured: dict = {}

        def fake_run(cmd, **kw):
            captured["cmd"] = cmd
            captured["env"] = kw.get("env", {})
            raise subprocess.CalledProcessError(128, cmd)

        with patch.object(fa.subprocess, "run", side_effect=fake_run):
            fa.fetch_plugin_git("https://example.invalid/x.git")

        env = captured["env"]
        self.assertEqual(env.get("GIT_TERMINAL_PROMPT"), "0")
        self.assertEqual(env.get("GIT_ASKPASS"), "/bin/true")
        self.assertIn("BatchMode=yes", env.get("GIT_SSH_COMMAND", ""))
        self.assertIn("--filter=blob:none", captured["cmd"])

    def test_clone_argv_uses_dash_dash_separator(self):
        # `--` before positional args defends against future Git versions
        # parsing flag-shaped URLs/refs as options.
        captured: dict = {}

        def fake_run(cmd, **kw):
            captured["cmd"] = cmd
            raise subprocess.CalledProcessError(128, cmd)

        with patch.object(fa.subprocess, "run", side_effect=fake_run):
            fa.fetch_plugin_git("https://github.com/example/repo.git")

        cmd = captured["cmd"]
        self.assertIn("--", cmd)
        dd_idx = cmd.index("--")
        self.assertEqual(cmd[dd_idx + 1], "https://github.com/example/repo.git")


class FetchPluginLocalSymlinkTests(unittest.TestCase):
    """S3: hostile plugin can ship symlinks pointing outside the plugin
    tree. fetch_plugin_local must skip symlinks the way content_hash
    already does."""

    def test_symlink_in_hooks_dir_is_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            # Target file outside the plugin tree, with a token-shaped string.
            secret = tmp_p / "secret.txt"
            secret.write_text("AKIAIOSFODNN7EXAMPLE")

            plugin = tmp_p / "plug"
            (plugin / ".claude-plugin").mkdir(parents=True)
            (plugin / ".claude-plugin" / "plugin.json").write_text(
                json.dumps({"name": "plug", "version": "0.1"})
            )
            (plugin / "hooks").mkdir()
            evil_link = plugin / "hooks" / "leak.sh"
            os.symlink(str(secret), str(evil_link))

            bundle = fa.fetch_plugin_local("plug", str(plugin))
            self.assertIsNotNone(bundle)
            self.assertNotIn("hooks/leak.sh", bundle.files)
            for content in bundle.files.values():
                self.assertNotIn("AKIAIOSFODNN7EXAMPLE", content)

    def test_symlink_manifest_is_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            secret = tmp_p / "fake_manifest.json"
            secret.write_text(json.dumps({"name": "victim", "evil": True}))

            plugin = tmp_p / "plug"
            plugin.mkdir()
            os.symlink(str(secret), str(plugin / "plugin.json"))

            bundle = fa.fetch_plugin_local("plug", str(plugin))
            self.assertIsNotNone(bundle)
            self.assertNotIn("plugin.json", bundle.files)


if __name__ == "__main__":
    unittest.main()