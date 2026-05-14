"""Tests for the path_shim adapter: resolver, installer, and shim
dispatch. All filesystem and process effects are isolated to a temp
directory; `os.execv` is patched so no real package manager is invoked.
"""
from __future__ import annotations

import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from adapters.path_shim import installer, resolver, shim  # noqa: E402
from adapters.path_shim import SHIMMED_TOOLS  # noqa: E402


# ---------- resolver ------------------------------------------------------

class FindRealBinaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.shim_dir = self.root / "shim_bin"
        self.real_dir = self.root / "real_bin"
        self.shim_dir.mkdir()
        self.real_dir.mkdir()
        # write fake npm in both
        for d in (self.shim_dir, self.real_dir):
            p = d / "npm"
            p.write_text("#!/bin/sh\necho hi\n")
            p.chmod(0o755)

    def _patched_path(self, *dirs):
        return patch.dict(os.environ, {"PATH": os.pathsep.join(str(d) for d in dirs)})

    def test_skips_excluded_dir(self):
        with self._patched_path(self.shim_dir, self.real_dir):
            real = resolver.find_real_binary("npm", [str(self.shim_dir)])
        self.assertIsNotNone(real)
        self.assertEqual(Path(real).parent.resolve(), self.real_dir.resolve())

    def test_returns_none_when_only_shim_dir(self):
        with self._patched_path(self.shim_dir):
            real = resolver.find_real_binary("npm", [str(self.shim_dir)])
        self.assertIsNone(real)

    def test_ignores_non_executable(self):
        non_exec = self.real_dir / "weird"
        non_exec.write_text("x")  # no chmod +x
        with self._patched_path(self.real_dir):
            self.assertIsNone(resolver.find_real_binary("weird", []))


# ---------- installer -----------------------------------------------------

class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name) / "bin"

    def test_install_writes_executable_shims(self):
        written = installer.install_shims(shim_dir=self.dir)
        self.assertEqual(len(written), len(SHIMMED_TOOLS))
        for tool in SHIMMED_TOOLS:
            p = self.dir / tool
            self.assertTrue(p.is_file(), f"{tool} not written")
            self.assertTrue(os.access(p, os.X_OK), f"{tool} not executable")
            self.assertIn("Watchdog shim", p.read_text())
            self.assertIn(tool, p.read_text())

    def test_install_subset(self):
        written = installer.install_shims(tools=["npm"], shim_dir=self.dir)
        self.assertEqual(len(written), 1)
        self.assertEqual(written[0].name, "npm")
        self.assertFalse((self.dir / "pip").exists())

    def test_no_overwrite_skips_existing(self):
        installer.install_shims(tools=["npm"], shim_dir=self.dir)
        (self.dir / "npm").write_text("CUSTOM")
        written = installer.install_shims(
            tools=["npm"], shim_dir=self.dir, overwrite=False
        )
        self.assertEqual(written, [])
        self.assertEqual((self.dir / "npm").read_text(), "CUSTOM")

    def test_uninstall_removes_only_watchdog_shims(self):
        installer.install_shims(tools=["npm"], shim_dir=self.dir)
        # User-authored binary that happens to share a name
        (self.dir / "pip").write_text("#!/bin/sh\necho user\n")
        (self.dir / "pip").chmod(0o755)
        removed = installer.uninstall_shims(
            tools=["npm", "pip"], shim_dir=self.dir
        )
        self.assertEqual([p.name for p in removed], ["npm"])
        self.assertFalse((self.dir / "npm").exists())
        self.assertTrue((self.dir / "pip").exists())  # untouched

    def test_uninstall_missing_dir_returns_empty(self):
        result = installer.uninstall_shims(shim_dir=self.dir / "nope")
        self.assertEqual(result, [])

    def test_status_reports_installed(self):
        installer.install_shims(tools=["npm"], shim_dir=self.dir)
        info = installer.status(shim_dir=self.dir)
        self.assertTrue(info["npm"])
        self.assertFalse(info["pip"])


# ---------- shim dispatch -------------------------------------------------

class ShimMainTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.real_dir = Path(self.tmp.name) / "real"
        self.shim_dir = Path(self.tmp.name) / "shim"
        self.real_dir.mkdir()
        self.shim_dir.mkdir()
        # fake real npm
        self.real_npm = self.real_dir / "npm"
        self.real_npm.write_text("#!/bin/sh\n")
        self.real_npm.chmod(0o755)
        self.env_patch = patch.dict(os.environ, {
            "PATH": os.pathsep.join([str(self.shim_dir), str(self.real_dir)]),
            "WATCHDOG_SHIM_DIR": str(self.shim_dir),
            "WATCHDOG_MASCOT": "0",
            "WATCHDOG_DISABLE": "0",
        })
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)

    def test_missing_toolname_arg_returns_2(self):
        self.assertEqual(shim.main(["watchdog-shim-exec"]), 2)

    def test_real_binary_missing_returns_127(self):
        with patch.dict(os.environ, {"PATH": str(self.shim_dir)}):
            rc = shim.main(["watchdog-shim-exec", "npm", "install", "x"])
        self.assertEqual(rc, 127)

    def test_disable_passthrough(self):
        with patch.dict(os.environ, {"WATCHDOG_DISABLE": "1"}), \
             patch.object(shim, "preflight_packages") as pf, \
             patch.object(shim.os, "execv") as ex:
            shim.main(["watchdog-shim-exec", "npm", "install", "lodash@4.17.21"])
        pf.assert_not_called()
        ex.assert_called_once()
        self.assertEqual(ex.call_args[0][0], str(self.real_npm.resolve()))

    def test_unshimmed_tool_passthrough(self):
        # Add a fake `ls` to real dir; not in SHIMMED_TOOLS.
        fake = self.real_dir / "ls"
        fake.write_text("#!/bin/sh\n")
        fake.chmod(0o755)
        with patch.object(shim, "preflight_packages") as pf, \
             patch.object(shim.os, "execv") as ex:
            shim.main(["watchdog-shim-exec", "ls", "-la"])
        pf.assert_not_called()
        ex.assert_called_once()

    def test_no_install_passthrough(self):
        with patch.object(shim, "preflight_packages") as pf, \
             patch.object(shim.os, "execv") as ex:
            shim.main(["watchdog-shim-exec", "npm", "test"])
        pf.assert_not_called()
        ex.assert_called_once()

    def test_install_allow_execs(self):
        with patch.object(shim, "preflight_packages",
                          return_value={"verdict": "allow", "reason": "clean"}), \
             patch.object(shim.os, "execv") as ex:
            rc = shim.main(["watchdog-shim-exec", "npm", "install", "lodash"])
        ex.assert_called_once()
        self.assertEqual(ex.call_args[0][1][0], "npm")
        # main() returns 0 (unreachable in real exec, but in test execv is mocked)
        self.assertEqual(rc, 0)

    def test_install_deny_blocks(self):
        with patch.object(shim, "preflight_packages",
                          return_value={"verdict": "deny", "reason": "GHSA-x"}), \
             patch.object(shim.os, "execv") as ex:
            rc = shim.main(["watchdog-shim-exec", "npm", "install", "lodash@4.17.20"])
        ex.assert_not_called()
        self.assertEqual(rc, 1)

    def test_install_ask_no_tty_uses_offline_decision(self):
        with patch.dict(os.environ, {"WATCHDOG_OFFLINE_DECISION": "deny"}), \
             patch.object(shim, "preflight_packages",
                          return_value={"verdict": "ask", "reason": "unsure"}), \
             patch.object(shim.sys.stdin, "isatty", return_value=False), \
             patch.object(shim.os, "execv") as ex:
            rc = shim.main(["watchdog-shim-exec", "npm", "install", "newpkg"])
        ex.assert_not_called()
        self.assertEqual(rc, 1)

    def test_install_ask_offline_allow(self):
        with patch.dict(os.environ, {"WATCHDOG_OFFLINE_DECISION": "allow"}), \
             patch.object(shim, "preflight_packages",
                          return_value={"verdict": "ask", "reason": "unsure"}), \
             patch.object(shim.sys.stdin, "isatty", return_value=False), \
             patch.object(shim.os, "execv") as ex:
            shim.main(["watchdog-shim-exec", "npm", "install", "newpkg"])
        ex.assert_called_once()


# ---------- CLI -----------------------------------------------------------

class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name) / "bin"

    def test_cli_install_then_status_then_uninstall(self):
        from adapters.path_shim import cli
        with redirect_stdout(io.StringIO()):
            rc = cli.main(["install", "--dir", str(self.dir)])
            self.assertEqual(rc, 0)
            self.assertTrue((self.dir / "npm").is_file())

            rc = cli.main(["status", "--dir", str(self.dir)])
            self.assertEqual(rc, 0)

            rc = cli.main(["uninstall", "--dir", str(self.dir)])
            self.assertEqual(rc, 0)
            self.assertFalse((self.dir / "npm").exists())


if __name__ == "__main__":
    unittest.main()
