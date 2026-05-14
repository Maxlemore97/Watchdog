"""Tests for the github_action adapter.

Filesystem and `git` invocations are isolated to a temp dir; the
analyzer is patched so no `claude` CLI is required.
"""
from __future__ import annotations

import io
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from adapters.github_action import annotations, entry  # noqa: E402


# ---------- annotations --------------------------------------------------

class AnnotationFormatTests(unittest.TestCase):
    def _capture(self, fn, *args, **kw):
        buf = io.StringIO()
        with redirect_stdout(buf):
            fn(*args, **kw)
        return buf.getvalue()

    def test_error_emits_workflow_command(self):
        out = self._capture(annotations.error, "boom", file="a.md", line=3)
        self.assertEqual(out, "::error file=a.md,line=3::boom\n")

    def test_warning_and_notice(self):
        self.assertTrue(self._capture(annotations.warning, "x").startswith("::warning"))
        self.assertTrue(self._capture(annotations.notice, "x").startswith("::notice"))

    def test_message_escapes_newlines_and_percent(self):
        out = self._capture(annotations.error, "a\nb%c\rd", file="x.md")
        self.assertIn("a%0Ab%25c%0Dd", out)

    def test_property_escapes_comma(self):
        out = self._capture(annotations.error, "msg", file="a,b.md")
        self.assertIn("file=a%2Cb.md", out)

    def test_no_file_omits_props(self):
        out = self._capture(annotations.error, "msg")
        self.assertEqual(out, "::error::msg\n")


# ---------- glob / grouping ----------------------------------------------

class IsPluginAssetTests(unittest.TestCase):
    def test_claude_plugin_dir(self):
        self.assertTrue(entry.is_plugin_asset("foo/.claude-plugin/plugin.json"))
        self.assertTrue(entry.is_plugin_asset(".claude-plugin/plugin.json"))

    def test_skill_only_skill_md(self):
        self.assertTrue(entry.is_plugin_asset("plug/skills/x/SKILL.md"))
        self.assertFalse(entry.is_plugin_asset("plug/skills/x/other.md"))
        self.assertFalse(entry.is_plugin_asset("plug/skills/x/script.py"))

    def test_command_only_md(self):
        self.assertTrue(entry.is_plugin_asset("plug/commands/foo.md"))
        self.assertFalse(entry.is_plugin_asset("plug/commands/foo.txt"))

    def test_hooks_anything(self):
        self.assertTrue(entry.is_plugin_asset("plug/hooks/check.sh"))
        self.assertTrue(entry.is_plugin_asset("plug/hooks/sub/foo.py"))

    def test_unrelated_paths_ignored(self):
        self.assertFalse(entry.is_plugin_asset("README.md"))
        self.assertFalse(entry.is_plugin_asset("src/main.py"))
        self.assertFalse(entry.is_plugin_asset("commands.md"))  # not under commands/


class PluginRootTests(unittest.TestCase):
    def test_nested_plugin_root(self):
        self.assertEqual(
            entry.plugin_root_for("plugins/foo/.claude-plugin/plugin.json"),
            "plugins/foo",
        )

    def test_repo_root_plugin(self):
        self.assertEqual(entry.plugin_root_for(".claude-plugin/plugin.json"), "")
        self.assertEqual(entry.plugin_root_for("hooks/check.sh"), "")

    def test_grouping(self):
        files = [
            "plugins/a/.claude-plugin/plugin.json",
            "plugins/a/skills/x/SKILL.md",
            "plugins/b/commands/foo.md",
            "src/unrelated.py",
            "plugins/a/skills/x/notes.md",  # filtered by is_plugin_asset
        ]
        grouped = entry.group_by_plugin(files)
        self.assertEqual(set(grouped.keys()), {"plugins/a", "plugins/b"})
        self.assertEqual(len(grouped["plugins/a"]), 2)


# ---------- git diff -----------------------------------------------------

class ChangedFilesTests(unittest.TestCase):
    def test_returns_split_lines(self):
        with patch.object(
            subprocess,
            "check_output",
            return_value="a.md\nb.md\n",
        ):
            result = entry.changed_files("main", "HEAD", Path("/tmp"))
        self.assertEqual(result, ["a.md", "b.md"])

    def test_falls_back_to_local_base(self):
        calls: list[list[str]] = []

        def fake(*args, **kw):
            calls.append(args[0])
            if "origin/main..." in args[0][-1]:
                raise subprocess.CalledProcessError(128, args[0])
            return "x.md\n"

        with patch.object(subprocess, "check_output", side_effect=fake):
            result = entry.changed_files("main", "HEAD", Path("/tmp"))
        self.assertEqual(result, ["x.md"])
        self.assertEqual(len(calls), 2)

    def test_git_missing_returns_empty(self):
        with patch.object(subprocess, "check_output", side_effect=FileNotFoundError):
            result = entry.changed_files("main", "HEAD", Path("/tmp"))
        self.assertEqual(result, [])


# ---------- run ----------------------------------------------------------

class RunTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.workspace = Path(self.tmp.name)
        # create plugin dir on disk so analyze_local_plugin path exists
        (self.workspace / "plugins" / "good" / ".claude-plugin").mkdir(parents=True)
        (self.workspace / "plugins" / "bad" / "skills" / "x").mkdir(parents=True)

    def _run(self, files, verdicts, fail_on="deny"):
        verdict_iter = iter(verdicts)

        def fake_analyze(name, path, content_hash=None):
            return next(verdict_iter)

        out = io.StringIO()
        with patch.object(entry, "changed_files", return_value=files), \
             patch.object(entry, "analyze_local_plugin", side_effect=fake_analyze), \
             redirect_stdout(out):
            rc = entry.run(workspace=self.workspace, fail_on=fail_on)
        return rc, out.getvalue()

    def test_no_assets_emits_notice_and_passes(self):
        rc, out = self._run(["src/main.py", "README.md"], [])
        self.assertEqual(rc, 0)
        self.assertIn("::notice", out)
        self.assertIn("No Claude plugin assets", out)

    def test_allow_emits_notice_zero_exit(self):
        rc, out = self._run(
            ["plugins/good/.claude-plugin/plugin.json"],
            [{"verdict": "allow", "reason": "clean"}],
        )
        self.assertEqual(rc, 0)
        self.assertIn("::notice", out)
        self.assertIn("plugins/good/.claude-plugin/plugin.json", out)

    def test_deny_emits_error_nonzero_exit(self):
        rc, out = self._run(
            ["plugins/bad/skills/x/SKILL.md"],
            [{"verdict": "deny", "reason": "exfil .env"}],
        )
        self.assertEqual(rc, 1)
        self.assertIn("::error", out)
        self.assertIn("exfil", out)

    def test_ask_with_default_fail_on_passes(self):
        # default fail_on=deny, ask alone should not fail the job
        rc, out = self._run(
            ["plugins/good/.claude-plugin/plugin.json"],
            [{"verdict": "ask", "reason": "unsure"}],
        )
        self.assertEqual(rc, 0)
        self.assertIn("::warning", out)

    def test_fail_on_ask_promotes_ask_to_failure(self):
        rc, _ = self._run(
            ["plugins/good/.claude-plugin/plugin.json"],
            [{"verdict": "ask", "reason": "unsure"}],
            fail_on="ask",
        )
        self.assertEqual(rc, 1)

    def test_fail_on_never_always_passes(self):
        rc, _ = self._run(
            ["plugins/bad/skills/x/SKILL.md"],
            [{"verdict": "deny", "reason": "bad"}],
            fail_on="never",
        )
        self.assertEqual(rc, 0)

    def test_worst_verdict_across_plugins(self):
        rc, _ = self._run(
            [
                "plugins/good/.claude-plugin/plugin.json",
                "plugins/bad/skills/x/SKILL.md",
            ],
            [
                {"verdict": "allow", "reason": "ok"},
                {"verdict": "deny", "reason": "bad"},
            ],
        )
        self.assertEqual(rc, 1)

    def test_analyzer_none_treated_as_ask(self):
        rc, out = self._run(
            ["plugins/good/.claude-plugin/plugin.json"],
            [None],
            fail_on="ask",
        )
        self.assertEqual(rc, 1)
        self.assertIn("no result", out)


class HelperTests(unittest.TestCase):
    def test_plugin_name_from_root(self):
        self.assertEqual(entry._plugin_name("plugins/foo"), "foo")

    def test_plugin_name_from_repo_env(self):
        with patch.dict(os.environ, {"GITHUB_REPOSITORY": "owner/myrepo"}):
            self.assertEqual(entry._plugin_name(""), "myrepo")

    def test_plugin_name_fallback(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("GITHUB_REPOSITORY", None)
            self.assertEqual(entry._plugin_name(""), "repo-root-plugin")

    def test_fail_on_normalises_invalid(self):
        with patch.dict(os.environ, {"WATCHDOG_ACTION_FAIL_ON": "banana"}):
            self.assertEqual(entry._fail_on(), "deny")


if __name__ == "__main__":
    unittest.main()
