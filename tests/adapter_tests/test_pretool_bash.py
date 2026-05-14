"""End-to-end I/O tests for the PreToolUse hook entry.

Drives `pretool_bash.main()` by feeding stdin and capturing stdout.
`preflight_packages` is mocked so the test does not touch network or
the local `claude` CLI.
"""
from __future__ import annotations

import io
import json
import os
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from adapters.claude_code.entry import pretool_bash  # noqa: E402


def _run(payload: dict, env: dict | None = None,
         preflight_return: dict | None = None):
    env = {"WATCHDOG_DISABLE": "0", "WATCHDOG_MASCOT": "0", **(env or {})}
    out = io.StringIO()
    with patch.dict(os.environ, env, clear=False):
        with patch.object(pretool_bash, "preflight_packages",
                          return_value=preflight_return or {}), \
             patch.object(sys, "stdin", io.StringIO(json.dumps(payload))), \
             redirect_stdout(out):
            rc = pretool_bash.main()
    return rc, out.getvalue()


class PreToolBashIOTests(unittest.TestCase):
    def test_non_bash_tool_passes_silently(self):
        rc, out = _run({"tool_name": "Read", "tool_input": {"file_path": "x"}})
        self.assertEqual(rc, 0)
        self.assertEqual(out, "")

    def test_empty_command_passes_silently(self):
        rc, out = _run({"tool_name": "Bash", "tool_input": {"command": ""}})
        self.assertEqual(rc, 0)
        self.assertEqual(out, "")

    def test_disable_env_skips(self):
        rc, out = _run(
            {"tool_name": "Bash", "tool_input": {"command": "npm install lodash"}},
            env={"WATCHDOG_DISABLE": "1"},
        )
        self.assertEqual(rc, 0)
        self.assertEqual(out, "")

    def test_non_install_command_passes_silently(self):
        rc, out = _run({"tool_name": "Bash", "tool_input": {"command": "ls -la"}})
        self.assertEqual(rc, 0)
        self.assertEqual(out, "")

    def test_clean_install_emits_allow(self):
        rc, out = _run(
            {"tool_name": "Bash", "tool_input": {"command": "npm install lodash@4.17.21"}},
            preflight_return={"verdict": "allow", "reason": "clean", "mode": "both",
                              "packages": [], "notes": [], "findings": []},
        )
        self.assertEqual(rc, 0)
        body = json.loads(out)
        self.assertEqual(
            body["hookSpecificOutput"]["permissionDecision"], "allow"
        )
        self.assertIn("clean", body["hookSpecificOutput"]["permissionDecisionReason"])

    def test_deny_emits_deny(self):
        rc, out = _run(
            {"tool_name": "Bash", "tool_input": {"command": "npm install evil@1.0"}},
            preflight_return={"verdict": "deny", "reason": "GHSA-xxxx", "mode": "both",
                              "packages": [], "notes": [], "findings": []},
        )
        self.assertEqual(rc, 0)
        body = json.loads(out)
        self.assertEqual(
            body["hookSpecificOutput"]["permissionDecision"], "deny"
        )
        self.assertIn("GHSA", body["hookSpecificOutput"]["permissionDecisionReason"])

    def test_ask_emits_ask(self):
        rc, out = _run(
            {"tool_name": "Bash", "tool_input": {"command": "npm install x"}},
            preflight_return={"verdict": "ask", "reason": "unsure", "mode": "both",
                              "packages": [], "notes": [], "findings": []},
        )
        body = json.loads(out)
        self.assertEqual(body["hookSpecificOutput"]["permissionDecision"], "ask")

    def test_unsupported_form_falls_through_to_preflight(self):
        # `pip install -r requirements.txt` parses to (pkgs=[], notes=[...]).
        # main() forwards to preflight, which returns ask.
        rc, out = _run(
            {"tool_name": "Bash", "tool_input": {"command": "pip install -r req.txt"}},
            preflight_return={"verdict": "ask", "reason": "unsupported install form: requirements file: req.txt",
                              "mode": "both", "packages": [], "notes": ["requirements file: req.txt"],
                              "findings": []},
        )
        body = json.loads(out)
        self.assertEqual(body["hookSpecificOutput"]["permissionDecision"], "ask")

    def test_malformed_stdin_passes_silently(self):
        env = {"WATCHDOG_DISABLE": "0", "WATCHDOG_MASCOT": "0"}
        out = io.StringIO()
        with patch.dict(os.environ, env, clear=False):
            with patch.object(sys, "stdin", io.StringIO("not-json{{{")), \
                 redirect_stdout(out):
                rc = pretool_bash.main()
        self.assertEqual(rc, 0)
        self.assertEqual(out.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
