"""End-to-end I/O tests for the UserPromptSubmit hook entry."""
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

from adapters.claude_code.entry import prompt as prompt_mod  # noqa: E402


def _run(prompt_text: str, analyzer_return=None, env: dict | None = None):
    env = {"WATCHDOG_DISABLE": "0", "WATCHDOG_MASCOT": "0", **(env or {})}
    payload = {"prompt": prompt_text}
    out = io.StringIO()
    with patch.dict(os.environ, env, clear=False):
        with patch.object(prompt_mod, "analyze_package", return_value=analyzer_return), \
             patch.object(sys, "stdin", io.StringIO(json.dumps(payload))), \
             redirect_stdout(out):
            rc = prompt_mod.main()
    return rc, out.getvalue()


class PromptHookTests(unittest.TestCase):
    def test_no_plugin_command_passes_silently(self):
        rc, out = _run("hello world")
        self.assertEqual(rc, 0)
        self.assertEqual(out, "")

    def test_disable_env_skips(self):
        rc, out = _run("/plugin install https://x/y.git", env={"WATCHDOG_DISABLE": "1"})
        self.assertEqual(rc, 0)
        self.assertEqual(out, "")

    def test_deny_emits_block_decision(self):
        rc, out = _run(
            "/plugin install https://github.com/foo/evil.git",
            analyzer_return={"verdict": "deny", "risk": "high", "reason": "exfil"},
        )
        body = json.loads(out)
        self.assertEqual(body["decision"], "block")
        self.assertIn("exfil", body["reason"])

    def test_ask_emits_additional_context(self):
        rc, out = _run(
            "/plugin install https://github.com/foo/grey.git",
            analyzer_return={"verdict": "ask", "risk": "medium", "reason": "broad tools"},
        )
        body = json.loads(out)
        self.assertNotIn("decision", body)
        self.assertIn("additionalContext", body["hookSpecificOutput"])
        self.assertIn("broad tools", body["hookSpecificOutput"]["additionalContext"])

    def test_allow_emits_additional_context_no_decision(self):
        rc, out = _run(
            "/plugin install https://github.com/foo/good.git",
            analyzer_return={"verdict": "allow", "risk": "low", "reason": "clean"},
        )
        body = json.loads(out)
        self.assertNotIn("decision", body)
        self.assertIn("clean", body["hookSpecificOutput"]["additionalContext"])

    def test_analyzer_unavailable_emits_context(self):
        rc, out = _run(
            "/plugin install https://github.com/foo/x.git",
            analyzer_return=None,
        )
        body = json.loads(out)
        self.assertIn("analyzer unavailable", body["hookSpecificOutput"]["additionalContext"])


if __name__ == "__main__":
    unittest.main()
