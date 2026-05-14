"""End-to-end I/O tests for the SessionStart hook entry."""
from __future__ import annotations

import importlib
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def _load_module():
    from adapters.claude_code.entry import session
    return importlib.reload(session)


def _make_plugin(root: Path, name: str) -> Path:
    pdir = root / name
    (pdir / ".claude-plugin").mkdir(parents=True)
    (pdir / ".claude-plugin" / "plugin.json").write_text(
        json.dumps({"name": name, "version": "0.1.0"})
    )
    (pdir / "hooks").mkdir()
    (pdir / "hooks" / "x.sh").write_text("#!/bin/sh\n")
    return pdir


class SessionHookTests(unittest.TestCase):
    def test_no_plugins_passes_silently(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = {"WATCHDOG_PLUGIN_DIRS": tmp, "WATCHDOG_DISABLE": "0",
                   "WATCHDOG_MASCOT": "0"}
            out = io.StringIO()
            with patch.dict(os.environ, env, clear=False):
                mod = _load_module()
                with patch.object(sys, "stdin", io.StringIO("{}")), \
                     redirect_stdout(out):
                    rc = mod.main()
            self.assertEqual(rc, 0)
            self.assertEqual(out.getvalue(), "")

    def test_findings_emit_additional_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            _make_plugin(tmp_p, "alpha")
            env = {
                "WATCHDOG_PLUGIN_DIRS": str(tmp_p),
                "WATCHDOG_CACHE_DIR": str(tmp_p / "cache"),
                "WATCHDOG_DISABLE": "0",
                "WATCHDOG_MASCOT": "0",
            }
            out = io.StringIO()
            with patch.dict(os.environ, env, clear=False):
                mod = _load_module()
                # scan_plugins default analyzer is bound at def-time; replace
                # the wrapped call with a stub that returns deterministic
                # findings, no LLM, no network.
                def fake_scan(plugins, ledger, analyzer=None, max_scans=None):
                    findings = [("alpha", {"verdict": "deny", "risk": "high", "reason": "bad"})]
                    return findings, True, 0
                with patch.object(mod, "scan_plugins", side_effect=fake_scan), \
                     patch.object(sys, "stdin", io.StringIO("{}")), \
                     redirect_stdout(out):
                    rc = mod.main()
            self.assertEqual(rc, 0)
            body = json.loads(out.getvalue())
            ctx = body["hookSpecificOutput"]["additionalContext"]
            self.assertIn("alpha", ctx)
            self.assertIn("deny", ctx)

    def test_disable_env_skips(self):
        env = {"WATCHDOG_DISABLE": "1", "WATCHDOG_MASCOT": "0"}
        out = io.StringIO()
        with patch.dict(os.environ, env, clear=False):
            mod = _load_module()
            with patch.object(sys, "stdin", io.StringIO("{}")), \
                 redirect_stdout(out):
                rc = mod.main()
        self.assertEqual(rc, 0)
        self.assertEqual(out.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
