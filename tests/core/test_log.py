"""Tests for the opt-in structured-logging helper."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from watchdog_core import log as wlog  # noqa: E402


class LogEventTests(unittest.TestCase):
    def test_no_env_is_noop(self):
        # Should not raise even if path is unset.
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("WATCHDOG_LOG", None)
            wlog.log_event("test", a=1)

    def test_writes_jsonl_when_path_set(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            with patch.dict(os.environ, {"WATCHDOG_LOG": str(path)}):
                wlog.log_event("scan", verdict="allow", pkg="lodash")
                wlog.log_event("scan", verdict="deny", pkg="evil")
            lines = path.read_text().strip().splitlines()
            self.assertEqual(len(lines), 2)
            rec = json.loads(lines[0])
            self.assertEqual(rec["event"], "scan")
            self.assertEqual(rec["verdict"], "allow")
            self.assertIn("ts", rec)
            self.assertIn("pid", rec)

    def test_unwritable_path_swallowed(self):
        # Pointing to a directory (not a file) should not raise.
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(os.environ, {"WATCHDOG_LOG": tmp}):
                wlog.log_event("test", a=1)

    def test_empty_env_treated_as_disabled(self):
        with patch.dict(os.environ, {"WATCHDOG_LOG": "   "}):
            wlog.log_event("test", a=1)


if __name__ == "__main__":
    unittest.main()
