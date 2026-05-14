"""Sanity tests for the mascot UI strings.

Locks in English headlines so a German revert (the project's prior
state) is caught."""
from __future__ import annotations

import io
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from watchdog_core import mascot  # noqa: E402


class HeadlineLanguageTests(unittest.TestCase):
    def test_all_headlines_english(self):
        for ev, headline in mascot._HEADLINES.items():
            self.assertIn("SECURITY CHECK", headline, f"non-english headline for {ev}")

    def test_no_german_substrings(self):
        for headline in mascot._HEADLINES.values():
            for needle in ("SICHERHEIT", "SICHERHEITSCHECK"):
                self.assertNotIn(needle, headline)


class EnableSwitchTests(unittest.TestCase):
    """`show()` is loud (multi-line ASCII art on stderr). CI logs, MCP
    clients, and tests need to silence it without monkey-patching."""

    def _capture(self, env: dict) -> str:
        buf = io.StringIO()
        with patch.dict(os.environ, env, clear=False):
            mascot.show(mascot.EVENT_INTERCEPT, ["sample"], stream=buf)
        return buf.getvalue()

    def test_default_emits_art(self):
        out = self._capture({"WATCHDOG_MASCOT": "1"})
        self.assertIn("SECURITY CHECK", out)

    def test_off_silences(self):
        for val in ("0", "false", "no", "off", "OFF"):
            with self.subTest(val=val):
                self.assertEqual(self._capture({"WATCHDOG_MASCOT": val}), "")


if __name__ == "__main__":
    unittest.main()
