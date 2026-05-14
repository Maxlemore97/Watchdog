"""Sanity tests for the mascot UI strings.

Locks in English headlines so a German revert (the project's prior
state) is caught."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

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


if __name__ == "__main__":
    unittest.main()
