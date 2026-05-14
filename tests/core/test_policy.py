"""Tests for verdict aggregation in `watchdog_core.policy`."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from watchdog_core.policy import VERDICT_RANK, rank, worst_verdict  # noqa: E402


class RankTests(unittest.TestCase):
    def test_known_verdicts(self):
        self.assertEqual(rank("allow"), 0)
        self.assertEqual(rank("ask"), 1)
        self.assertEqual(rank("deny"), 2)

    def test_unknown_defaults_to_ask_rank(self):
        self.assertEqual(rank("banana"), 1)
        self.assertEqual(rank(""), 1)

    def test_rank_table_is_total_order(self):
        # allow < ask < deny
        self.assertLess(VERDICT_RANK["allow"], VERDICT_RANK["ask"])
        self.assertLess(VERDICT_RANK["ask"], VERDICT_RANK["deny"])


class WorstVerdictTests(unittest.TestCase):
    def test_empty_iterable_returns_ask(self):
        self.assertEqual(worst_verdict([]), "ask")

    def test_single_value(self):
        self.assertEqual(worst_verdict(["allow"]), "allow")
        self.assertEqual(worst_verdict(["deny"]), "deny")

    def test_deny_beats_ask_beats_allow(self):
        self.assertEqual(worst_verdict(["allow", "ask"]), "ask")
        self.assertEqual(worst_verdict(["ask", "deny"]), "deny")
        self.assertEqual(worst_verdict(["allow", "ask", "deny"]), "deny")

    def test_unknown_collapses_to_ask(self):
        # Unknown ranks as "ask"; an explicit "deny" still wins.
        self.assertEqual(worst_verdict(["banana", "allow"]), "banana")  # banana ranks 1
        self.assertEqual(worst_verdict(["banana", "deny"]), "deny")


if __name__ == "__main__":
    unittest.main()
