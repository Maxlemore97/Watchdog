"""Severity-ranking tests for the OSV helpers.

The default severity policy must fail safe: an OSV record with no
recognisable severity label and no CVSS score must rank `high`, not
`medium`, so a user raising `MIN_SEVERITY` to `high` still sees it.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from watchdog_core import osv  # noqa: E402


class SeverityRankTests(unittest.TestCase):
    def test_unknown_ranks_high(self):
        self.assertEqual(osv.severity_rank({}), osv.SEVERITY_RANK["high"])

    def test_explicit_label_wins(self):
        v = {"database_specific": {"severity": "critical"}}
        self.assertEqual(osv.severity_rank(v), osv.SEVERITY_RANK["critical"])

    def test_cvss_score_maps_to_rank(self):
        v = {"severity": [{"type": "CVSS_V3", "score": "9.8"}]}
        self.assertEqual(osv.severity_rank(v), osv.SEVERITY_RANK["critical"])

        v = {"severity": [{"type": "CVSS_V3", "score": "5.0"}]}
        self.assertEqual(osv.severity_rank(v), osv.SEVERITY_RANK["medium"])

    def test_unparseable_score_falls_back_to_unknown(self):
        v = {"severity": [{"type": "CVSS_V3", "score": "not-a-number"}]}
        self.assertEqual(osv.severity_rank(v), osv.SEVERITY_RANK["high"])


class FilterBySeverityTests(unittest.TestCase):
    def test_unknown_passes_default_low_threshold(self):
        # MIN_SEVERITY defaults to "low"; unknown ranks "high" so passes.
        vulns = [{"id": "GHSA-x"}]
        self.assertEqual(osv.filter_by_severity(vulns), vulns)


if __name__ == "__main__":
    unittest.main()
