"""Severity-ranking tests for the OSV helpers.

The default severity policy must fail safe: an OSV record with no
recognisable severity label and no CVSS score must rank `high`, not
`medium`, so a user raising `MIN_SEVERITY` to `high` still sees it.
"""
from __future__ import annotations

import sys
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from watchdog_core import osv  # noqa: E402
from watchdog_core.types import Package  # noqa: E402


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


class QueryOsvResilienceTests(unittest.TestCase):
    """query_osv must absorb network errors and return `[]` instead of
    raising — it is in the public API and called by adapters whose
    contract is a clean verdict, not a raw URLError."""

    def setUp(self):
        self._env = patch.dict("os.environ", {"WATCHDOG_CACHE_DIR": "/nonexistent-watchdog-test-dir-x9q"})
        self._env.start()
        self.addCleanup(self._env.stop)

    def test_urlerror_returns_empty(self):
        with patch.object(osv.urllib.request, "urlopen",
                          side_effect=urllib.error.URLError("offline")):
            self.assertEqual(osv.query_osv(Package("npm", "lodash", "4.0.0")), [])

    def test_timeout_returns_empty(self):
        with patch.object(osv.urllib.request, "urlopen", side_effect=TimeoutError("slow")):
            self.assertEqual(osv.query_osv(Package("npm", "lodash", "4.0.0")), [])

    def test_oserror_returns_empty(self):
        with patch.object(osv.urllib.request, "urlopen", side_effect=OSError("conn reset")):
            self.assertEqual(osv.query_osv(Package("npm", "lodash", "4.0.0")), [])


class MinSeverityTests(unittest.TestCase):
    """min_severity() must read env on every call so adapters running in
    a long-lived process pick up changes."""

    def test_default_is_low(self):
        with patch.dict("os.environ", {}, clear=False):
            # Ensure no override leaks from outer env
            os_env = patch.dict("os.environ", {})
            os_env.start()
            try:
                if "WATCHDOG_MIN_SEVERITY" in __import__("os").environ:
                    del __import__("os").environ["WATCHDOG_MIN_SEVERITY"]
                self.assertEqual(osv.min_severity(), "low")
            finally:
                os_env.stop()

    def test_env_override(self):
        with patch.dict("os.environ", {"WATCHDOG_MIN_SEVERITY": "HIGH"}):
            self.assertEqual(osv.min_severity(), "high")

    def test_invalid_falls_back_to_low(self):
        with patch.dict("os.environ", {"WATCHDOG_MIN_SEVERITY": "bogus"}):
            self.assertEqual(osv.min_severity(), "low")


if __name__ == "__main__":
    unittest.main()
