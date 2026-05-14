"""Tests for adapters._shared.preflight.preflight_packages.

Pure-function tests; no network. Mirrors the MCP adapter's
preflight_install behaviour but operates on already-parsed Packages.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from adapters._shared import preflight as pf  # noqa: E402
from watchdog_core.types import Package  # noqa: E402


def _pkg(name="lodash", version="4.17.21", eco="npm"):
    return Package(eco, name, version)


class PreflightPackagesTests(unittest.TestCase):
    def test_empty_returns_allow(self):
        result = pf.preflight_packages([], [])
        self.assertEqual(result["verdict"], "allow")

    def test_notes_only_returns_ask(self):
        result = pf.preflight_packages([], ["requirements file ignored"])
        self.assertEqual(result["verdict"], "ask")
        self.assertIn("requirements file", result["reason"])

    def test_clean_returns_allow(self):
        with patch.object(pf, "query_osv", return_value=[]), \
             patch.object(pf, "analyze_package", return_value=None):
            result = pf.preflight_packages([_pkg()], [], mode="both")
        self.assertEqual(result["verdict"], "allow")
        self.assertEqual(result["findings"], [])

    def test_osv_hit_denies(self):
        vuln = {"id": "GHSA-x", "database_specific": {"severity": "high"}}
        with patch.object(pf, "query_osv", return_value=[vuln]), \
             patch.object(pf, "analyze_package") as ap:
            result = pf.preflight_packages([_pkg()], [], mode="both")
        self.assertEqual(result["verdict"], "deny")
        self.assertIn("GHSA-x", result["reason"])
        ap.assert_not_called()  # OSV deny short-circuits LLM

    def test_claude_only_skips_osv(self):
        with patch.object(pf, "query_osv") as q, \
             patch.object(pf, "analyze_package",
                          return_value={"verdict": "allow", "reason": "ok"}):
            result = pf.preflight_packages([_pkg()], [], mode="claude")
        q.assert_not_called()
        self.assertEqual(result["verdict"], "allow")

    def test_osv_only_skips_claude(self):
        with patch.object(pf, "query_osv", return_value=[]), \
             patch.object(pf, "analyze_package") as ap:
            result = pf.preflight_packages([_pkg()], [], mode="osv")
        ap.assert_not_called()
        self.assertEqual(result["verdict"], "allow")

    def test_invalid_mode_falls_back(self):
        with patch.object(pf, "query_osv", return_value=[]), \
             patch.object(pf, "analyze_package", return_value=None):
            result = pf.preflight_packages([_pkg()], [], mode="banana")
        self.assertEqual(result["mode"], "both")

    def test_offline_decision_on_osv_error(self):
        with patch.object(pf, "query_osv", side_effect=OSError("net")):
            result = pf.preflight_packages([_pkg()], [], mode="osv",
                                           offline_decision="deny")
        self.assertEqual(result["verdict"], "deny")
        self.assertIn("OSV unreachable", result["reason"])

    def test_offline_decision_on_analyzer_error(self):
        with patch.object(pf, "query_osv", return_value=[]), \
             patch.object(pf, "analyze_package", side_effect=RuntimeError("boom")):
            result = pf.preflight_packages([_pkg()], [], mode="claude",
                                           offline_decision="ask")
        self.assertEqual(result["verdict"], "ask")
        self.assertIn("analyzer error", result["reason"])

    def test_worst_verdict_wins_across_packages(self):
        verdicts = iter([
            {"verdict": "allow", "reason": "ok"},
            {"verdict": "deny", "reason": "bad"},
        ])
        with patch.object(pf, "query_osv", return_value=[]), \
             patch.object(pf, "analyze_package", side_effect=lambda *a, **k: next(verdicts)):
            result = pf.preflight_packages(
                [_pkg("a"), _pkg("b")], [], mode="claude"
            )
        self.assertEqual(result["verdict"], "deny")
        self.assertIn("bad", result["reason"])

    def test_findings_include_osv_when_above_threshold(self):
        vuln = {"id": "GHSA-1", "database_specific": {"severity": "high"}}
        with patch.object(pf, "query_osv", return_value=[vuln]), \
             patch.object(pf, "analyze_package"):
            result = pf.preflight_packages([_pkg()], [], mode="both")
        self.assertEqual({f["source"] for f in result["findings"]}, {"osv"})

    def test_findings_include_claude_when_osv_clean(self):
        with patch.object(pf, "query_osv", return_value=[]), \
             patch.object(pf, "analyze_package",
                          return_value={"verdict": "ask", "reason": "weird"}):
            result = pf.preflight_packages([_pkg()], [], mode="both")
        self.assertEqual({f["source"] for f in result["findings"]}, {"claude"})

    def test_result_includes_packages_key(self):
        with patch.object(pf, "query_osv", return_value=[]), \
             patch.object(pf, "analyze_package", return_value=None):
            result = pf.preflight_packages(
                [_pkg("a"), _pkg("b", version=None)], [], mode="both"
            )
        self.assertIn("packages", result)
        self.assertEqual(len(result["packages"]), 2)
        self.assertEqual(result["packages"][0]["name"], "a")
        self.assertIsNone(result["packages"][1]["version"])


class BudgetTests(unittest.TestCase):
    def test_zero_budget_returns_ask(self):
        with patch.object(pf, "query_osv", return_value=[]), \
             patch.object(pf, "analyze_package", return_value=None):
            result = pf.preflight_packages(
                [_pkg("a"), _pkg("b")], [], mode="claude", budget_secs=0.0
            )
        self.assertEqual(result["verdict"], "ask")
        self.assertIn("budget", result["reason"])

    def test_budget_exceeded_midway_returns_ask(self):
        import time as _time

        def slow(*a, **kw):
            _time.sleep(0.05)
            return {"verdict": "allow", "reason": "ok"}

        with patch.object(pf, "query_osv", return_value=[]), \
             patch.object(pf, "analyze_package", side_effect=slow):
            result = pf.preflight_packages(
                [_pkg("a"), _pkg("b"), _pkg("c"), _pkg("d")],
                [], mode="claude", budget_secs=0.06,
            )
        self.assertEqual(result["verdict"], "ask")
        self.assertIn("budget", result["reason"])

    def test_budget_none_does_not_short_circuit(self):
        with patch.object(pf, "query_osv", return_value=[]), \
             patch.object(pf, "analyze_package",
                          return_value={"verdict": "allow", "reason": "ok"}):
            result = pf.preflight_packages(
                [_pkg("a")], [], mode="claude", budget_secs=None
            )
        self.assertEqual(result["verdict"], "allow")


class OsvParallelTests(unittest.TestCase):
    """OSV lookups must run in parallel across packages so N×latency
    does not blow the hook budget."""

    def test_osv_runs_in_parallel(self):
        import time as _time

        def slow(_pkg):
            _time.sleep(0.05)
            return []

        pkgs = [_pkg(name) for name in ("a", "b", "c", "d", "e", "f")]
        with patch.object(pf, "query_osv", side_effect=slow), \
             patch.object(pf, "analyze_package", return_value=None):
            start = _time.monotonic()
            result = pf.preflight_packages(pkgs, [], mode="osv")
            elapsed = _time.monotonic() - start
        self.assertEqual(result["verdict"], "allow")
        # Sequential would be ~0.30s; parallel with 8 workers fits well
        # under 0.20s even on a loaded CI runner.
        self.assertLess(elapsed, 0.20)

    def test_osv_error_still_records_offline_decision(self):
        def boom(pkg):
            if pkg.name == "bad":
                raise OSError("net")
            return []

        with patch.object(pf, "query_osv", side_effect=boom), \
             patch.object(pf, "analyze_package", return_value=None):
            result = pf.preflight_packages(
                [_pkg("good"), _pkg("bad")], [], mode="osv",
                offline_decision="deny",
            )
        self.assertEqual(result["verdict"], "deny")
        self.assertIn("OSV unreachable for npm:bad", result["reason"])


if __name__ == "__main__":
    unittest.main()
