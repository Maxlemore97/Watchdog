"""Unit tests for the MCP adapter's pure-Python tool implementations.

These tests do NOT require the `mcp` SDK to be installed; they exercise
the functions that the FastMCP wrappers delegate to. The wrapper layer
itself is intentionally a one-liner-per-tool and is covered by a
lightweight import smoke test elsewhere.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from adapters.mcp_server import server as mcp_server  # noqa: E402
from watchdog_core.types import Package  # noqa: E402


class PreflightInstallTests(unittest.TestCase):
    def test_no_install_returns_allow(self):
        result = mcp_server.preflight_install("ls -la /tmp")
        self.assertEqual(result["verdict"], "allow")
        self.assertEqual(result["packages"], [])
        self.assertEqual(result["notes"], [])

    def test_unsupported_form_returns_ask(self):
        result = mcp_server.preflight_install("pip install -r requirements.txt")
        self.assertEqual(result["verdict"], "ask")
        self.assertEqual(result["packages"], [])
        self.assertTrue(any("requirements file" in n for n in result["notes"]))

    def test_clean_install_returns_allow(self):
        with patch.object(mcp_server, "query_osv", return_value=[]), \
             patch.object(mcp_server, "analyze_package", return_value=None):
            result = mcp_server.preflight_install("npm install lodash@4.17.21", mode="both")
        self.assertEqual(result["verdict"], "allow")
        self.assertEqual(result["packages"][0]["ecosystem"], "npm")
        self.assertEqual(result["packages"][0]["name"], "lodash")

    def test_osv_hit_returns_deny(self):
        fake_vuln = {
            "id": "GHSA-fake-1",
            "database_specific": {"severity": "high"},
        }
        with patch.object(mcp_server, "query_osv", return_value=[fake_vuln]), \
             patch.object(mcp_server, "analyze_package") as ap:
            result = mcp_server.preflight_install(
                "npm install lodash@4.17.20", mode="both"
            )
        self.assertEqual(result["verdict"], "deny")
        self.assertIn("GHSA-fake-1", result["reason"])
        ap.assert_not_called()  # OSV deny short-circuits Claude

    def test_claude_only_mode_skips_osv(self):
        with patch.object(mcp_server, "query_osv") as q, \
             patch.object(
                 mcp_server, "analyze_package",
                 return_value={"verdict": "allow", "reason": "fine"},
             ):
            result = mcp_server.preflight_install(
                "npm install x", mode="claude"
            )
        q.assert_not_called()
        self.assertEqual(result["verdict"], "allow")

    def test_osv_only_mode_skips_claude(self):
        with patch.object(mcp_server, "query_osv", return_value=[]), \
             patch.object(mcp_server, "analyze_package") as ap:
            result = mcp_server.preflight_install(
                "npm install x", mode="osv"
            )
        ap.assert_not_called()
        self.assertEqual(result["verdict"], "allow")

    def test_invalid_mode_falls_back_to_both(self):
        with patch.object(mcp_server, "query_osv", return_value=[]), \
             patch.object(mcp_server, "analyze_package", return_value=None):
            result = mcp_server.preflight_install("npm install x", mode="banana")
        self.assertEqual(result["mode"], "both")

    def test_subshell_extraction_passes_through(self):
        with patch.object(mcp_server, "query_osv", return_value=[]), \
             patch.object(mcp_server, "analyze_package", return_value=None):
            result = mcp_server.preflight_install("bash -c 'npm install evil@1.0'")
        self.assertEqual(len(result["packages"]), 1)
        self.assertEqual(result["packages"][0]["name"], "evil")

    def test_claude_ask_aggregates_to_ask(self):
        with patch.object(mcp_server, "query_osv", return_value=[]), \
             patch.object(
                 mcp_server, "analyze_package",
                 return_value={"verdict": "ask", "reason": "unsure"},
             ):
            result = mcp_server.preflight_install("npm install x", mode="both")
        self.assertEqual(result["verdict"], "ask")
        self.assertIn("unsure", result["reason"])

    def test_findings_include_osv_hits(self):
        fake_vuln = {"id": "X-1", "database_specific": {"severity": "critical"}}
        with patch.object(mcp_server, "query_osv", return_value=[fake_vuln]), \
             patch.object(mcp_server, "analyze_package"):
            result = mcp_server.preflight_install("npm install pkg@1.0")
        self.assertTrue(any(f["source"] == "osv" for f in result["findings"]))


class ScanPackageTests(unittest.TestCase):
    def test_delegates_to_analyzer(self):
        with patch.object(
            mcp_server, "analyze_package",
            return_value={"verdict": "allow", "reason": "ok"},
        ) as ap:
            result = mcp_server.scan_package("npm", "lodash", "4.17.21")
        ap.assert_called_once_with("npm", "lodash", "4.17.21")
        self.assertEqual(result["verdict"], "allow")

    def test_none_response_becomes_ask(self):
        with patch.object(mcp_server, "analyze_package", return_value=None):
            result = mcp_server.scan_package("npm", "x", None)
        self.assertEqual(result["verdict"], "ask")


class AuditPluginTests(unittest.TestCase):
    def test_git_url_classified_as_plugin(self):
        captured: dict = {}

        def fake_analyze(ecosystem, name, version):
            captured.update({"ecosystem": ecosystem, "name": name, "version": version})
            return {"verdict": "allow", "reason": "ok"}

        with patch.object(mcp_server, "analyze_package", side_effect=fake_analyze):
            mcp_server.audit_plugin("https://github.com/foo/bar")
        self.assertEqual(captured["ecosystem"], "plugin")
        self.assertEqual(captured["name"], "https://github.com/foo/bar")

    def test_name_at_version_split(self):
        captured: dict = {}

        def fake_analyze(ecosystem, name, version):
            captured.update({"ecosystem": ecosystem, "name": name, "version": version})
            return {"verdict": "ask", "reason": "x"}

        with patch.object(mcp_server, "analyze_package", side_effect=fake_analyze):
            mcp_server.audit_plugin("my-plugin@1.2.3")
        self.assertEqual(captured["name"], "my-plugin")
        self.assertEqual(captured["version"], "1.2.3")


class AuditPluginLocalTests(unittest.TestCase):
    def test_delegates_to_local_analyzer(self):
        with patch.object(
            mcp_server, "analyze_local_plugin",
            return_value={"verdict": "deny", "reason": "exfil"},
        ) as ap:
            result = mcp_server.audit_plugin_local("evil", "/tmp/evil")
        ap.assert_called_once_with("evil", "/tmp/evil")
        self.assertEqual(result["verdict"], "deny")


class ListVettedPluginsTests(unittest.TestCase):
    def test_returns_ledger(self):
        fake_ledger = {"version": 1, "entries": {"foo": {"verdict": "allow"}}}
        with patch.object(mcp_server, "load_ledger", return_value=fake_ledger):
            result = mcp_server.list_vetted_plugins()
        self.assertEqual(result, fake_ledger)


class OsvQueryTests(unittest.TestCase):
    def test_returns_vulns_and_filtered(self):
        v = [{"id": "X-1", "database_specific": {"severity": "high"}}]
        with patch.object(mcp_server, "query_osv", return_value=v):
            result = mcp_server.osv_query("npm", "pkg", "1.0")
        self.assertEqual(result["vulns"], v)
        self.assertEqual(len(result["filtered"]), 1)
        self.assertIn("threshold", result)

    def test_exception_becomes_error_field(self):
        with patch.object(mcp_server, "query_osv", side_effect=OSError("boom")):
            result = mcp_server.osv_query("npm", "pkg", None)
        self.assertIn("error", result)
        self.assertEqual(result["vulns"], [])


class BuildAppTests(unittest.TestCase):
    """Verify the FastMCP wrapper layer raises a clear error when the SDK
    is missing and registers tools when it is present."""

    def test_build_app_raises_systemexit_without_sdk(self):
        with patch.dict(sys.modules, {"mcp.server.fastmcp": None}):
            with self.assertRaises(SystemExit) as cm:
                mcp_server._build_app()
            self.assertIn("mcp", str(cm.exception).lower())

    def test_build_app_registers_tools_when_sdk_available(self):
        try:
            import mcp.server.fastmcp  # noqa: F401
        except ImportError:
            self.skipTest("mcp SDK not installed")
        app = mcp_server._build_app()
        self.assertEqual(app.name, "watchdog")


class HelperTests(unittest.TestCase):
    def test_pkg_label_with_version(self):
        p = Package("npm", "lodash", "4.17.21")
        self.assertEqual(mcp_server._pkg_label(p), "npm:lodash@4.17.21")

    def test_pkg_label_without_version(self):
        p = Package("npm", "lodash", None)
        self.assertEqual(mcp_server._pkg_label(p), "npm:lodash")

    def test_package_dict_round_trip(self):
        p = Package("PyPI", "requests", "2.0")
        d = mcp_server._package_dict(p)
        self.assertEqual(d, {"ecosystem": "PyPI", "name": "requests", "version": "2.0"})


if __name__ == "__main__":
    unittest.main()
