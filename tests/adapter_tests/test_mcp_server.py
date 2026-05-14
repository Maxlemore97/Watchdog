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
from adapters._shared import preflight as shared_preflight  # noqa: E402


class PreflightInstallDelegationTests(unittest.TestCase):
    """After A1, preflight_install is a thin wrapper. We assert it
    delegates to the shared aggregator with the parsed packages and
    the requested mode. The aggregation matrix is tested in
    test_shared_preflight.py."""

    def test_no_install_returns_allow(self):
        result = mcp_server.preflight_install("ls -la /tmp")
        self.assertEqual(result["verdict"], "allow")
        self.assertEqual(result["packages"], [])
        self.assertEqual(result["notes"], [])

    def test_unsupported_form_returns_ask(self):
        result = mcp_server.preflight_install("pip install -r requirements.txt")
        self.assertEqual(result["verdict"], "ask")
        self.assertTrue(any("requirements file" in n for n in result["notes"]))

    def test_delegates_to_preflight_packages(self):
        captured: dict = {}

        def fake(pkgs, notes, mode="both", offline_decision="ask", budget_secs=None):
            captured["pkgs"] = list(pkgs)
            captured["notes"] = list(notes)
            captured["mode"] = mode
            captured["offline_decision"] = offline_decision
            return {"verdict": "allow", "reason": "ok", "mode": mode,
                    "packages": [], "notes": [], "findings": []}

        with patch.object(mcp_server, "preflight_packages", side_effect=fake):
            mcp_server.preflight_install("npm install lodash@4.17.21", mode="claude")
        self.assertEqual(captured["mode"], "claude")
        self.assertEqual(captured["offline_decision"], "ask")
        self.assertEqual(len(captured["pkgs"]), 1)
        self.assertEqual(captured["pkgs"][0].name, "lodash")

    def test_subshell_extraction_passes_through(self):
        with patch.object(shared_preflight, "query_osv", return_value=[]), \
             patch.object(shared_preflight, "analyze_package", return_value=None):
            result = mcp_server.preflight_install("bash -c 'npm install evil@1.0'")
        self.assertEqual(len(result["packages"]), 1)
        self.assertEqual(result["packages"][0]["name"], "evil")


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


if __name__ == "__main__":
    unittest.main()
