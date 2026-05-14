"""Tests for the multi-LLM provider registry.

Per-provider invocation shape, auto-detect order, env-driven config,
and recursion-guard env propagation. All subprocess calls and
`shutil.which` lookups are mocked so the suite stays offline and host-
agnostic.
"""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from watchdog_core import providers as pv  # noqa: E402


SYS_PROMPT = "system: be terse"


class _FakeProc:
    def __init__(self, returncode=0, stdout='{"verdict":"allow"}', stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _which_only(*names: str):
    name_set = set(names)
    return lambda b: f"/usr/bin/{b}" if b in name_set else None


class ConfigBuildTests(unittest.TestCase):
    def test_defaults_to_provider_defaults(self):
        with patch.dict(os.environ, {}, clear=True):
            cfg = pv.build_config(pv.REGISTRY["claude"], SYS_PROMPT)
        self.assertEqual(cfg.bin, "claude")
        self.assertEqual(cfg.model, pv.REGISTRY["claude"].default_model)
        self.assertEqual(cfg.timeout, pv.DEFAULT_TIMEOUT)
        self.assertTrue(cfg.append_system)

    def test_env_overrides_bin_model_timeout(self):
        env = {
            "WATCHDOG_LLM_BIN": "/opt/custom/claude",
            "WATCHDOG_LLM_MODEL": "claude-sonnet-4-6",
            "WATCHDOG_LLM_TIMEOUT": "12",
        }
        with patch.dict(os.environ, env, clear=True):
            cfg = pv.build_config(pv.REGISTRY["claude"], SYS_PROMPT)
        self.assertEqual(cfg.bin, "/opt/custom/claude")
        self.assertEqual(cfg.model, "claude-sonnet-4-6")
        self.assertEqual(cfg.timeout, 12.0)

    def test_append_system_disabled_via_env(self):
        with patch.dict(os.environ, {"WATCHDOG_LLM_APPEND_SYSTEM": "0"}, clear=True):
            cfg = pv.build_config(pv.REGISTRY["claude"], SYS_PROMPT)
        self.assertFalse(cfg.append_system)

    def test_invalid_timeout_falls_back_to_default(self):
        with patch.dict(os.environ, {"WATCHDOG_LLM_TIMEOUT": "not-a-number"}, clear=True):
            cfg = pv.build_config(pv.REGISTRY["claude"], SYS_PROMPT)
        self.assertEqual(cfg.timeout, pv.DEFAULT_TIMEOUT)


class AutoDetectTests(unittest.TestCase):
    def test_claude_first_when_all_present(self):
        with patch("watchdog_core.providers.shutil.which",
                   side_effect=_which_only("claude", "gemini", "openai", "ollama")):
            prov = pv.auto_detect()
        self.assertIsNotNone(prov)
        self.assertEqual(prov.name, "claude")

    def test_falls_through_to_next_available(self):
        with patch("watchdog_core.providers.shutil.which",
                   side_effect=_which_only("ollama")):
            prov = pv.auto_detect()
        self.assertIsNotNone(prov)
        self.assertEqual(prov.name, "ollama")

    def test_returns_none_when_nothing_on_path(self):
        with patch("watchdog_core.providers.shutil.which", return_value=None):
            self.assertIsNone(pv.auto_detect())

    def test_detection_order_gemini_before_openai(self):
        with patch("watchdog_core.providers.shutil.which",
                   side_effect=_which_only("openai", "gemini")):
            prov = pv.auto_detect()
        self.assertEqual(prov.name, "gemini")


class ResolveProviderTests(unittest.TestCase):
    def test_explicit_provider_pinned(self):
        env = {"WATCHDOG_LLM_PROVIDER": "ollama"}
        with patch.dict(os.environ, env, clear=True), \
             patch("watchdog_core.providers.shutil.which",
                   side_effect=_which_only("ollama", "claude")):
            prov = pv.resolve_provider()
        self.assertEqual(prov.name, "ollama")

    def test_pinned_but_missing_returns_none(self):
        # `claude` pinned, but not installed; do NOT silently auto-detect
        # another model — return None so the analyzer falls back to ask.
        env = {"WATCHDOG_LLM_PROVIDER": "claude"}
        with patch.dict(os.environ, env, clear=True), \
             patch("watchdog_core.providers.shutil.which",
                   side_effect=_which_only("ollama")):
            self.assertIsNone(pv.resolve_provider())

    def test_auto_when_unset(self):
        with patch.dict(os.environ, {}, clear=True), \
             patch("watchdog_core.providers.shutil.which",
                   side_effect=_which_only("gemini")):
            prov = pv.resolve_provider()
        self.assertEqual(prov.name, "gemini")

    def test_invalid_value_falls_back_to_auto(self):
        env = {"WATCHDOG_LLM_PROVIDER": "banana"}
        with patch.dict(os.environ, env, clear=True), \
             patch("watchdog_core.providers.shutil.which",
                   side_effect=_which_only("ollama")):
            prov = pv.resolve_provider()
        self.assertEqual(prov.name, "ollama")

    def test_generic_returned_even_without_bin(self):
        # `generic` resolution does not gate on shutil.which because the
        # actual binary lives inside WATCHDOG_LLM_CMD; the invoke fn
        # validates command runnability.
        env = {"WATCHDOG_LLM_PROVIDER": "generic"}
        with patch.dict(os.environ, env, clear=True):
            prov = pv.resolve_provider()
        self.assertEqual(prov.name, "generic")


class ClaudeInvokeTests(unittest.TestCase):
    def _cfg(self, **overrides):
        base = dict(
            bin="claude",
            model="claude-haiku-4-5-20251001",
            system_prompt=SYS_PROMPT,
            append_system=True,
            timeout=60.0,
            cmd="",
        )
        base.update(overrides)
        return pv.ProviderConfig(**base)

    def test_argv_shape(self):
        captured: dict = {}

        def fake_run(cmd, **kw):
            captured["cmd"] = cmd
            captured["input"] = kw.get("input")
            captured["env"] = kw.get("env", {})
            return _FakeProc()

        with patch("watchdog_core.providers.shutil.which", side_effect=_which_only("claude")), \
             patch("watchdog_core.providers.subprocess.run", side_effect=fake_run):
            out = pv._invoke_claude("user-prompt", self._cfg())

        self.assertEqual(out, '{"verdict":"allow"}')
        self.assertIn("-p", captured["cmd"])
        self.assertIn("--output-format", captured["cmd"])
        self.assertIn("--max-turns", captured["cmd"])
        self.assertIn("--allowed-tools", captured["cmd"])
        self.assertIn("--append-system-prompt", captured["cmd"])
        self.assertEqual(captured["env"].get("WATCHDOG_DISABLE"), "1")
        # Prompt must be stdin, not argv (ARG_MAX safety).
        self.assertEqual(captured["input"], "user-prompt")
        self.assertNotIn("user-prompt", captured["cmd"])

    def test_returns_none_when_cli_missing(self):
        with patch("watchdog_core.providers.shutil.which", return_value=None):
            self.assertIsNone(pv._invoke_claude("hi", self._cfg()))

    def test_skips_append_system_when_disabled(self):
        captured: dict = {}

        def fake_run(cmd, **kw):
            captured["cmd"] = cmd
            return _FakeProc()

        with patch("watchdog_core.providers.shutil.which", side_effect=_which_only("claude")), \
             patch("watchdog_core.providers.subprocess.run", side_effect=fake_run):
            pv._invoke_claude("hi", self._cfg(append_system=False))
        self.assertNotIn("--append-system-prompt", captured["cmd"])


class GeminiInvokeTests(unittest.TestCase):
    def test_prepends_system_via_stdin(self):
        captured: dict = {}

        def fake_run(cmd, **kw):
            captured["cmd"] = cmd
            captured["input"] = kw.get("input")
            return _FakeProc(stdout="raw model response")

        cfg = pv.ProviderConfig(
            bin="gemini",
            model="gemini-2.5-flash",
            system_prompt=SYS_PROMPT,
            append_system=True,
            timeout=30.0,
            cmd="",
        )
        with patch("watchdog_core.providers.shutil.which", side_effect=_which_only("gemini")), \
             patch("watchdog_core.providers.subprocess.run", side_effect=fake_run):
            out = pv._invoke_gemini("user-prompt", cfg)

        self.assertEqual(out, "raw model response")
        self.assertEqual(captured["cmd"][0], "gemini")
        self.assertIn("-m", captured["cmd"])
        self.assertIn("gemini-2.5-flash", captured["cmd"])
        self.assertIn("=== SYSTEM ===", captured["input"])
        self.assertIn(SYS_PROMPT, captured["input"])
        self.assertIn("user-prompt", captured["input"])


class OllamaInvokeTests(unittest.TestCase):
    def test_run_command_shape(self):
        captured: dict = {}

        def fake_run(cmd, **kw):
            captured["cmd"] = cmd
            captured["input"] = kw.get("input")
            captured["env"] = kw.get("env", {})
            return _FakeProc(stdout="ollama out")

        cfg = pv.ProviderConfig(
            bin="ollama", model="llama3.1", system_prompt=SYS_PROMPT,
            append_system=True, timeout=30.0, cmd="",
        )
        with patch("watchdog_core.providers.shutil.which", side_effect=_which_only("ollama")), \
             patch("watchdog_core.providers.subprocess.run", side_effect=fake_run):
            out = pv._invoke_ollama("user-prompt", cfg)
        self.assertEqual(out, "ollama out")
        self.assertEqual(captured["cmd"], ["ollama", "run", "llama3.1"])
        self.assertEqual(captured["env"].get("WATCHDOG_DISABLE"), "1")
        self.assertIn("user-prompt", captured["input"])


class OpenAIInvokeTests(unittest.TestCase):
    def test_chat_completions_argv(self):
        captured: dict = {}

        def fake_run(cmd, **kw):
            captured["cmd"] = cmd
            return _FakeProc(stdout='{"verdict":"allow"}')

        cfg = pv.ProviderConfig(
            bin="openai", model="gpt-4.1-mini", system_prompt=SYS_PROMPT,
            append_system=True, timeout=30.0, cmd="",
        )
        with patch("watchdog_core.providers.shutil.which", side_effect=_which_only("openai")), \
             patch("watchdog_core.providers.subprocess.run", side_effect=fake_run):
            out = pv._invoke_openai("user-prompt", cfg)
        self.assertEqual(out, '{"verdict":"allow"}')
        self.assertEqual(captured["cmd"][:3], ["openai", "api", "chat.completions.create"])
        self.assertIn("user-prompt", captured["cmd"])


class GenericInvokeTests(unittest.TestCase):
    def _cfg(self, cmd: str):
        return pv.ProviderConfig(
            bin="", model="generic", system_prompt=SYS_PROMPT,
            append_system=True, timeout=30.0, cmd=cmd,
        )

    def test_shlex_splits_cmd(self):
        captured: dict = {}

        def fake_run(cmd, **kw):
            captured["cmd"] = cmd
            captured["input"] = kw.get("input")
            return _FakeProc(stdout="generic out")

        with patch("watchdog_core.providers.shutil.which", side_effect=_which_only("mymodel")), \
             patch("watchdog_core.providers.subprocess.run", side_effect=fake_run):
            out = pv._invoke_generic("user-prompt", self._cfg('mymodel --temperature 0 "extra arg"'))
        self.assertEqual(out, "generic out")
        self.assertEqual(captured["cmd"], ["mymodel", "--temperature", "0", "extra arg"])
        self.assertIn("user-prompt", captured["input"])

    def test_returns_none_for_empty_cmd(self):
        self.assertIsNone(pv._invoke_generic("hi", self._cfg("")))

    def test_returns_none_when_first_word_missing(self):
        with patch("watchdog_core.providers.shutil.which", return_value=None):
            self.assertIsNone(pv._invoke_generic("hi", self._cfg("nonexistent --flag")))

    def test_malformed_shell_returns_none(self):
        # Unbalanced quote in WATCHDOG_LLM_CMD must not raise.
        self.assertIsNone(pv._invoke_generic("hi", self._cfg('foo "unbalanced')))


class InvokeLlmDispatchTests(unittest.TestCase):
    def test_returns_tuple_with_provider(self):
        with patch("watchdog_core.providers.shutil.which", side_effect=_which_only("claude")), \
             patch("watchdog_core.providers.subprocess.run",
                   return_value=_FakeProc(stdout='{"verdict":"allow"}')):
            output, provider, cfg = pv.invoke_llm("prompt", SYS_PROMPT)
        self.assertEqual(output, '{"verdict":"allow"}')
        self.assertEqual(provider.name, "claude")
        self.assertEqual(cfg.model, pv.REGISTRY["claude"].default_model)

    def test_returns_nones_when_no_provider(self):
        with patch.dict(os.environ, {}, clear=True), \
             patch("watchdog_core.providers.shutil.which", return_value=None):
            output, provider, cfg = pv.invoke_llm("prompt", SYS_PROMPT)
        self.assertIsNone(output)
        self.assertIsNone(provider)
        self.assertIsNone(cfg)


class CacheKeyProviderInvariantTests(unittest.TestCase):
    """Switching provider or model must invalidate the cache so a weak
    local model cannot whitewash a stale verdict from a stronger one."""

    def test_cache_key_differs_per_provider(self):
        from watchdog_core import analyzer as ca
        with patch.dict(os.environ, {"WATCHDOG_LLM_PROVIDER": "claude"}, clear=True), \
             patch("watchdog_core.providers.shutil.which", side_effect=_which_only("claude")):
            key_claude = ca._cache_key("npm", "lodash", "4.17.21")
        with patch.dict(os.environ, {"WATCHDOG_LLM_PROVIDER": "ollama"}, clear=True), \
             patch("watchdog_core.providers.shutil.which", side_effect=_which_only("ollama")):
            key_ollama = ca._cache_key("npm", "lodash", "4.17.21")
        self.assertNotEqual(key_claude, key_ollama)

    def test_cache_key_differs_per_model(self):
        from watchdog_core import analyzer as ca
        env_a = {"WATCHDOG_LLM_PROVIDER": "claude", "WATCHDOG_LLM_MODEL": "claude-haiku-4-5"}
        env_b = {"WATCHDOG_LLM_PROVIDER": "claude", "WATCHDOG_LLM_MODEL": "claude-sonnet-4-6"}
        with patch.dict(os.environ, env_a, clear=True), \
             patch("watchdog_core.providers.shutil.which", side_effect=_which_only("claude")):
            key_a = ca._cache_key("npm", "lodash", "4.17.21")
        with patch.dict(os.environ, env_b, clear=True), \
             patch("watchdog_core.providers.shutil.which", side_effect=_which_only("claude")):
            key_b = ca._cache_key("npm", "lodash", "4.17.21")
        self.assertNotEqual(key_a, key_b)


if __name__ == "__main__":
    unittest.main()
