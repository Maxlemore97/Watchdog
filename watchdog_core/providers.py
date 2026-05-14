"""LLM provider registry for the source-review analyzer.

Watchdog needs *some* local LLM CLI to perform source analysis on
fetched package/plugin files. This module abstracts that CLI behind a
small Provider protocol so users can plug in whatever model they have
available locally:

- `claude`   — Anthropic Claude Code CLI (`claude -p`)
- `gemini`   — Google Gemini CLI (`gemini`)
- `openai`   — OpenAI CLI (`openai`)
- `ollama`   — local Ollama (`ollama run <model>`)
- `generic`  — any CLI specified via WATCHDOG_LLM_CMD; prompt piped via stdin

Selection precedence:
1. `WATCHDOG_LLM_PROVIDER` env var (claude/gemini/openai/ollama/generic).
2. Auto-detect: first of (claude, gemini, openai, ollama) found on PATH.

`generic` is never auto-selected; it must be explicitly requested.

All providers set `WATCHDOG_DISABLE=1` in the child env so any nested
agent session's hooks short-circuit and do not recursively re-invoke
the analyzer.
"""
from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from typing import Callable, Optional

VALID_PROVIDERS = {"claude", "gemini", "openai", "ollama", "generic"}
AUTO_DETECT_ORDER = ("claude", "gemini", "openai", "ollama")

DEFAULT_TIMEOUT = 60.0


@dataclass(frozen=True)
class Provider:
    name: str
    bin: str
    default_model: str
    invoke: Callable[[str, "ProviderConfig"], Optional[str]]


@dataclass(frozen=True)
class ProviderConfig:
    bin: str
    model: str
    system_prompt: str
    append_system: bool
    timeout: float
    cmd: str  # only used by `generic`


def _child_env() -> dict[str, str]:
    env = os.environ.copy()
    env["WATCHDOG_DISABLE"] = "1"
    return env


def _run(cmd: list[str], stdin: str, timeout: float) -> Optional[str]:
    try:
        proc = subprocess.run(
            cmd,
            input=stdin,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=_child_env(),
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout


# ---------- claude --------------------------------------------------------

def _invoke_claude(prompt: str, cfg: ProviderConfig) -> Optional[str]:
    if not shutil.which(cfg.bin):
        return None
    cmd = [
        cfg.bin,
        "-p",
        "--model",
        cfg.model,
        "--output-format",
        "json",
        "--max-turns",
        "1",
        "--allowed-tools",
        "",
    ]
    if cfg.append_system:
        cmd += ["--append-system-prompt", cfg.system_prompt]
    return _run(cmd, stdin=prompt, timeout=cfg.timeout)


# ---------- gemini --------------------------------------------------------

def _invoke_gemini(prompt: str, cfg: ProviderConfig) -> Optional[str]:
    """Google Gemini CLI. Pipes a combined system+user prompt via stdin
    because the public `gemini` CLI's flag shape has shifted across
    versions; stdin is the stable surface."""
    if not shutil.which(cfg.bin):
        return None
    body = _combine_system_user(prompt, cfg)
    cmd = [cfg.bin, "-m", cfg.model]
    return _run(cmd, stdin=body, timeout=cfg.timeout)


# ---------- openai --------------------------------------------------------

def _invoke_openai(prompt: str, cfg: ProviderConfig) -> Optional[str]:
    """OpenAI CLI. Uses the `openai api chat.completions.create` form
    with system+user messages. Newer CLI variants accept stdin; we use
    explicit message args for deterministic shape."""
    if not shutil.which(cfg.bin):
        return None
    cmd = [
        cfg.bin,
        "api",
        "chat.completions.create",
        "-m",
        cfg.model,
    ]
    if cfg.append_system:
        cmd += ["-g", "system", cfg.system_prompt]
    cmd += ["-g", "user", prompt]
    return _run(cmd, stdin="", timeout=cfg.timeout)


# ---------- ollama --------------------------------------------------------

def _invoke_ollama(prompt: str, cfg: ProviderConfig) -> Optional[str]:
    """Local Ollama. `ollama run <model>` reads user input via stdin
    and emits the model response on stdout."""
    if not shutil.which(cfg.bin):
        return None
    body = _combine_system_user(prompt, cfg)
    cmd = [cfg.bin, "run", cfg.model]
    return _run(cmd, stdin=body, timeout=cfg.timeout)


# ---------- generic -------------------------------------------------------

def _invoke_generic(prompt: str, cfg: ProviderConfig) -> Optional[str]:
    """Run any user-specified CLI via WATCHDOG_LLM_CMD. The command is
    shlex-split (no shell interpolation). System+user prompt is piped
    via stdin; raw stdout is returned for verdict extraction."""
    if not cfg.cmd:
        return None
    try:
        argv = shlex.split(cfg.cmd)
    except ValueError:
        return None
    if not argv or not shutil.which(argv[0]):
        return None
    body = _combine_system_user(prompt, cfg)
    return _run(argv, stdin=body, timeout=cfg.timeout)


# ---------- helpers -------------------------------------------------------

def _combine_system_user(prompt: str, cfg: ProviderConfig) -> str:
    """Prepend the system prompt to the user prompt when the provider
    cannot pass it via a dedicated flag. Section markers help models
    that have no native system-role handling."""
    if not cfg.append_system or not cfg.system_prompt:
        return prompt
    return (
        "=== SYSTEM ===\n"
        f"{cfg.system_prompt}\n"
        "=== USER ===\n"
        f"{prompt}\n"
    )


# ---------- registry & resolution -----------------------------------------

REGISTRY: dict[str, Provider] = {
    "claude": Provider("claude", "claude", "claude-haiku-4-5-20251001", _invoke_claude),
    "gemini": Provider("gemini", "gemini", "gemini-2.5-flash", _invoke_gemini),
    "openai": Provider("openai", "openai", "gpt-4.1-mini", _invoke_openai),
    "ollama": Provider("ollama", "ollama", "llama3.1", _invoke_ollama),
    "generic": Provider("generic", "", "generic", _invoke_generic),
}


def auto_detect() -> Optional[Provider]:
    for name in AUTO_DETECT_ORDER:
        prov = REGISTRY[name]
        if shutil.which(prov.bin):
            return prov
    return None


def resolve_provider() -> Optional[Provider]:
    """Pick a provider per WATCHDOG_LLM_PROVIDER or auto-detect.

    Returns None when no usable provider is available (e.g. provider
    pinned but its CLI missing, or `auto` and nothing on PATH). Caller
    treats None as "LLM step unavailable" and falls back to its
    offline_decision policy."""
    raw = os.environ.get("WATCHDOG_LLM_PROVIDER", "").strip().lower()
    if not raw or raw == "auto":
        return auto_detect()
    if raw not in VALID_PROVIDERS:
        return auto_detect()
    prov = REGISTRY[raw]
    if prov.name == "generic":
        # generic always returns from resolve_provider; the invoke
        # function rejects if WATCHDOG_LLM_CMD is unset/unrunnable.
        return prov
    if not shutil.which(prov.bin):
        return None
    return prov


def build_config(provider: Provider, system_prompt: str) -> ProviderConfig:
    bin_override = os.environ.get("WATCHDOG_LLM_BIN", "").strip()
    model = os.environ.get("WATCHDOG_LLM_MODEL", "").strip() or provider.default_model
    timeout_raw = os.environ.get("WATCHDOG_LLM_TIMEOUT", "").strip()
    try:
        timeout = float(timeout_raw) if timeout_raw else DEFAULT_TIMEOUT
    except ValueError:
        timeout = DEFAULT_TIMEOUT
    append_system = os.environ.get("WATCHDOG_LLM_APPEND_SYSTEM", "1").strip().lower() not in {
        "0",
        "false",
        "no",
        "off",
    }
    cmd = os.environ.get("WATCHDOG_LLM_CMD", "")
    return ProviderConfig(
        bin=bin_override or provider.bin,
        model=model,
        system_prompt=system_prompt,
        append_system=append_system,
        timeout=timeout,
        cmd=cmd,
    )


def invoke_llm(prompt: str, system_prompt: str) -> tuple[Optional[str], Optional[Provider], Optional[ProviderConfig]]:
    """Resolve provider, build config, invoke. Returns (stdout, provider, config).

    Returns (None, None, None) when no provider is available.
    Provider and config are returned even on invocation failure so the
    caller can include them in cache keys and diagnostics."""
    provider = resolve_provider()
    if provider is None:
        return None, None, None
    cfg = build_config(provider, system_prompt)
    output = provider.invoke(prompt, cfg)
    return output, provider, cfg
