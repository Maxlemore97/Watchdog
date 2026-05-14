<div align="center">

# Watchdog

**Pre-install security review for AI-mediated package and plugin installs.**

Single static binary. No Python. Works on Linux, macOS, and Windows.

Host-agnostic. Catches installs from Claude Code, Cursor, Continue, Zed, OpenCode, Aider, Cline, plain shells driven by an agent — anywhere code gets installed on your behalf.

[![Go 1.25+](https://img.shields.io/badge/go-1.25%2B-blue.svg)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-162%20passing-brightgreen.svg)](#testing)
[![Zero runtime deps](https://img.shields.io/badge/runtime%20deps-mcp--go%20only-lightgrey.svg)](#engine)

</div>

---

## Why it exists

AI coding agents now run package managers on your behalf. A single `npm install` issued by an agent — or a plugin that drops a hostile skill into `~/.claude/`, `~/.cursor/`, or wherever your host stores extensions — bypasses every tool you have for source repos. `npm audit`, Snyk, and Dependabot inspect manifest edits in version control. None of them inspect **the moment an agent reaches for the network**.

Watchdog plugs that gap. It intercepts installs at the **agent surface** — wherever an AI tool actually runs a package manager — and runs a two-stage check **before** the install lands:

1. **OSV.dev CVE lookup** — fast, deterministic, cached. Works regardless of which LLM you use.
2. **LLM source review** — pulls a curated subset of the artifact's files and asks the model to flag malicious patterns the CVE feed has not caught yet (typosquats, malicious `postinstall`, obfuscated payloads, credential-stealing skills).

Verdict: `allow`, `ask`, or `deny`. Worst across packages wins. Fail-closed defaults: missing CLI / offline network → `ask`, never silent allow.

> **Scope discipline.** Watchdog targets the agent surface only. If your tool catches manifest edits in PRs, Watchdog is not your replacement — it covers the surface those tools were never designed for.

---

## Install

```bash
# Linux / macOS
curl -fsSL https://raw.githubusercontent.com/Maxlemore97/Watchdog/main/install.sh | sh

# Windows (PowerShell)
iwr -useb https://raw.githubusercontent.com/Maxlemore97/Watchdog/main/install.ps1 | iex

# Or with go install
go install github.com/Maxlemore97/watchdog/cmd/...@latest

# Or grab a tarball from the GitHub Releases page and put the
# binaries on your PATH manually.
```

The installer drops eight binaries into `~/.local/bin` (Linux/macOS) or `%USERPROFILE%\.watchdog\bin` (Windows). After install, two more steps:

```bash
# 1. Install package-manager shims (intercepts every npm/pip/cargo/... install)
watchdog-shim install

# 2. Verify
watchdog-shim doctor
```

`watchdog-shim install` writes wrapper scripts into `~/.watchdog/bin/` and prints the PATH line to add. Put the shim dir **first** on your PATH so installs hit the wrapper before the real binary.

---

## Four surfaces, one engine

```
+------------------------- where installs originate -------------------------+
|                                                                            |
|  Claude Code Bash tool ──┐                                                 |
|  Claude Code /plugin     ├─→ watchdog-pretool / -session / -prompt /       |
|  install                 ┘   -scan        (Claude Code hooks)              |
|                                                                            |
|  MCP-aware host          ──→ watchdog-mcp  (6 stdio tools)                 |
|  (Cursor / Continue / …)                                                   |
|                                                                            |
|  Aider / Cline / plain   ──→ watchdog-shim + -shim-exec  (PATH wrappers)   |
|  agent-driven shell                                                        |
|                                                                            |
|  PR adding a hostile     ──→ watchdog-action  (GitHub Action)              |
|  skill / hook                                                              |
|                                                                            |
+----------------------------------------------------------------------------+
                                  │
                                  ▼
                ┌─────────────────────────────────────────┐
                │  internal/preflight                     │
                │   OSV.dev query  +  LLM source review   │
                │   prefilter      +  verdict aggregation │
                └─────────────────────────────────────────┘
```

| Adapter         | Host                                                              | When to use                                                                            |
|-----------------|-------------------------------------------------------------------|----------------------------------------------------------------------------------------|
| `watchdog-shim` | **Anything that shells out** to a package manager                 | Universal catch-all. OpenCode, Aider, Cline, Cursor terminal, plain shell.             |
| `watchdog-mcp`  | Any MCP-aware host (Cursor, Continue, Zed, custom agents)         | Native integration without writing host glue. Same cache as the other adapters.        |
| `watchdog-pretool`<br/>`-session` / `-prompt` / `-scan` | Claude Code                                  | Tightest integration: PreToolUse hook blocks the install **inside** the agent.         |
| `watchdog-action` | GitHub PRs                                                      | Repos that ship Claude Code plugins/skills publicly.                                   |

All four adapters share `~/.cache/watchdog/`, so a plugin vetted by one is recognised by the rest.

---

## Claude Code plugin

The Claude Code plugin is shipped in this repo. Install it once and the three hooks fire automatically (PreToolUse on Bash, UserPromptSubmit, SessionStart):

```
/plugin install <this-repo>
```

The plugin's hook scripts shell out to the `watchdog-pretool` / `watchdog-session` / `watchdog-prompt` binaries on your PATH. If the binaries are missing the hook scripts exit silently rather than overriding other plugins' decisions — install Watchdog first, then the plugin.

---

## MCP server

`watchdog-mcp` is a stdio MCP server. Six tools:

| Tool                            | What it does                                            |
|---------------------------------|---------------------------------------------------------|
| `watchdog_preflight_install`    | Parse + OSV + (optional) LLM on a full install command  |
| `watchdog_scan_package`         | LLM source review of one published package              |
| `watchdog_audit_plugin`         | Audit a plugin git URL or `name@version`                |
| `watchdog_audit_plugin_local`   | Audit an already-installed plugin directory             |
| `watchdog_list_vetted_plugins`  | Read the persistent vetted-plugins ledger               |
| `watchdog_osv_query`            | Raw OSV.dev query for diagnostics                       |

Configure in your MCP client (Cursor, Continue, Claude Desktop, …):

```json
{
  "mcpServers": {
    "watchdog": { "command": "watchdog-mcp" }
  }
}
```

---

## GitHub Action

For repos that publish Claude Code plugins or skills, the GitHub Action runs `analyze_local_plugin` on every modified plugin root on PR. Annotations land as file-level comments; the job exits non-zero when any plugin is denied (configurable via `WATCHDOG_ACTION_FAIL_ON`).

Workflow snippet:

```yaml
- uses: Maxlemore97/Watchdog@v1  # via install.sh in a setup step
- run: watchdog-action
  env:
    WATCHDOG_ACTION_FAIL_ON: deny
```

---

## Configuration

All knobs are env vars. Sensible defaults; nothing required.

| Env var                         | Default            | What it does                                                  |
|---------------------------------|--------------------|---------------------------------------------------------------|
| `WATCHDOG_MODE`                 | `both`             | `osv` / `claude` / `both`                                     |
| `WATCHDOG_MIN_SEVERITY`         | `low`              | OSV severity floor (`none`/`low`/`medium`/`high`/`critical`)  |
| `WATCHDOG_OFFLINE_DECISION`     | `ask` (hooks) / `deny` (shim) | What to emit when OSV unreachable / LLM CLI missing |
| `WATCHDOG_MAX_PACKAGES`         | `50`               | Above this, return `ask` without scanning                     |
| `WATCHDOG_LLM_PROVIDER`         | `auto`             | `claude` / `gemini` / `openai` / `ollama` / `generic`         |
| `WATCHDOG_LLM_MODEL`            | per-provider       | Override model name                                           |
| `WATCHDOG_LLM_TIMEOUT`          | `60`               | Per-invocation timeout in seconds                             |
| `WATCHDOG_LLM_CMD`              | —                  | When provider=`generic`, the CLI to spawn                     |
| `WATCHDOG_CACHE_DIR`            | `~/.cache/watchdog`| Where verdicts + ledger live                                  |
| `WATCHDOG_CACHE_TTL`            | `3600`             | OSV cache TTL (seconds)                                       |
| `WATCHDOG_LLM_CACHE_TTL`        | `86400`            | LLM-verdict cache TTL (seconds)                               |
| `WATCHDOG_HOOK_BUDGET_SECS`     | `30`               | Wall-clock cap per hook invocation                            |
| `WATCHDOG_SESSION_MAX_SCANS`    | `10`               | Max plugins re-analyzed per SessionStart                      |
| `WATCHDOG_ACTION_FAIL_ON`       | `deny`             | `deny` / `ask` / `never` for GitHub Action exit code          |
| `WATCHDOG_LOG`                  | —                  | If set, JSON-line event log path                              |
| `WATCHDOG_DISABLE`              | —                  | Set to `1` in nested LLM child env to break hook recursion    |

---

## LLM providers

Watchdog shells out to whichever local CLI you have installed. Auto-detect order is `claude → gemini → openai → ollama`. Pin with `WATCHDOG_LLM_PROVIDER`.

| Provider | CLI binary | Default model                          |
|----------|------------|----------------------------------------|
| Claude   | `claude`   | `claude-haiku-4-5-20251001`            |
| Gemini   | `gemini`   | `gemini-2.5-flash`                     |
| OpenAI   | `openai`   | `gpt-4.1-mini`                         |
| Ollama   | `ollama`   | `llama3.1`                             |
| Generic  | `WATCHDOG_LLM_CMD` | user-specified, stdin-piped     |

Verdict cache keys include `(provider, model)`, so switching CLIs invalidates prior verdicts — a weaker model cannot whitewash a verdict cached by a stronger one.

The analyzer only accepts a verdict that is either the model's entire trimmed output as one JSON object, or wrapped in a fenced ```` ```json ```` block. Prose-embedded JSON is ignored — a hostile artifact that the model quotes back in its response cannot smuggle a forged verdict object. Unparseable output falls through to `ask`.

---

## Threat model

See [SECURITY.md](SECURITY.md) for the full threat model and disclosure address.

Highlights:
- **In scope:** prompt injection from fetched artifacts, malicious install commands, supply-chain payloads in published packages, hostile plugin repos, recursive LLM invocation, OSV / registry network failure, DoS via install-command fan-out.
- **Out of scope:** local filesystem integrity (verdict cache poisoning), compromised LLM provider CLIs, SSRF via plugin git URLs.

Report vulnerabilities via GitHub Security Advisories on this repo.

---

## Engine

Core (parser, OSV, fetchers, analyzer, ledger, preflight) is **stdlib only**. The MCP server depends on [`github.com/mark3labs/mcp-go`](https://github.com/mark3labs/mcp-go); pure Watchdog code stays vendorable.

Source layout:

```
cmd/                  thin CLI entry points (each <200 LOC)
  watchdog-pretool/   Claude Code PreToolUse hook
  watchdog-session/   Claude Code SessionStart hook
  watchdog-prompt/    Claude Code UserPromptSubmit hook
  watchdog-scan/      manual /watchdog-scan slash command
  watchdog-mcp/       MCP stdio server (uses mark3labs/mcp-go)
  watchdog-shim/      install/uninstall/status/doctor CLI
  watchdog-shim-exec/ per-call shim dispatcher
  watchdog-action/    GitHub Action entry
internal/
  types/      Package, ArtifactBundle structs
  paths/      cache_dir() resolution
  log/        opt-in JSON-line event log
  policy/     verdict ranking + worst-wins
  osv/        OSV.dev query, severity, version resolution
  parsers/    install command lexer + plugin prompt parser
  fetchers/   per-ecosystem artifact fetch + tar safety
  analyzer/   LLM prompt + prefilter + verdict extraction
  providers/  multi-LLM CLI registry
  ledger/     persistent plugin vetting ledger
  preflight/  shared OSV+LLM aggregator
  shim/       wrapper templates, FindRealBinary
  ghaction/   workflow command emitter, path classifiers
hooks/        Claude Code hook shell scripts (POSIX)
```

---

## Building from source

Requires Go 1.25+ (mcp-go runtime dep floor).

```bash
git clone https://github.com/Maxlemore97/Watchdog
cd Watchdog
go build ./...
go test -race ./...
```

`asdf` users: `.tool-versions` pins Go 1.26.3.

---

## Testing

162 Go test cases. Race-clean. No network.

```bash
go test -race ./...
```

End-to-end smoke verified locally: `npm install lodash` through the `watchdog-pretool` binary returns a real OSV deny with GHSA identifiers; `watchdog-shim install` writes 10 wrappers, status correct, marker baked.

---

## License

[MIT](LICENSE) © Maxlemore97
