# Watchdog

A Claude Code plugin that guards **AI-mediated installs**: it intercepts package and plugin installs that originate inside a Claude Code session — either Claude itself running `npm install` / `pip install` / `cargo add` via the `Bash` tool, or the user typing `/plugin install <target>` in chat — and runs a security review **before** the install happens. It combines a fast OSV vulnerability lookup with an LLM-driven source analysis powered by Claude, so it can catch both known CVEs and brand-new threats (typosquats, malicious post-install hooks, obfuscated payloads) that haven't been disclosed yet.

Out of scope: installs you run directly in your terminal outside a Claude Code session. Watchdog is not a package-manager wrapper — it only fires on tool calls and prompts that pass through Claude Code's hook system.

## What it does

- **PreToolUse hook** on `Bash` — when Claude (or you) tries to run `npm install`, `pip install`, `cargo add`, `gem install`, `composer require`, etc., the hook intercepts the command, identifies the target package(s), and decides whether to allow, ask, or deny.
- **UserPromptSubmit hook** — when you type `/plugin install <target>` or `/plugin marketplace add <git-url>`, the hook fetches the plugin source and runs the analyzer before the prompt reaches Claude.
- **SessionStart hook** — on every new Claude Code session, scans installed plugins under `~/.claude/plugins` (configurable). A persistent ledger at `~/.cache/watchdog/vetted_plugins.json` records the SHA-256 content hash of each plugin's `.claude-plugin/`, `hooks/`, `commands/`, and `skills/` directories. Plugins with an unchanged hash are skipped; new or updated plugins are re-analyzed and a summary is injected as session context. Soft-capped via `WATCHDOG_SESSION_MAX_SCANS` (default 10) to bound first-session latency.
- **`/watchdog-scan <target>`** — manual audit slash command for ad-hoc checks before installing something yourself.

## Pipeline

```
install command
   │
   ▼
[1] parse install (npm / pip / cargo / gem / composer / plugin git)
   │
   ▼
[2] OSV.dev CVE lookup (fast, deterministic, cached 1h)
   │     ├─ hit at or above WATCHDOG_MIN_SEVERITY ──► deny
   │     └─ clean / below threshold
   ▼
[3] fetch artifact (tarball / sdist / gem / zip / git clone)
   │     extract a curated subset of files (max 50KB total, 10KB per file)
   ▼
[4] Claude analyzer (claude -p, model configurable, cached 24h)
   │     wraps untrusted content in <UNTRUSTED> tags
   │     returns strict JSON verdict
   ▼
emit hook decision  →  allow | ask | deny  (+ reason for the user)
```

## Supported ecosystems

| Ecosystem  | Install detection                           | Fetched files                                              | Special flag                 |
|------------|---------------------------------------------|------------------------------------------------------------|------------------------------|
| npm        | `npm/pnpm/yarn install\|i\|add`             | `package.json`, `index.{js,mjs,cjs}`, `README*`            | install/postinstall scripts  |
| PyPI       | `pip/pip3/uv/poetry install\|add`           | `setup.py`, `setup.cfg`, `pyproject.toml`, `__init__.py`   | sdist required (wheel-only ⇒ note) |
| crates.io  | `cargo add\|install`                        | `Cargo.toml`, `build.rs`, `src/lib.rs`, `src/main.rs`      | `has_build_script`           |
| RubyGems   | `gem install`                               | `<name>.gemspec`, `lib/<name>.rb`, `ext/**/extconf.rb`     | `has_native_extension`       |
| Packagist  | `composer require`                          | `composer.json`, `README*`                                 | `has_install_scripts`        |
| plugin git | `/plugin install`, `/plugin marketplace add`| `plugin.json`, `hooks/**`, `commands/**`, `skills/**`      | skill `allowed-tools` + body audit |

## Installation

This is a Claude Code plugin. From a marketplace add it with:

```text
/plugin marketplace add https://github.com/Maxlemore97/Watchdog
/plugin install watchdog
```

Or use the local source directly by pointing your Claude Code config at this repo.

Requirements:
- Python 3.10+
- The `claude` CLI must be on `PATH` (Watchdog shells out to it for analysis). If absent, Watchdog degrades to OSV-only.
- `git` (for cloning plugin sources during analysis).

## Configuration

All configuration is via environment variables. None are required.

| Variable                          | Default                          | Purpose                                                       |
|-----------------------------------|----------------------------------|---------------------------------------------------------------|
| `WATCHDOG_MODE`                   | `both`                           | `osv`, `claude`, or `both` — which checks to run              |
| `WATCHDOG_MODEL`                  | `claude-haiku-4-5-20251001`      | Claude model used by the analyzer                             |
| `WATCHDOG_MIN_SEVERITY`           | `low`                            | OSV threshold: `none` / `low` / `medium` / `high` / `critical`|
| `WATCHDOG_OFFLINE_DECISION`       | `ask`                            | What to do when OSV or Claude is unreachable                  |
| `WATCHDOG_RESOLVE_LATEST`         | `1`                              | Resolve latest version when none specified                    |
| `WATCHDOG_CACHE_DIR`              | `~/.cache/watchdog`              | Cache directory for both OSV and Claude results               |
| `WATCHDOG_CACHE_TTL`              | `3600`                           | OSV cache TTL in seconds                                      |
| `WATCHDOG_CLAUDE_CACHE_TTL`       | `86400`                          | Claude verdict cache TTL in seconds                           |
| `WATCHDOG_CLAUDE_TIMEOUT`         | `60`                             | `claude -p` invocation timeout in seconds                     |
| `WATCHDOG_CLAUDE_BIN`             | `claude`                         | Override the binary name/path for the Claude CLI              |
| `WATCHDOG_APPEND_SYSTEM`          | `1`                              | Set to `0` to skip the `--append-system-prompt` flag          |
| `WATCHDOG_PYTHON`                 | `python3`                        | Python interpreter the hook shim uses                         |
| `WATCHDOG_MASCOT`                 | `1`                              | ASCII police-dog gimmick on stderr. Set `0`/`false`/`no`/`off` to silence |
| `WATCHDOG_DISABLE`                | `0`                              | Internal recursion guard; the analyzer sets this on its child |
| `WATCHDOG_PLUGIN_DIRS`            | `~/.claude/plugins`              | `os.pathsep`-separated list of directories scanned by the SessionStart hook |
| `CLAUDE_PLUGINS_DIR`              | `~/.claude/plugins`              | Single override consulted after `WATCHDOG_PLUGIN_DIRS` (Claude Code convention) |
| `WATCHDOG_SESSION_MAX_SCANS`      | `10`                             | Maximum plugins to analyze per SessionStart event; the rest are deferred |

## Layout

The repository is split into a platform-agnostic engine (`watchdog_core/`)
and per-host adapters (`adapters/<host>/`). Adapters are thin glue: they
translate their host's hook contract into calls on `watchdog_core` and
emit the host's response format. New hosts (MCP, PATH shim, CI) are
expected to live as siblings of `adapters/claude_code/` without touching
the engine.

```
Watchdog/
├── pyproject.toml           # `pip install watchdog-scanner`
├── README.md
├── .claude-plugin/
│   └── plugin.json          # Claude Code manifest; hook paths point at adapters/claude_code/
│
├── watchdog_core/                       # engine, importable library
│   ├── __init__.py                      # public API
│   ├── types.py                         # Package, ArtifactBundle dataclasses
│   ├── parsers.py                       # install-command + plugin-prompt parsing
│   ├── osv.py                           # OSV.dev client + version resolution + severity
│   ├── fetchers.py                      # per-ecosystem source fetchers + plugin git/local
│   ├── analyzer.py                      # claude CLI wrapper + prompt + verdict cache
│   ├── ledger.py                        # plugin content-hash ledger
│   ├── policy.py                        # verdict aggregation helpers
│   └── mascot.py                        # ASCII police-dog UI
│
├── adapters/
│   ├── claude_code/                     # production Claude Code plugin
│   │   ├── hooks/
│   │   │   ├── watchdog-check.sh
│   │   │   ├── plugin-prompt-check.sh
│   │   │   └── session-scan.sh
│   │   ├── commands/
│   │   │   └── watchdog-scan.md
│   │   └── entry/
│   │       ├── pretool_bash.py          # PreToolUse Bash hook
│   │       ├── prompt.py                # UserPromptSubmit /plugin install
│   │       ├── session.py               # SessionStart plugin ledger scan
│   │       └── manual.py                # /watchdog-scan slash command
│   └── mcp_server/                      # MCP server adapter
│       └── server.py                    # FastMCP tools + pure-Python impls
│
└── tests/
    ├── core/                            # engine tests
    │   ├── test_parse.py                # install-command parsing
    │   ├── test_fetch_artifact.py       # fetchers (fully mocked, no network)
    │   ├── test_claude_analyze.py       # analyzer cache, prompt, verdict extraction
    │   └── test_session_scan.py         # ledger, content-hash, discovery
    └── adapter_tests/                   # adapter integration tests
        └── test_mcp_server.py           # MCP tool implementations
```

> Note: the adapter test directory is named `adapter_tests/` (not
> `adapters/`) to avoid shadowing the top-level `adapters/` package
> during `unittest discover`.

### Adapters

#### MCP server — `adapters/mcp_server/`

A Model Context Protocol server that exposes the Watchdog engine as a
set of MCP tools. Runs as a local stdio subprocess started by your
agent host; no daemon, no network listener, no shared service. Lets
any MCP-aware client (Cursor, Continue, Zed AI, custom agents, etc.)
call Watchdog without writing host-specific glue.

Install:

```bash
pip install watchdog-scanner[mcp]
```

Configure in your agent host's MCP settings (Claude Code / Cursor / Continue):

```json
{
  "mcpServers": {
    "watchdog": {
      "command": "watchdog-mcp"
    }
  }
}
```

Exposed tools:

| Tool                              | Purpose                                              |
|-----------------------------------|------------------------------------------------------|
| `watchdog_preflight_install`      | Analyze a shell install command; returns allow/ask/deny |
| `watchdog_scan_package`           | LLM source review of one published package           |
| `watchdog_audit_plugin`           | Audit a Claude plugin (git URL or name@version)      |
| `watchdog_audit_plugin_local`     | Audit an already-installed plugin directory          |
| `watchdog_list_vetted_plugins`    | Read the persistent vetted-plugins ledger            |
| `watchdog_osv_query`              | Raw OSV.dev vulnerability query for diagnostics      |

The MCP adapter and the Claude Code adapter share the same `~/.cache/watchdog/`
state, so plugins vetted via one are recognized by the other.

### Planned adapters

- `adapters/path_shim/` — PATH-prepend wrapper for package-manager
  binaries (`npm`, `pip`, `cargo`, ...). Agent- and host-agnostic;
  covers installs from terminals and from agents that don't expose
  hooks.
- `adapters/pre_commit/`, `adapters/github_action/` — CI integrations
  for blocking unsafe installs at commit/PR time.

All planned adapters reuse `watchdog_core` as-is, no engine changes.

## Using the engine directly

If you're building your own agent or tooling, you can use the engine as
a regular Python library without going through any adapter:

```python
from watchdog_core import (
    collect_packages,            # parse a shell install command
    query_osv, resolve_version,  # OSV.dev lookups
    analyze_package,             # LLM source review
    analyze_local_plugin,        # local plugin directory audit
    discover_plugins,            # scan ~/.claude/plugins
    load_ledger, save_ledger,    # persistent vetted-plugins ledger
    worst_verdict,               # verdict aggregation
)

pkgs, notes = collect_packages("npm install lodash@4.17.20")
for pkg in pkgs:
    print(query_osv(pkg))
```

Install with `pip install watchdog-scanner`. No dependencies beyond the
Python standard library; the `[mcp]` extra adds the MCP SDK only if you
need to run the MCP server.

## Security model

- **Skill-aware analysis.** `skills/` directories are bundled into the LLM review for both `/plugin install` and SessionStart scans, and contribute to the content hash so any later modification triggers a re-scan. The analyzer system prompt explicitly briefs Claude on skill-specific exfiltration patterns: bodies that read `.env` / `~/.aws/` / `~/.ssh/` / `~/.npmrc`, `allowed-tools` frontmatter granting `Bash`/`Read`/`*` paired with secret-shaped greps (`AKIA*`, `ghp_*`, `sk-*`, JWT, PEM blocks), `printenv | curl …` style egress, and write-time persistence into `~/.claude/`.
- **Prompt injection defense.** All extracted file contents are wrapped in `<UNTRUSTED kind="..." path="...">` tags and the system prompt explicitly instructs Claude to treat them as data, never as instructions.
- **Recursion guard.** When the analyzer invokes `claude -p`, it sets `WATCHDOG_DISABLE=1` in the child environment so the nested session's hooks short-circuit and do not re-trigger the analyzer.
- **Bounded input.** Per-file cap is 10KB; total prompt bundle is capped at 50KB. Large or zip-bomb-style archives cannot exhaust tokens.
- **Bounded I/O.** All HTTP requests have a 10s timeout; `git clone` has a 20s timeout; downloads are capped at 5MB.
- **Fail closed (configurable).** When OSV or Claude is unreachable, the default is to emit `ask` so the human decides instead of silently allowing.

## Verdicts

The analyzer returns one of:

- `allow` — clean: no OSV CVEs (or below threshold) and no Claude red flags.
- `deny` — concrete malicious indicators (OSV hit at or above threshold, or Claude flagged definitive evidence).
- `ask` — suspicious but inconclusive, or analyzer unavailable. The user gets the indicators and decides.

OSV finds short-circuit before Claude runs in mode `both` if they are at or above the configured threshold. Otherwise Claude has the final say.

## Examples

Block an install of a known-vulnerable lodash version:

```text
$ npm install lodash@4.17.20
# Watchdog emits: deny, reason: "vulnerable packages (>= low): npm:lodash@4.17.20 -> GHSA-...[high], ..."
```

Allow a clean install after Claude review:

```text
$ npm install lodash@4.17.21
# Watchdog emits: allow, reason: "[claude] npm:lodash@4.17.21: Legitimate lodash package by original author, no scripts, no suspicious code or network calls."
```

Manual audit of a candidate plugin before installing:

```text
/watchdog-scan https://github.com/some/claude-plugin
```

Use Watchdog from a non-Claude-Code agent via MCP (Cursor, Continue,
custom):

```text
# In the agent: invoke the Watchdog MCP tool
> tool: watchdog_preflight_install
> arg:  command="npm install lodash@4.17.20"
< {"verdict":"deny","reason":"GHSA-...","packages":[...]}
```

## Testing

```bash
python3 -m unittest discover -s tests
```

The full test suite (140 tests) runs in under a second with **zero
network calls** — every external dependency (OSV, npm registry, PyPI,
crates.io, RubyGems, Packagist, git, `claude` CLI, MCP SDK) is mocked
or gracefully skipped when absent.

## Limitations

- The UserPromptSubmit interceptor matches `/plugin install <target>` and `/plugin marketplace add <url>` patterns. If a future Claude Code UI flow installs plugins without surfacing one of those prompts, the interceptor won't see it. Fall back to `/watchdog-scan` in that case.
- Wheel-only PyPI packages cannot be source-analyzed; the analyzer falls back to metadata-only reasoning.
- The Claude verdict is non-deterministic. Cache TTL is 24h by default; clear `~/.cache/watchdog` to force re-analysis.
- OSV.dev coverage and the GHSA severity labels are only as good as the underlying advisories. Watchdog flags `severity=medium` for vulns with no labelled severity (configurable via the `UNKNOWN_SEVERITY_RANK` constant).