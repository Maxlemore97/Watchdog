---
description: Run a Watchdog OSV + LLM scan on a package, name@version, git URL, or project directory
argument-hint: [target | project DIR]
allowed-tools: Bash
---

Scan `$ARGUMENTS` and show the JSON verdict:

```!
watchdog-scan $ARGUMENTS
```

Two modes:

- **Single target** — `name`, `name@version`, or a git URL. The JSON `results` array carries one entry per ecosystem probed (`npm`, `PyPI`, or `plugin` for a git URL); each entry has `ecosystem`, `name`, `version`, and a `verdict` block (`verdict` ∈ `allow` / `ask` / `deny`, `reason`, `findings`). Summarize the worst verdict and which ecosystem it came from.
- **Project walk** — `project [DIR]` (DIR defaults to the cwd). Discovers lockfiles (`package-lock.json`, `pnpm-lock.yaml`, `Pipfile.lock`, `poetry.lock`, `uv.lock`, `Cargo.lock`, `Gemfile.lock`, `composer.lock`, `go.mod`, `packages.lock.json`) plus agent-extension roots (`.claude-plugin/`, `skills/`, `commands/`, `hooks/`, `CLAUDE.md`, `agents.md`), then runs the same OSV + analyzer pipeline against everything found. The result has `packages` and `plugins` blocks each with a sub-verdict; the top-level `verdict` is the worst of the two. Lockfile parse notes and walker notes land in the `notes` field. Flags: `--depth N`, `--skip-gitignored`, `--packages-only`, `--plugins-only`, `--format json|text`, `--budget-secs N`, `--mode osv|claude|both`, `--max-packages N` (default 500 for explicit project scans — the install-time hook keeps the lower 50-package cap so a runaway `npm install` still fails fast).
