# Watchdog GitHub Action

Audits pull requests that add or modify Claude Code plugin assets:

- `**/.claude-plugin/**`
- `**/skills/**/SKILL.md`
- `**/commands/**.md`
- `**/hooks/**`

Each touched plugin root is passed to `watchdog_core.analyze_local_plugin`
and the verdict is surfaced as a GitHub workflow annotation on the
changed files. Use this in repositories that ship Claude plugins or
skills to catch malicious additions at PR review time.

This adapter is **not** a generic dependency scanner. Watchdog
deliberately does not duplicate Dependabot / Snyk / `npm audit` /
`pip-audit`.

## Usage

```yaml
name: Watchdog
on:
  pull_request:
    paths:
      - '**/.claude-plugin/**'
      - '**/skills/**'
      - '**/commands/**.md'
      - '**/hooks/**'
permissions:
  contents: read
  pull-requests: read
jobs:
  watchdog:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: Maxlemore97/Watchdog/adapters/github_action@v0.4.0
        with:
          fail-on: deny
```

## Inputs

| Input            | Default                          | Purpose                                          |
|------------------|----------------------------------|--------------------------------------------------|
| `fail-on`        | `deny`                           | Job fails if worst verdict ≥ this. Use `ask` to fail on uncertain, `never` to only annotate. |
| `model`          | `claude-haiku-4-5-20251001`      | Claude model used by the analyzer.               |
| `base-ref`       | (auto)                           | Override the base ref for the diff.              |
| `python-version` | `3.11`                           | Python used to run the analyzer.                 |

## Notes

- The analyzer needs the `claude` CLI on the runner. The default
  setup-python step does not install it; if you want full LLM review,
  add a step that installs and authenticates the Claude CLI before this
  action. Without `claude`, the analyzer degrades gracefully.
- Annotations use `::error::`, `::warning::`, `::notice::` based on the
  verdict (`deny` / `ask` / `allow`).
