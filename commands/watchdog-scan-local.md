---
description: Scan every locally installed Claude Code plugin and report the worst verdict
argument-hint: []
allowed-tools: Bash
---

Scan local plugins and show the JSON verdict:

```!
watchdog-scan local
```

Auto-discovers plugin roots in this order: every entry in `WATCHDOG_PLUGIN_DIRS` (`:` / `;` separated), then `CLAUDE_PLUGINS_DIR`, then `~/.claude/plugins/`. Only directories that actually exist are walked. Each discovered plugin (directory containing `plugin.json` or `.claude-plugin/plugin.json`) is fed through the same content-addressed analyzer cache the install-time path uses, so repeat scans are near-instant when nothing changed on disk.

The JSON output has the same shape as `watchdog-scan project`: top-level `verdict` (worst across all plugins), `plugins` block with per-plugin `findings`, and `notes` listing the scanned roots. Summarize the worst verdict, mention the plugin name and reason if it's `ask` or `deny`, and surface the scanned-roots note so the user knows which directories were covered. If `scanned: 0`, point the user at `WATCHDOG_PLUGIN_DIRS` or `~/.claude/plugins/` as places to put plugin trees.
