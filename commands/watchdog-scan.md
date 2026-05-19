---
description: Run a Watchdog OSV + LLM scan on a package, name@version, or git URL
argument-hint: [target]
allowed-tools: Bash
---

Scan `$ARGUMENTS` and show the JSON verdict:

```!
watchdog-scan "$ARGUMENTS"
```

The JSON `results` array contains one entry per ecosystem probed (`npm`, `PyPI`, or `plugin` for a git URL). Each entry carries `ecosystem`, `name`, `version`, and a `verdict` block with `verdict` (`allow` / `ask` / `deny`), `reason`, and any `findings`. Summarize the worst verdict and the reason; if multiple ecosystems were tried, mention which one matched.
