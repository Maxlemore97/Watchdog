---
description: Run a manual Watchdog security scan of a package or Claude plugin before install.
argument-hint: <pkg@ver | git-url>
allowed-tools: Bash
---

Run the Watchdog analyzer against the target the user supplies in `$ARGUMENTS`.

If `$ARGUMENTS` looks like a git URL (starts with `https://`, `git@`, `ssh://`, or ends in `.git`), treat it as a Claude plugin source.

Otherwise treat it as a package and let the user clarify the ecosystem if not obvious from context (npm / PyPI).

Invoke the analyzer with the existing `WATCHDOG_DISABLE=0` flow disabled (we run it directly here):

```bash
WATCHDOG_DISABLE=1 python3 ${CLAUDE_PLUGIN_ROOT}/adapters/claude_code/entry/manual.py "$ARGUMENTS"
```

Report the JSON verdict to the user. If the verdict is `deny`, explicitly recommend NOT installing. If `ask`, summarize the indicators and ask the user how to proceed. If `allow`, briefly confirm the package looks clean.
