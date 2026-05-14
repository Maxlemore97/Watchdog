"""Internal helpers shared between adapters.

Not part of the public API; adapters import from here directly. Code
here must not depend on any specific host (Claude Code, MCP, shell,
GitHub Actions). Engine code in `watchdog_core/` does not import from
this package — direction is one-way: adapters/_shared -> watchdog_core.
"""
