"""GitHub Action adapter — narrow plugin/skill PR review.

Scans a pull request for new or modified files belonging to Claude
Code plugin assets (`.claude-plugin/`, `skills/`, `commands/`,
`hooks/`) and runs `watchdog_core.analyze_local_plugin` on the
containing plugin roots. Emits GitHub workflow annotations and exits
with a non-zero status when a plugin is denied (configurable via the
`fail-on` action input).

Out of scope: generic dependency scanning, `package.json` /
`requirements.txt` diffs, OSV CVE checks against pinned versions.
Those are already covered by Dependabot, Snyk, npm audit, etc.
"""

# Path segments that mark plugin-asset directories. A changed file is
# interesting iff one of these appears as a path segment AND the
# per-segment file-type rules in `entry.py` match.
PLUGIN_ASSET_DIRS = (".claude-plugin", "skills", "commands", "hooks")
