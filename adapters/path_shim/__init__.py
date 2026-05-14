"""PATH-prepend shim adapter.

Installs small wrapper executables for package-manager binaries into
`~/.watchdog/bin/`. When that directory is first on the user's PATH,
every `npm install`, `pip install`, `cargo add`, ... goes through
Watchdog before the real binary runs.

Unlike the Claude Code adapter, the shim is host-agnostic: it catches
installs from any agent that shells out to a package manager
(terminal panes in Cursor, Aider, Cline, plain shells driven by an
agent), not just Claude Code. Non-install invocations (`npm test`,
`pip --version`, ...) are detected and forwarded unmodified to the
real binary.

Public entry points:
- `cli.main`     -> `watchdog-shim` (install / uninstall / status)
- `shim.main`    -> `watchdog-shim-exec` (per-call dispatch)
"""

SHIMMED_TOOLS = (
    "npm",
    "pnpm",
    "yarn",
    "pip",
    "pip3",
    "uv",
    "poetry",
    "cargo",
    "gem",
    "composer",
)
