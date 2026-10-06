#!/usr/bin/env bash
# Watchdog SessionStart hook wrapper.
# No pipefail: `printf | grep -q` would report SIGPIPE on an early
# match and turn a detected install into a pass-through.
set -eu

# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/resolve.sh
. "$(dirname "$0")/lib/resolve.sh"

bin="$(resolve_watchdog_bin watchdog-session || true)"
if [ -n "$bin" ]; then
  exec "$bin"
fi
exit 0
