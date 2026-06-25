#!/usr/bin/env bash
# Watchdog SessionStart hook wrapper.
set -eu

# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/resolve.sh
. "$(dirname "$0")/lib/resolve.sh"

bin="$(resolve_watchdog_bin watchdog-session || true)"
if [ -n "$bin" ]; then
  exec "$bin"
fi
exit 0
