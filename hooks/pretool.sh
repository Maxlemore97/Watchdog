#!/usr/bin/env bash
# Watchdog PreToolUse hook wrapper. Exec's the watchdog-pretool Go
# binary if installed; otherwise exits 0 so other plugins' hook
# decisions are not overridden.
set -eu
if ! command -v watchdog-pretool >/dev/null 2>&1; then
  exit 0
fi
exec watchdog-pretool
