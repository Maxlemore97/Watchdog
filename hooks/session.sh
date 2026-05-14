#!/usr/bin/env bash
# Watchdog SessionStart hook wrapper.
set -eu
if ! command -v watchdog-session >/dev/null 2>&1; then
  exit 0
fi
exec watchdog-session
