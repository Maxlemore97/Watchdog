#!/usr/bin/env bash
# Watchdog UserPromptSubmit hook wrapper.
set -eu
if ! command -v watchdog-prompt >/dev/null 2>&1; then
  exit 0
fi
exec watchdog-prompt
