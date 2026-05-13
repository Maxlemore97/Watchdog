#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ADAPTER_ROOT="$(dirname "$SCRIPT_DIR")"

PYTHON_BIN="${WATCHDOG_PYTHON:-python3}"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  exit 0
fi

exec "$PYTHON_BIN" "$ADAPTER_ROOT/entry/session.py"
