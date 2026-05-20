#!/usr/bin/env bash
# Watchdog UserPromptSubmit hook wrapper.
#
# Normal path: exec the watchdog-prompt Go binary if installed.
#
# Tamper path: binary is missing but the manifest at
# ${WATCHDOG_DIR:-$HOME/.watchdog}/manifest.json exists → deny
# /plugin install … patterns so an adversary can't disable plugin
# screening by deleting the binary.
#
# Clean-uninstall path: binary missing AND no manifest → exit 0.
set -eu

# shellcheck source=lib/resolve.sh
. "$(dirname "$0")/lib/resolve.sh"

bin="$(resolve_watchdog_bin watchdog-prompt || true)"
if [ -n "$bin" ]; then
  exec "$bin"
fi

manifest="${WATCHDOG_DIR:-$HOME/.watchdog}/manifest.json"
if [ ! -f "$manifest" ]; then
  exit 0
fi

input=$(cat)

# Extract just the prompt field so the /plugin-install regex below
# only sees the user's actual prompt text, not the full hook envelope.
# If python3 is missing we fall back to scanning the whole payload —
# the prompt hook's regex is narrow enough (`/plugin install <arg>`)
# that prose false positives are rare.
prompt=$(extract_json_field "$input" "d.get('prompt','')" || true)
if [ -z "$prompt" ]; then
  prompt="$input"
fi

if printf '%s' "$prompt" | grep -qiE '/plugin[[:space:]]+(install|marketplace[[:space:]]+add)[[:space:]]+\S'; then
  # shellcheck disable=SC2016  # backticks are literal markdown in JSON message
  printf '%s\n' '{"decision":"deny","reason":"watchdog: prompt binary missing but manifest present — tamper suspected. Run `watchdog-shim doctor` to investigate."}'

  audit_log="${WATCHDOG_AUDIT_LOG:-${WATCHDOG_DIR:-$HOME/.watchdog}/audit.jsonl}"
  audit_dir=$(dirname -- "$audit_log")
  if mkdir -p "$audit_dir" 2>/dev/null; then
    ts=$(date +%s)
    printf '{"ts":%s,"event":"tamper.suspected","pid":%s,"source":"hook_wrapper","tool":"UserPromptSubmit"}\n' \
      "$ts" "$$" >> "$audit_log" 2>/dev/null || true
  fi
fi
exit 0
