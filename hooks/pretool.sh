#!/usr/bin/env bash
# Watchdog PreToolUse hook wrapper.
#
# Normal path: exec the watchdog-pretool Go binary if installed.
#
# Tamper path: binary is missing but the manifest at
# ${WATCHDOG_DIR:-$HOME/.watchdog}/manifest.json exists. That means
# Watchdog was set up here and something removed the binary — refuse
# install-shaped Bash tool calls with a deny verdict so an adversary
# can't disable protection just by `rm`-ing the binary.
#
# Clean-uninstall path: binary missing AND no manifest → exit 0
# (other plugins' hook decisions remain in effect).
set -eu

if command -v watchdog-pretool >/dev/null 2>&1; then
  exec watchdog-pretool
fi

manifest="${WATCHDOG_DIR:-$HOME/.watchdog}/manifest.json"
if [ ! -f "$manifest" ]; then
  exit 0
fi

input=$(cat)

# Only inspect Bash tool calls. Other tools pass through silently.
case "$input" in
  *'"tool_name"'*'"Bash"'*) ;;
  *) exit 0 ;;
esac

# Conservative install-verb match. False positives (over-blocking) are
# acceptable here — this fallback only fires when the main binary is
# already missing and the manifest indicates tamper.
if printf '%s' "$input" | grep -qE '(npm|pnpm|yarn|bun)[[:space:]]+(i|add|install)|pip[3]?[[:space:]]+install|cargo[[:space:]]+(add|install)|gem[[:space:]]+install|composer[[:space:]]+require|brew[[:space:]]+install|uv[[:space:]]+(add|pip[[:space:]]+install)|poetry[[:space:]]+add'; then
  # shellcheck disable=SC2016  # backticks are literal markdown in JSON message
  printf '%s\n' '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"watchdog: pretool binary missing but manifest present — tamper suspected. Run `watchdog-shim doctor` to investigate, or `watchdog-shim uninstall` to remove protection cleanly."}}'

  # Best-effort audit append. Fail silently if the dir is not writable.
  audit_log="${WATCHDOG_AUDIT_LOG:-${WATCHDOG_DIR:-$HOME/.watchdog}/audit.jsonl}"
  audit_dir=$(dirname -- "$audit_log")
  if mkdir -p "$audit_dir" 2>/dev/null; then
    ts=$(date +%s)
    printf '{"ts":%s,"event":"tamper.suspected","pid":%s,"source":"hook_wrapper","tool":"Bash"}\n' \
      "$ts" "$$" >> "$audit_log" 2>/dev/null || true
  fi
fi
exit 0
