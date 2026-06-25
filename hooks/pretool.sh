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

# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/resolve.sh
. "$(dirname "$0")/lib/resolve.sh"

bin="$(resolve_watchdog_bin watchdog-pretool || true)"
if [ -n "$bin" ]; then
  exec "$bin"
fi

manifest="${WATCHDOG_DIR:-$HOME/.watchdog}/manifest.json"
if [ ! -f "$manifest" ]; then
  exit 0
fi

input=$(cat)

# Only inspect Bash tool calls. Other tools pass through silently.
tool=$(extract_json_field "$input" "d.get('tool_name','')" || true)
if [ "$tool" != "Bash" ]; then
  exit 0
fi

# Pull just the command field so the install-verb regex doesn't false-
# positive on commit messages, PR bodies, or any other prose that
# happens to quote an install verb. If python3 is unavailable the
# extraction returns empty — in that case we exit 0 rather than fall
# back to denying every Bash call, because over-blocking the user's
# normal workflow is worse than the (already-unlikely) tamper case
# the fallback was meant to catch.
cmd=$(extract_json_field "$input" "d.get('tool_input',{}).get('command','')" || true)
if [ -z "$cmd" ]; then
  exit 0
fi

# Install-verb match at the start of a sub-command. Sub-commands begin
# at the start of the string or after a separator (; && || | ( newline).
# Anchoring at a separator avoids matching `git commit -m "npm install"`.
if printf '%s' "$cmd" | grep -qE '(^|[;&|()][[:space:]]*|[[:space:]]&&[[:space:]]*|[[:space:]]\|\|[[:space:]]*)(npm|pnpm|yarn|bun)[[:space:]]+(i|add|install)([[:space:]]|$)|(^|[;&|()][[:space:]]*)pip[3]?[[:space:]]+install([[:space:]]|$)|(^|[;&|()][[:space:]]*)cargo[[:space:]]+(add|install)([[:space:]]|$)|(^|[;&|()][[:space:]]*)gem[[:space:]]+install([[:space:]]|$)|(^|[;&|()][[:space:]]*)composer[[:space:]]+require([[:space:]]|$)|(^|[;&|()][[:space:]]*)brew[[:space:]]+install([[:space:]]|$)|(^|[;&|()][[:space:]]*)uv[[:space:]]+(add|pip[[:space:]]+install)([[:space:]]|$)|(^|[;&|()][[:space:]]*)poetry[[:space:]]+add([[:space:]]|$)'; then
  # shellcheck disable=SC2016  # backticks are literal markdown in JSON message
  printf '%s\n' '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"watchdog: pretool binary missing but manifest present — tamper suspected. Run `watchdog-shim doctor` to investigate, or `watchdog-shim uninstall` to remove protection cleanly."}}'

  audit_log="${WATCHDOG_AUDIT_LOG:-${WATCHDOG_DIR:-$HOME/.watchdog}/audit.jsonl}"
  audit_dir=$(dirname -- "$audit_log")
  if mkdir -p "$audit_dir" 2>/dev/null; then
    ts=$(date +%s)
    printf '{"ts":%s,"event":"tamper.suspected","pid":%s,"source":"hook_wrapper","tool":"Bash"}\n' \
      "$ts" "$$" >> "$audit_log" 2>/dev/null || true
  fi
fi
exit 0
