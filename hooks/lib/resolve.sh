#!/usr/bin/env bash
# Shared resolver for hook wrappers. Sourced by pretool.sh, prompt.sh,
# session.sh.
#
# Why this exists: Claude Code prepends each enabled plugin's bin/ to
# PATH for the *Bash tool* subprocess, but the hook subprocess does
# not inherit the same PATH manipulation reliably across platforms,
# so `command -v watchdog-pretool` may return false even when the
# plugin's bin/ shim exists on disk. Falling into the tamper-deny
# fallback in that state is a UX bug — git commits, PR bodies, and
# anything else that quotes an install verb get denied.
#
# Strategy: check a fixed list of well-known install locations
# directly. We do *not* fall back to the plugin's bin/ shim because
# the shim itself re-execs one of these same dirs, so resolving
# directly avoids a level of indirection.

# resolve_watchdog_bin <name> → echoes absolute path to the binary
# or empty string. Never errors.
resolve_watchdog_bin() {
  local name="$1"
  if [ -n "${WATCHDOG_INSTALL_DIR:-}" ] && [ -x "${WATCHDOG_INSTALL_DIR}/${name}" ]; then
    printf '%s' "${WATCHDOG_INSTALL_DIR}/${name}"
    return 0
  fi
  for d in \
    "$HOME/.local/bin" \
    "/usr/local/bin" \
    "/opt/homebrew/bin" \
    "$HOME/.watchdog/bin"; do
    if [ -x "$d/$name" ]; then
      printf '%s' "$d/$name"
      return 0
    fi
  done
  # PATH fallback for non-standard installs.
  if command -v "$name" >/dev/null 2>&1; then
    command -v "$name"
    return 0
  fi
  return 1
}

# extract_json_field <json-string> <python-expr>
#   Returns the value at <python-expr> applied to the parsed JSON, or
#   empty string on any failure (missing python3, malformed JSON,
#   missing key). Used to safely look at a *specific* field of the
#   hook payload instead of regex-matching the whole serialised JSON,
#   which false-positives on prose that quotes install verbs.
extract_json_field() {
  local json="$1"
  local expr="$2"
  if ! command -v python3 >/dev/null 2>&1; then
    return 1
  fi
  printf '%s' "$json" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    v = $expr
    if v is None:
        sys.exit(0)
    print(v)
except Exception:
    sys.exit(0)
" 2>/dev/null
}
