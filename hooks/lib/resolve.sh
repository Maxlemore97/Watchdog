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
#
# Every candidate is checked against the sha256 recorded for it in
# the install manifest, so a look-alike binary planted earlier in the
# search order (e.g. ~/.local/bin) is skipped rather than executed.

# manifest_path echoes the install manifest location.
manifest_path() {
  printf '%s' "${WATCHDOG_DIR:-$HOME/.watchdog}/manifest.json"
}

# sha256_of <file> → hex digest, or nothing when no hashing tool exists.
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -- "$1" 2>/dev/null | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 -- "$1" 2>/dev/null | cut -d' ' -f1
  fi
}

# binary_matches_manifest <path> <name> → success when the manifest has
# no hash for <name> (manual install, no manifest, no tooling — the
# binary's own integrity check still runs) or when the hash matches.
binary_matches_manifest() {
  local path="$1" name="$2" manifest expected actual
  manifest="$(manifest_path)"
  [ -f "$manifest" ] || return 0
  expected="$(extract_json_field "$(cat -- "$manifest")" "binaries.$name" || true)"
  [ -n "$expected" ] || return 0
  actual="$(sha256_of "$path")"
  [ -n "$actual" ] || return 0
  [ "$actual" = "$expected" ]
}

# resolve_watchdog_bin <name> → echoes absolute path to the binary
# or empty string. Never errors.
resolve_watchdog_bin() {
  local name="$1" candidate
  for d in \
    "${WATCHDOG_INSTALL_DIR:-}" \
    "$HOME/.local/bin" \
    "/usr/local/bin" \
    "/opt/homebrew/bin" \
    "$HOME/.watchdog/bin"; do
    [ -n "$d" ] || continue
    candidate="$d/$name"
    if [ -x "$candidate" ] && binary_matches_manifest "$candidate" "$name"; then
      printf '%s' "$candidate"
      return 0
    fi
  done
  # PATH fallback for non-standard installs.
  if candidate="$(command -v "$name" 2>/dev/null)" && [ -n "$candidate" ] &&
    binary_matches_manifest "$candidate" "$name"; then
    printf '%s' "$candidate"
    return 0
  fi
  return 1
}

# extract_json_field <json-string> <dotted.key.path>
#   Returns the string value at the dotted key path of the parsed
#   JSON (e.g. "tool_input.command"), or empty string on any failure
#   (missing python3, malformed JSON, missing key, non-scalar value).
#   The key path is passed as data, never interpolated into code. Used
#   to look at a *specific* field of the hook payload instead of
#   regex-matching the whole serialised JSON, which false-positives on
#   prose that quotes install verbs.
extract_json_field() {
  local json="$1"
  local keypath="$2"
  if ! command -v python3 >/dev/null 2>&1; then
    return 1
  fi
  printf '%s' "$json" | python3 -I -c '
import json, sys
try:
    v = json.load(sys.stdin)
    for k in sys.argv[1].split("."):
        v = v.get(k) if isinstance(v, dict) else None
    if isinstance(v, (str, int, float)) and not isinstance(v, bool):
        print(v)
except Exception:
    pass
' "$keypath" 2>/dev/null
}
