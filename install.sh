#!/usr/bin/env sh
# Watchdog installer (POSIX). Downloads the latest GitHub Release
# binaries for the host OS+arch and drops them into
# $WATCHDOG_INSTALL_DIR (default ~/.local/bin).
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/Maxlemore97/Watchdog/main/install.sh | sh
#   WATCHDOG_VERSION=v1.0.0 sh install.sh
set -eu

REPO="Maxlemore97/Watchdog"
INSTALL_DIR="${WATCHDOG_INSTALL_DIR:-$HOME/.local/bin}"
VERSION="${WATCHDOG_VERSION:-latest}"

err() { printf '%s\n' "watchdog-install: $*" >&2; exit 1; }
info() { printf '%s\n' "watchdog-install: $*"; }

# ---------- detect OS + arch -------------------------------------

uname_os() {
  case "$(uname -s)" in
    Darwin) echo "darwin" ;;
    Linux)  echo "linux" ;;
    *)      err "unsupported OS: $(uname -s)" ;;
  esac
}

uname_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *) err "unsupported arch: $(uname -m)" ;;
  esac
}

OS="$(uname_os)"
ARCH="$(uname_arch)"

# ---------- resolve version --------------------------------------

if [ "$VERSION" = "latest" ]; then
  if ! command -v curl >/dev/null 2>&1; then
    err "curl required"
  fi
  VERSION="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
    | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n1)"
  [ -n "$VERSION" ] || err "could not resolve latest version"
fi

info "installing watchdog $VERSION ($OS/$ARCH) into $INSTALL_DIR"

# ---------- download + extract -----------------------------------

VERSION_BARE="${VERSION#v}"
ARCHIVE="watchdog_${VERSION_BARE}_${OS}_${ARCH}.tar.gz"
URL="https://github.com/$REPO/releases/download/$VERSION/$ARCHIVE"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

info "fetching $URL"
if ! curl -fsSL "$URL" -o "$TMP/$ARCHIVE"; then
  err "download failed: $URL"
fi

# ---------- verify checksum --------------------------------------
# goreleaser publishes checksums.txt alongside every archive. We
# refuse to extract a tarball whose sha256 doesn't match. Defense
# against a compromised release / mirror serving altered bytes.

CHECKSUMS_URL="https://github.com/$REPO/releases/download/$VERSION/checksums.txt"
info "fetching checksums.txt"
if ! curl -fsSL "$CHECKSUMS_URL" -o "$TMP/checksums.txt"; then
  err "checksum download failed: $CHECKSUMS_URL"
fi

# Pick sha256 tool (Linux: sha256sum; macOS: shasum -a 256).
if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL="$(sha256sum "$TMP/$ARCHIVE" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  ACTUAL="$(shasum -a 256 "$TMP/$ARCHIVE" | awk '{print $1}')"
else
  err "no sha256 tool (sha256sum or shasum) on PATH"
fi

EXPECTED="$(awk -v f="$ARCHIVE" '$2 == f {print $1}' "$TMP/checksums.txt")"
if [ -z "$EXPECTED" ]; then
  err "checksums.txt has no entry for $ARCHIVE"
fi
if [ "$ACTUAL" != "$EXPECTED" ]; then
  err "checksum mismatch: got $ACTUAL, want $EXPECTED"
fi
info "checksum verified ($ACTUAL)"

info "extracting"
# --no-same-owner / --no-same-permissions where supported (GNU tar)
# avoids honoring archive-encoded ownership when run as root.
if tar --version 2>&1 | grep -q GNU; then
  tar -xzf "$TMP/$ARCHIVE" -C "$TMP" --no-same-owner --no-same-permissions
else
  tar -xzf "$TMP/$ARCHIVE" -C "$TMP"
fi

mkdir -p "$INSTALL_DIR"
for bin in watchdog-pretool watchdog-session watchdog-prompt watchdog-scan \
           watchdog-mcp watchdog-shim watchdog-shim-exec watchdog-action; do
  if [ -f "$TMP/$bin" ]; then
    install -m 0755 "$TMP/$bin" "$INSTALL_DIR/$bin"
  fi
done

# ---------- PATH hint ---------------------------------------------

case ":$PATH:" in
  *":$INSTALL_DIR:"*)
    ;;
  *)
    cat <<EOF

NOTE: $INSTALL_DIR is not on your PATH.
Add this line to your shell rc (~/.bashrc, ~/.zshrc, etc.):

  export PATH="$INSTALL_DIR:\$PATH"

Then restart your shell.

EOF
    ;;
esac

info "done. Binaries installed:"
ls "$INSTALL_DIR" | grep '^watchdog-' || true

cat <<EOF

Next steps:
  1. Install the package-manager shims (intercepts npm/pip/cargo/...):
       watchdog-shim install
  2. Add the shim dir to the FRONT of your PATH (instructions above).
  3. Verify with:
       watchdog-shim doctor

See https://github.com/$REPO for full docs.
EOF
