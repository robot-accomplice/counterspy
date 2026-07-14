#!/bin/sh
# CounterSpy installer — fetches the latest release, verifies its checksum, and installs the
# binary onto your PATH. macOS only. Downloads via curl, which does NOT set the Gatekeeper
# quarantine flag, so the binary runs without an xattr dance (browser downloads do get it).
#
#   curl -fsSL https://raw.githubusercontent.com/robot-accomplice/counterspy/main/install.sh | sh
#
# Override the install location with PREFIX (default /usr/local/bin):
#   curl -fsSL .../install.sh | PREFIX="$HOME/.local/bin" sh
set -eu

REPO="robot-accomplice/counterspy"
PREFIX="${PREFIX:-/usr/local/bin}"

fail() { echo "install: $*" >&2; exit 1; }

[ "$(uname -s)" = "Darwin" ] || fail "CounterSpy is macOS only (saw $(uname -s))."
command -v curl >/dev/null 2>&1 || fail "curl is required."
command -v shasum >/dev/null 2>&1 || fail "shasum is required."

echo "Resolving the latest release…"
tag="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
  | sed -n 's/.*"tag_name" *: *"\([^"]*\)".*/\1/p' | head -1)"
[ -n "$tag" ] || fail "could not resolve the latest release tag."

ver="${tag#v}"
asset="counterspy_${ver}_darwin_all.tar.gz"   # universal binary — runs on Intel + Apple Silicon
base="https://github.com/$REPO/releases/download/$tag"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "Downloading $asset ($tag)…"
curl -fsSL "$base/$asset" -o "$tmp/$asset" || fail "download failed: $base/$asset"
curl -fsSL "$base/checksums.txt" -o "$tmp/checksums.txt" || fail "could not fetch checksums.txt"

echo "Verifying checksum…"
( cd "$tmp" && grep " ${asset}\$" checksums.txt | shasum -a 256 -c - >/dev/null ) \
  || fail "checksum verification FAILED — refusing to install."

tar -xzf "$tmp/$asset" -C "$tmp"
[ -f "$tmp/counterspy" ] || fail "archive did not contain the counterspy binary."

echo "Installing to $PREFIX/counterspy…"
# Create PREFIX if it doesn't exist yet — a custom PREFIX (e.g. ~/.local/bin) may not, and
# `install` won't create the target directory itself. Elevate only when we can't write it.
if [ -d "$PREFIX" ] && [ -w "$PREFIX" ]; then
  install -m 0755 "$tmp/counterspy" "$PREFIX/counterspy"
elif [ ! -e "$PREFIX" ] && mkdir -p "$PREFIX" 2>/dev/null; then
  install -m 0755 "$tmp/counterspy" "$PREFIX/counterspy"
else
  echo "  ($PREFIX needs elevated permission)"
  sudo mkdir -p "$PREFIX"
  sudo install -m 0755 "$tmp/counterspy" "$PREFIX/counterspy"
fi

echo "Installed CounterSpy $tag → $PREFIX/counterspy"
echo "Next: sudo counterspy scan   (run under sudo for full visibility)"
