#!/bin/sh
# Install the latest VEN release on Linux or macOS:
#   curl -fsSL https://raw.githubusercontent.com/enigma-137/ven/HEAD/scripts/install.sh | sh
# Options (environment): VEN_VERSION=v0.2.0 to pin a version,
# VEN_INSTALL_DIR=/usr/local/bin to change where ven goes (default ~/.local/bin).
set -eu

REPO="enigma-137/ven"
DIR="${VEN_INSTALL_DIR:-$HOME/.local/bin}"

fail() { echo "ven install: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "$1 is required"; }
need curl
need tar

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) fail "unsupported OS $(uname -s); on Windows use install.ps1" ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *) fail "unsupported CPU $(uname -m)" ;;
esac

version="${VEN_VERSION:-}"
if [ -z "$version" ]; then
  # The /releases/latest page redirects to /releases/tag/<version>.
  url=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest")
  version="${url##*/}"
  case "$version" in v*) ;; *) fail "could not find the latest release" ;; esac
fi

name="ven_${version#v}_${os}_${arch}"
base="https://github.com/$REPO/releases/download/$version"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "Downloading VEN $version for $os/$arch..."
curl -fsSL -o "$tmp/$name.tar.gz" "$base/$name.tar.gz"
curl -fsSL -o "$tmp/SHA256SUMS" "$base/SHA256SUMS"

expected=$(grep " $name.tar.gz\$" "$tmp/SHA256SUMS" | cut -d' ' -f1)
[ -n "$expected" ] || fail "no checksum for $name.tar.gz"
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$tmp/$name.tar.gz" | cut -d' ' -f1)
else
  actual=$(shasum -a 256 "$tmp/$name.tar.gz" | cut -d' ' -f1)
fi
[ "$expected" = "$actual" ] || fail "checksum mismatch: the download is corrupted or was tampered with"

tar -xzf "$tmp/$name.tar.gz" -C "$tmp"
mkdir -p "$DIR"
install -m 0755 "$tmp/$name/ven" "$DIR/ven"
echo "Installed $DIR/ven ($("$DIR/ven" version 2>/dev/null || echo "$version"))"

case ":$PATH:" in
  *":$DIR:"*) ;;
  *) echo "Add $DIR to your PATH, e.g.:  echo 'export PATH=\"$DIR:\$PATH\"' >> ~/.profile" ;;
esac
