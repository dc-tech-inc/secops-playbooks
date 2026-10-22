#!/usr/bin/env bash
# Download a pinned Bicep CLI release (linux-x64) and verify its sha256.
# Usage: scripts/install-bicep.sh [install_dir]   (default: ./.bin)
set -euo pipefail

VERSION="0.47.16"
SHA256="64c345a58e0c3e48b1bc98a4e62d6b3adb1d238281297de3400aeafb2697aa5a"
DEST="${1:-.bin}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

curl -fsSL -o "$tmp/bicep" "https://github.com/Azure/bicep/releases/download/v${VERSION}/bicep-linux-x64"
echo "${SHA256}  $tmp/bicep" | sha256sum -c -

mkdir -p "$DEST"
install -m 0755 "$tmp/bicep" "$DEST/bicep"
echo "bicep ${VERSION} installed in ${DEST}"
