#!/usr/bin/env bash
# Download a pinned gitleaks release and verify its sha256 before extracting it.
# Usage: scripts/install-gitleaks.sh [install_dir]   (default: ./.bin)
set -euo pipefail

VERSION="8.30.1"
SHA256="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"
TARBALL="gitleaks_${VERSION}_linux_x64.tar.gz"
DEST="${1:-.bin}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

curl -fsSL -o "$tmp/$TARBALL" "https://github.com/gitleaks/gitleaks/releases/download/v${VERSION}/${TARBALL}"
echo "${SHA256}  $tmp/$TARBALL" | sha256sum -c -

mkdir -p "$DEST"
tar -xzf "$tmp/$TARBALL" -C "$DEST" gitleaks
echo "gitleaks ${VERSION} installed in ${DEST}"
