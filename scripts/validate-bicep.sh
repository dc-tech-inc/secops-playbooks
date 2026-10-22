#!/usr/bin/env bash
# Build and lint Bicep files; fail on any warning or error (unknown properties and
# outdated API versions are reported by Bicep as warnings).
# Usage: scripts/validate-bicep.sh BICEP_BIN FILE...
set -euo pipefail

[[ $# -ge 2 ]] || { echo "usage: $0 BICEP_BIN FILE..." >&2; exit 2; }
bicep="$1"
shift

status=0
for file in "$@"; do
  out="$("$bicep" build "$file" --stdout 2>&1 >/dev/null; "$bicep" lint "$file" 2>&1)" || status=1
  if [[ -n "$out" ]]; then
    printf '%s\n' "$out"
    status=1
  else
    echo "ok  $file"
  fi
done
exit "$status"
