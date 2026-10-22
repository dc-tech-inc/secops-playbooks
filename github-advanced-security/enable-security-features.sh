#!/usr/bin/env bash
# Turn on GitHub's repository security features with the gh CLI.
#
# Usage: enable-security-features.sh OWNER/REPO [--apply]
# Without --apply it only prints the API calls (dry run). With --apply it runs them using
# the gh authentication already configured on the machine; it never reads or stores tokens.
#
# Secret scanning and push protection are free on public repositories; on private
# repositories they need GitHub Secret Protection (Team/Enterprise plans).
set -euo pipefail

usage() { echo "usage: $0 OWNER/REPO [--apply]" >&2; exit 2; }

[[ $# -ge 1 && $# -le 2 ]] || usage
repo="$1"
apply="${2:-}"
[[ "$repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || usage
[[ -z "$apply" || "$apply" == "--apply" ]] || usage

run() {
  if [[ "$apply" == "--apply" ]]; then
    "$@"
  else
    printf 'DRY RUN:'
    printf ' %q' "$@"
    printf '\n'
  fi
}

# Dependabot alerts, then Dependabot security updates (automatic fix PRs).
run gh api --method PUT "repos/${repo}/vulnerability-alerts" --silent
run gh api --method PUT "repos/${repo}/automated-security-fixes" --silent

# Private vulnerability reporting, so SECURITY.md can point researchers to the Security tab.
run gh api --method PUT "repos/${repo}/private-vulnerability-reporting" --silent

# Secret scanning and push protection.
run gh api --method PATCH "repos/${repo}" --silent \
  -f "security_and_analysis[secret_scanning][status]=enabled" \
  -f "security_and_analysis[secret_scanning_push_protection][status]=enabled"

# Show the resulting state.
run gh api "repos/${repo}" --jq '.security_and_analysis'

if [[ "$apply" != "--apply" ]]; then
  echo "Nothing changed. Re-run with --apply to make these calls."
fi
