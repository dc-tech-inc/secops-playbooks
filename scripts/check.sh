#!/usr/bin/env bash
# One command for local checks. Requires Python 3.11+; pwsh and terraform are optional.
# Usage: scripts/check.sh
set -euo pipefail
cd "$(dirname "$0")/.."

python -m pip install -q -r requirements-ci.txt
ruff check . && ruff format --check .
python network-architecture/policy_check.py
python runbooks/runbook_lint.py
pytest --cov
python pcap-notebooks/fetch_samples.py
pytest --nbmake pcap-notebooks/notebooks

if command -v pwsh >/dev/null; then
  pwsh -NoProfile -Command "Invoke-Pester ./powershell/tests -Output Detailed -CI"
else
  echo "pwsh not found: skipping Pester"
fi

if command -v terraform >/dev/null; then
  (cd azure-as-code/terraform && terraform init -backend=false -input=false >/dev/null && terraform validate && terraform test)
else
  echo "terraform not found: skipping Terraform checks"
fi
