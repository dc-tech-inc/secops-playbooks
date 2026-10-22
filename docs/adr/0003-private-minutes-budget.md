# ADR 0003: Split CI by cost while the repository is private

Status: accepted

## Context
Private repositories on a Free plan have a monthly Actions minutes budget, and CodeQL/secret scanning are not available to them.

## Decision
Fast jobs (lint, pytest, Pester, gitleaks) run on every push and pull request. Heavier jobs (notebooks, Terraform, tflint, Bicep, checkov) run on pull requests and manual dispatch only. CodeQL is committed but skipped while the repository is private (`if: visibility == 'public'`).

## Consequences
A direct push to `main` skips the heavy jobs, so changes go through pull requests. After publication the CodeQL job starts running without further changes.
