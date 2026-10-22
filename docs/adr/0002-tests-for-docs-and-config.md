# ADR 0002: Test documentation and configuration, not just code

Status: accepted

## Context
Most of a security operations repository is prose and configuration. Untested runbooks rot (broken links, missing steps); untested detections silently stop matching; untested policies accumulate unsafe exceptions.

## Decision
Each area has an executable check: runbook section order and links (`runbook_lint.py`), firewall-policy invariants (`policy_check.py`), Sigma rules converted by the official SQLite backend and run against labelled events, YARA rules matched against EICAR and benign files, secret patterns exercised with generated tokens, notebooks executed by nbmake with assertions on their findings, Terraform plan tests with a mock provider, Bicep build/lint with warnings as errors.

## Consequences
Changing a rule or a runbook means updating its expectations. The checks prove consistency and intent, not real-world effectiveness.
