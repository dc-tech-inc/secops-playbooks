# ADR 0001: Defensive content only, synthetic or public data only

Status: accepted

## Context
A public security repository can easily drift into offensive tooling, or leak real incident data, customer names or infrastructure details.

## Decision
The repository holds only defensive material: runbooks, detection rules, configuration as code, triage helpers. Every sample is either synthetic (fictional "Example Co.", `example.com`, RFC 1918/5737 addresses), the EICAR test string, or a public sample capture downloaded and sha256-verified at run time. No malware, exploit, scanner or real incident artifact is committed.

## Consequences
Detection rules are tested against benign and synthetic data, so coverage of real-world variants is not demonstrated. `runbooks/runbook_lint.py` fails CI on e-mail addresses outside example domains and on phone-number-like strings in any Markdown file.
