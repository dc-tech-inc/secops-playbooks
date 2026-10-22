# Security policy

This repository contains defensive reference material only: runbooks, detection rules, configuration as code and read-only triage helpers. It holds no credentials, no malware and no real incident data, and nothing in it has been deployed to a real environment.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting ("Security" tab, "Report a vulnerability") instead of a public issue. We aim to acknowledge reports within a few business days.

Useful reports include a detection rule that can be trivially bypassed, an unsafe default in the Terraform or Bicep, a runbook step that would destroy evidence, or a CI workflow that could leak secrets.

## Scope

In scope: everything in this repository. Out of scope: the third-party tools, providers, actions and public sample captures it references.

## What we will not accept

Contributions containing malware, working exploits, offensive tooling, real credentials or real incident data are rejected regardless of intent.
