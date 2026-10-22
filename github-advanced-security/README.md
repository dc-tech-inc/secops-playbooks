# GitHub Advanced Security as code

How DCtech. turns on and configures GitHub's security features for a repository, kept as files so the setup is reviewable and repeatable.

| Feature | File | What it does |
|---|---|---|
| Code scanning (CodeQL) | [`../.github/workflows/codeql.yml`](../.github/workflows/codeql.yml), [`codeql/codeql-config.yml`](codeql/codeql-config.yml) | Advanced setup for Python and GitHub Actions workflows, `security-extended` queries, weekly schedule |
| Dependabot version updates | [`../.github/dependabot.yml`](../.github/dependabot.yml) (this repo), [`dependabot/dependabot.template.yml`](dependabot/dependabot.template.yml) (template with grouping) | Weekly update PRs for actions, pip and Terraform |
| Dependabot alerts + security updates, secret scanning, push protection, private vulnerability reporting | [`enable-security-features.sh`](enable-security-features.sh) | `gh api` calls; dry run by default, `--apply` to change settings |
| Custom secret scanning patterns | [`secret-scanning/custom_patterns.yml`](secret-scanning/custom_patterns.yml) | Three patterns for the fictional Example Co. token formats, tested with generated tokens |

```bash
github-advanced-security/enable-security-features.sh dc-tech-inc/secops-playbooks          # prints the calls
github-advanced-security/enable-security-features.sh dc-tech-inc/secops-playbooks --apply  # makes them
pytest github-advanced-security/tests
```

## Plan availability (why some of this is off right now)

- On **public** repositories, CodeQL code scanning, secret scanning and push protection are free.
- On **private** repositories they need GitHub Code Security / Secret Protection, which a Free organization does not have. This repository is private until it is published, so [`codeql.yml`](../.github/workflows/codeql.yml) skips its job with `if: github.event.repository.visibility == 'public'` instead of failing, and the enablement script is run after publication.
- Dependabot alerts and version updates work on private repositories on every plan.
- Until then, every push is covered by **gitleaks** in CI (pinned release, sha256-verified download), which scans the full git history.

## Custom patterns

GitHub custom patterns are defined in the UI or API with a *secret format*, optional *before/after secret* boundaries and *additional match requirements*. [`custom_patterns.yml`](secret-scanning/custom_patterns.yml) uses the same fields, and [`patterns.py`](secret-scanning/patterns.py) applies them the way GitHub does, so a pattern can be tested before anyone pastes it into the settings page:

- positive cases: tokens generated at test time (never stored in git), in several surrounding contexts (`KEY=…`, JSON, shell export);
- negative cases: too short, glued to other characters, a documented placeholder (`must_not_match`), wrong host.

GitHub evaluates patterns with Hyperscan. The patterns here stay inside the syntax Python's `re` shares with it; `\z` is translated to `\Z` for Python.

## Alert handling

A secret scanning alert is an incident: follow [RB-02](../runbooks/RB-02-leaked-secret.md). Revoke first, then clean history, then close the alert as *revoked*.

## Limitations

- CodeQL and secret scanning have not produced results on this repository yet because it is private on a Free plan; the workflow and the patterns are validated (schema, tests) but not yet exercised by GitHub.
- The enablement script has been run in dry-run mode only.

## References

- About code scanning with CodeQL: <https://docs.github.com/en/code-security/code-scanning/introduction-to-code-scanning/about-code-scanning-with-codeql>
- CodeQL workflow configuration: <https://docs.github.com/en/code-security/code-scanning/creating-an-advanced-setup-for-code-scanning/customizing-your-advanced-setup-for-code-scanning>
- About secret scanning: <https://docs.github.com/en/code-security/secret-scanning/introduction/about-secret-scanning>
- Defining custom patterns: <https://docs.github.com/en/code-security/secret-scanning/using-advanced-secret-scanning-and-push-protection-features/custom-patterns/defining-custom-patterns-for-secret-scanning>
- Dependabot options reference: <https://docs.github.com/en/code-security/dependabot/dependabot-version-updates/configuration-options-for-the-dependabot.yml-file>
- REST API, repositories (`security_and_analysis`): <https://docs.github.com/en/rest/repos/repos#update-a-repository>
- gitleaks: <https://github.com/gitleaks/gitleaks>
