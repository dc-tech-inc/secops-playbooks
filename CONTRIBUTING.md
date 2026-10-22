# Contributing

1. Branch from `main` (`feat/<scope>` or `fix/<scope>`).
2. Use [conventional commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`, `ci:`, `chore:`).
3. Run `scripts/check.sh` before pushing. It runs lint, all Python tests, the notebooks and, when the tools are installed, Pester and Terraform.
4. Defensive content only. Use synthetic data: `example.com`, RFC 1918 internal ranges, RFC 5737 public ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), the EICAR string for malware tests. Never commit real credentials, real IPs, real incident data or personal contact details.
5. New Sigma/YARA rules need positive and negative test cases; new runbooks keep the standard sections (the lint enforces them).
6. Open a pull request. All CI checks must be green; merges use a merge commit.

New checkov skips need an inline `checkov:skip=<ID>: <reason>` comment next to the resource.
