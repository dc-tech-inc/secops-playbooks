# RB-02 · Secret leaked in a repository

## Trigger

- GitHub secret scanning alert, push protection bypass notice, or a provider's own leak notification.
- gitleaks finding in CI or on a developer machine.
- A token appears in a log, issue, pull request comment or chat message.

## Severity

- SEV-3: secret was in a private repository and is already expired or a test credential.
- SEV-2: valid secret in a private repository, or any secret in a public one for less than an hour with no use in the provider's logs.
- SEV-1: valid secret in a public repository or fork, or the provider's logs show use by an unknown party.

## Roles

Incident lead, technical responder (owner of the credential), repository admin.

## Detect and analyze

1. Identify the secret type and the system it opens (cloud account, API, database, CI).
2. Find the first commit that contained it (`git log -S '<prefix>' --all`) and whether that commit was ever on a public branch or fork.
3. Check the provider's access logs for use of the credential since that commit. Record every source IP and action.

## Contain

1. **Revoke or rotate the secret at the provider first.** Deleting the commit does not invalidate the secret; anyone who cloned the repository still has it.
2. Replace it in the secret store (GitHub Actions secrets, Key Vault) and redeploy consumers.
3. If the provider logs show unknown use, follow the provider's compromise guidance (for cloud: review IAM changes, new keys, new resources).

## Eradicate

1. Remove the secret from the current tree and add the file pattern to `.gitignore` if it was a config file.
2. Rewriting history (`git filter-repo`) is optional once the secret is revoked. Do it for public repositories to reduce noise, and tell every collaborator to re-clone.
3. Close the secret scanning alert as **revoked**, not as false positive.

## Recover

1. Confirm consumers work with the new credential.
2. Make sure push protection and the CI gitleaks job are on for the repository (see [`../github-advanced-security`](../github-advanced-security)).

## Evidence to keep

- Alert details, commit SHA and author, provider access logs for the exposure window, rotation time.

## Communication

- Inform the credential owner's team and, if customer data may have been reached, follow the SEV-1 communication path.

## Post-incident

- Ask why the secret was in code at all: missing `.env.example` pattern, no secret store, or a script that printed it.
- Add a custom secret scanning pattern if the token format is internal.
- Run [TT-01](tabletop/TT-01-leaked-ci-token.md) with the team if this was the first occurrence.
