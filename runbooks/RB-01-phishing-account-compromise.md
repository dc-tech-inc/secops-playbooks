# RB-01 · Phishing and account compromise

## Trigger

- A user reports a suspicious email, or clicked a link and entered credentials.
- Identity provider alert: impossible travel, sign-in from an anonymizing network, MFA fatigue (many denied prompts).
- A new inbox rule that forwards or deletes mail, or a new OAuth app consent.

## Severity

- SEV-3: reported phish, no click.
- SEV-2: credentials entered or a suspicious sign-in succeeded.
- SEV-1: mailbox used to phish others or to redirect payments, or admin account involved.

## Roles

Incident lead, technical responder (identity admin), communications (if other staff or customers received mail from the account).

## Detect and analyze

1. Get the original message as an attachment (`.eml`), not a screenshot. Record sender, return path, links and attachment hashes.
2. Search the mail platform for the same sender, subject or URL across all mailboxes; note how many received it and who clicked.
3. For each affected account, pull sign-in logs for the last 7 days: source IPs, countries, user agents, MFA result.
4. Check for persistence: inbox rules, forwarding, new MFA methods, app consents, app passwords.
5. Decide the severity with the table above and open the incident report.

## Contain

1. Reset the password and **revoke all sessions and refresh tokens** for the affected account. A password reset alone does not end existing sessions.
2. Remove attacker-added MFA methods, inbox rules, forwarding and app consents.
3. Block the sender domain and URLs at the mail gateway and web filter; purge the message from all mailboxes.
4. If an admin account is involved, treat it as SEV-1: review every admin action in the audit log for the exposure window.

## Eradicate

1. If an attachment was opened, run an EDR scan on the device and follow RB-03 if anything executes.
2. Confirm no other account shows the same sign-in IPs or user agent.

## Recover

1. Return the account to the user after a supervised sign-in with a phishing-resistant MFA method where possible.
2. Watch the account's sign-ins for 14 days.

## Evidence to keep

- Original `.eml`, message trace, sign-in log export, audit log export for the window, list of recipients and clickers.

## Communication

- Tell recipients what to delete and whether to change passwords.
- If the account sent mail to customers or suppliers, communications warns them through a known channel (not a reply to the phishing thread).
- If payment details may have been changed, call the finance contact by phone on a known number.

## Post-incident

- Feed the sender, URLs and lure into awareness training and mail rules.
- Review whether conditional access (location, device compliance) would have blocked the sign-in.
- Fill in the [post-incident review](templates/post-incident-review.md).
