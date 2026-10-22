# TT-01 · Tabletop exercise: leaked CI token

A 60-90 minute discussion exercise for the engineering and IT staff of the fictional Example Co. Nobody touches a real system. The facilitator reads each inject, the team answers the questions, and the scribe records decisions and gaps. Format based on the CISA Tabletop Exercise Packages.

## Objectives

1. Practise [RB-02](../RB-02-leaked-secret.md) end to end, including the "revoke first" rule.
2. Test whether the team can tell, from logs, if a leaked credential was used.
3. Find gaps in ownership: who can rotate which secret, at 18:00 on a Friday.

## Participants

Facilitator, incident lead, two developers, cloud/platform owner, communications, scribe.

## Scenario

Example Co. runs a customer portal on Azure behind Front Door. Deployments use a GitHub Actions workflow with a service principal secret stored as a repository secret.

## Injects

| # | Time (exercise) | Inject | Questions for the team |
|---|---|---|---|
| 1 | 17:40 Fri | A developer, debugging a failing deploy, adds `env` to a workflow step and pushes to a **public** fork they use for a conference demo. The log prints the service principal secret. | Who is likely to notice first? What alert, if any, fires? |
| 2 | 18:05 | GitHub secret scanning raises an alert on the fork. The developer is offline. | Who receives the alert? What is the first action, and who is allowed to take it? |
| 3 | 18:20 | The platform owner finds the Azure sign-in logs show the service principal used from an IP address outside Example Co.'s ranges at 18:01. | Does this change severity? What do you check in the Azure activity log? |
| 4 | 18:45 | Activity log shows a new storage account key listed and a VM created in an unused region. | Containment steps, in order. Who decides to delete the VM? What evidence do you keep first? |
| 5 | Mon 09:00 | A customer emails asking whether "the security issue" affected their data, after a post on social media. | What does communications say, and who approves it? What do you not say yet? |

## Expected decisions (facilitator only)

- Inject 2: revoke the service principal secret immediately; deleting the workflow log or the fork does not invalidate it.
- Inject 3: escalate to SEV-1 (use by an unknown party).
- Inject 4: snapshot/export before deleting; disable the service principal, rotate the storage keys, review role assignments, check the other regions.
- Inject 5: acknowledge, commit to an update time, no speculation on impact until analysis is complete.

## Scoring

For each inject, the scribe marks: **met** (the team named the right action and owner), **partial**, or **gap**. Every *partial* or *gap* becomes an action item with an owner and due date in the post-incident review template.

| Inject | Result | Gap / action item | Owner | Due |
|---|---|---|---|---|
| 1 | | | | |
| 2 | | | | |
| 3 | | | | |
| 4 | | | | |
| 5 | | | | |

## Hot wash questions

1. What would we have done differently if the fork was private?
2. Was anything in RB-02 wrong or missing?
3. What one control would have prevented inject 1? (Examples: environment protection rules, OIDC federation instead of a stored secret, log masking.)
