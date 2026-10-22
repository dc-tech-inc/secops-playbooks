# RB-04 · Web application attack at the WAF

## Trigger

- Spike in blocked requests on the Front Door WAF policy (managed rule set or custom rules).
- The rate-limit custom rule fires for one source or a small set of sources.
- Application errors (5xx) or latency rising together with WAF logs.

The WAF policy this runbook assumes is defined in [`../azure-as-code`](../azure-as-code).

## Severity

- SEV-3: blocks only, application healthy.
- SEV-2: some malicious requests reached the application (logged in Detection mode, or matched an exclusion), or availability degraded.
- SEV-1: evidence of successful exploitation (unexpected data in responses, new admin users, web shell) or sustained outage.

## Roles

Incident lead, technical responder (application owner), platform responder (Azure).

## Detect and analyze

1. Query the Front Door WAF logs for the window: top client IPs, rule IDs, request URIs, user agents, actions (`Block`, `Log`, `AnomalyScoring`).
2. Separate scanner noise (many rules, many paths, one source) from targeted attempts (one path, payload variations).
3. Check application logs for the same request IDs or paths to see what got through.
4. Confirm the policy is in Prevention mode and that no recent exclusion or override opened the path.

## Contain

1. Add a temporary custom rule blocking the offending sources or the specific path pattern, with a comment and an expiry date in the ticket.
2. Lower the rate-limit threshold on the targeted path if the attack is volumetric.
3. If exploitation is suspected, take the affected backend out of the origin group and serve a maintenance page.

## Eradicate

1. Fix the application flaw the payload targets; do not rely on the WAF as the fix.
2. Remove any artifacts of successful exploitation (accounts, files) and rotate secrets the application holds.

## Recover

1. Return the backend to the origin group and watch error rates and WAF logs for 24 hours.
2. Remove the temporary rules when they expire, or convert them into documented permanent rules.

## Evidence to keep

- WAF log export for the window, application logs, the custom rules added and removed with timestamps.

## Communication

- Status page or customer notice if availability was affected.
- Data exposure follows the SEV-1 communication path.

## Post-incident

- Turn the payload into a regression test for the application.
- Review whether a managed rule override or exclusion was too broad.
