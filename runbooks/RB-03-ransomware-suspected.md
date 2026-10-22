# RB-03 · Suspected ransomware

## Trigger

- Many files renamed or rewritten with a new extension on a share or endpoint.
- A ransom note file appears, or a user reports one on screen.
- EDR alert for shadow copy deletion, mass encryption behaviour or a known ransomware family.

## Severity

SEV-1 by default. Downgrade only after analysis shows a single endpoint with no lateral movement.

## Roles

Incident lead, technical responders (endpoint and network), communications, management decision-maker (for business continuity and legal questions). Contact the organization's cyber insurer and legal counsel early: many policies require notice before any decisions are made.

## Detect and analyze

1. Identify the first affected host and the user account running the encrypting process (EDR timeline, file share audit logs).
2. Check for the usual precursors in the days before: new admin accounts, remote access tools, unusual RDP or SMB traffic between sites, large outbound transfers (possible data theft before encryption).
3. Determine the scope: which hosts, shares and backups are touched.

## Contain

1. **Isolate affected hosts from the network** (EDR network containment, or pull the switch port). Do not power them off if memory capture is possible and safe.
2. Disable the compromised user and any admin accounts used by the attacker; reset the passwords of privileged accounts from a clean device.
3. Block the inter-site tunnels or the affected VLAN at the firewall if spread is ongoing.
4. Protect backups: take them offline or confirm they are immutable, and stop sync jobs that could overwrite good copies.

## Eradicate

1. Find the initial access path (phish, exposed RDP, vulnerable VPN appliance) and close it.
2. Remove persistence (scheduled tasks, services, new accounts, remote access tools) found during analysis.
3. Rebuild affected hosts from known-good images; do not "clean" them in place.

## Recover

1. Restore data from backups verified to predate the intrusion, starting with business-critical systems agreed with management.
2. Bring hosts back in a monitored VLAN first; watch for re-infection for at least two weeks.
3. Reset all credentials that were present on affected hosts.

## Evidence to keep

- Ransom note, sample encrypted file and its original if available, EDR timeline, memory images, firewall and VPN logs, list of affected hosts and shares.

## Communication

- Staff: one message from management explaining what to do (and not to do) with their devices.
- Customers, regulators and law enforcement: decided by management with legal counsel, within the legal deadlines that apply.
- Do not engage with the attacker without legal counsel.

## Post-incident

- Review backup coverage, restore times and immutability.
- Review remote access exposure and MFA coverage.
- Update this runbook with the timings that actually happened.
