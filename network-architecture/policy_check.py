"""Validate and query the fictional zone-based firewall policy in policy.yaml.

Usage:
    python policy_check.py [policy.yaml]                 # validate, exit 1 on errors
    python policy_check.py policy.yaml guest servers smb # evaluate one flow
"""

from __future__ import annotations

import ipaddress
import sys
from pathlib import Path

import yaml

DEFAULT_POLICY = Path(__file__).with_name("policy.yaml")
DOC_RANGES = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
PRIVATE_RANGES = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def load(path: Path | str = DEFAULT_POLICY) -> dict:
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _targets(rule: dict) -> list[str]:
    to = rule["to"]
    return to if isinstance(to, list) else [to]


def _in_any(net: ipaddress.IPv4Network, ranges: list[ipaddress.IPv4Network]) -> bool:
    return any(net.subnet_of(r) for r in ranges)


def evaluate(policy: dict, src: str, dst: str, service: str) -> tuple[str, str | None]:
    """Return (action, rule_id) for a flow; first match wins, else the default action."""
    for rule in policy["rules"]:
        if rule["from"] == src and dst in _targets(rule):
            if "any" in rule["services"] or service in rule["services"]:
                return rule["action"], rule["id"]
    return policy["default_action"], None


def validate(policy: dict) -> list[str]:
    """Return a list of human-readable invariant violations (empty means valid)."""
    errors: list[str] = []
    zones = {z["name"] for z in policy["zones"]}
    services = set(policy["services"])
    groups = policy.get("source_groups", {})

    if policy.get("default_action") != "drop":
        errors.append("default_action must be drop")

    seen_ids: set[str] = set()
    for rule in policy["rules"]:
        rid = rule.get("id", "?")
        if rid in seen_ids:
            errors.append(f"{rid}: duplicate rule id")
        seen_ids.add(rid)
        if not str(rule.get("reason", "")).strip():
            errors.append(f"{rid}: every rule needs a reason")
        if rule.get("action") not in ("allow", "drop"):
            errors.append(f"{rid}: action must be allow or drop")
        for zone in [rule["from"], *_targets(rule)]:
            if zone not in zones:
                errors.append(f"{rid}: unknown zone {zone!r}")
        for svc in rule["services"]:
            if svc != "any" and svc not in services:
                errors.append(f"{rid}: unknown service {svc!r}")
        if rule.get("action") == "allow":
            if "any" in rule["services"]:
                errors.append(f"{rid}: allow rules must list services, never 'any'")
            if rule["from"] == "wan" and not rule.get("source_group"):
                errors.append(f"{rid}: inbound from wan needs a source_group")
            if rule["from"] == "iot" and "wan" in _targets(rule):
                errors.append(f"{rid}: iot must not reach wan")
            if rule["from"] == "guest" and _targets(rule) != ["wan"]:
                errors.append(f"{rid}: guest may only reach wan")
            if "mgmt" in _targets(rule) and rule["from"] != "mgmt" and rule.get("source_group") != "it-admins":
                errors.append(f"{rid}: mgmt access must be limited to the it-admins group")
        if rule.get("source_group") and rule["source_group"] not in groups:
            errors.append(f"{rid}: unknown source_group {rule['source_group']!r}")

    all_nets: list[tuple[str, ipaddress.IPv4Network]] = []
    for site in policy["sites"]:
        wan = ipaddress.ip_network(f"{site['wan_address']}/32")
        if not _in_any(wan, DOC_RANGES):
            errors.append(f"{site['name']}: WAN address must be an RFC 5737 placeholder")
        ids = [v["id"] for v in site["vlans"]]
        if len(ids) != len(set(ids)):
            errors.append(f"{site['name']}: duplicate VLAN id")
        for vlan in site["vlans"]:
            net = ipaddress.ip_network(vlan["cidr"])
            if not _in_any(net, PRIVATE_RANGES):
                errors.append(f"{site['name']}/{vlan['name']}: VLAN must use RFC 1918 space")
            if vlan["zone"] not in zones:
                errors.append(f"{site['name']}/{vlan['name']}: unknown zone {vlan['zone']!r}")
            for other_name, other in all_nets:
                if net.overlaps(other):
                    errors.append(f"{site['name']}/{vlan['name']} overlaps {other_name}")
            all_nets.append((f"{site['name']}/{vlan['name']}", net))

    for name, members in groups.items():
        for member in members:
            net = ipaddress.ip_network(member)
            if not (_in_any(net, PRIVATE_RANGES) or _in_any(net, DOC_RANGES)):
                errors.append(f"source_group {name}: {member} is not a private or documentation range")

    peers = {ipaddress.ip_network(m) for m in groups.get("site-peers", [])}
    wans = {ipaddress.ip_network(f"{s['wan_address']}/32") for s in policy["sites"]}
    if peers != wans:
        errors.append("source_group site-peers must list exactly the sites' WAN addresses")

    return errors


def main(argv: list[str]) -> int:
    path = argv[1] if len(argv) > 1 else DEFAULT_POLICY
    policy = load(path)
    if len(argv) == 5:
        action, rule = evaluate(policy, argv[2], argv[3], argv[4])
        print(f"{argv[2]} -> {argv[3]} ({argv[4]}): {action} [{rule or 'default'}]")
        return 0
    errors = validate(policy)
    for err in errors:
        print(f"ERROR {err}")
    print(f"{len(policy['rules'])} rules, {len(errors)} errors")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
