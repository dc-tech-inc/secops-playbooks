import copy

import pytest

import policy_check


@pytest.fixture(scope="module")
def policy():
    return policy_check.load()


def test_shipped_policy_is_valid(policy):
    assert policy_check.validate(policy) == []


@pytest.mark.parametrize(
    ("src", "dst", "service", "expected"),
    [
        ("corp", "servers", "smb", "allow"),
        ("corp", "wan", "web", "allow"),
        ("guest", "wan", "web", "allow"),
        ("guest", "servers", "smb", "drop"),
        ("guest", "mgmt", "ssh", "drop"),
        ("iot", "wan", "web", "drop"),
        ("iot", "servers", "rtsp", "allow"),
        ("voip", "servers", "smb", "drop"),
        ("wan", "servers", "web", "drop"),
        ("wan", "vpn", "wireguard", "allow"),
        ("servers", "corp", "smb", "drop"),
    ],
)
def test_flows(policy, src, dst, service, expected):
    action, _ = policy_check.evaluate(policy, src, dst, service)
    assert action == expected


def test_unmatched_flow_hits_default(policy):
    assert policy_check.evaluate(policy, "servers", "guest", "web") == ("drop", None)


def _mutated(policy, **rule):
    bad = copy.deepcopy(policy)
    base = {"id": "X1", "from": "corp", "to": "wan", "services": ["web"], "action": "allow", "reason": "test"}
    base.update(rule)
    bad["rules"].insert(0, base)
    return bad


@pytest.mark.parametrize(
    ("rule", "fragment"),
    [
        ({"services": ["any"]}, "never 'any'"),
        ({"reason": " "}, "needs a reason"),
        ({"from": "wan", "to": "servers"}, "needs a source_group"),
        ({"from": "iot", "to": "wan"}, "iot must not reach wan"),
        ({"from": "guest", "to": "corp"}, "guest may only reach wan"),
        ({"to": "mgmt", "services": ["ssh"]}, "it-admins"),
        ({"to": "dmz"}, "unknown zone"),
        ({"services": ["telnet"]}, "unknown service"),
        ({"action": "accept"}, "allow or drop"),
        ({"id": "R010"}, "duplicate rule id"),
    ],
)
def test_validator_rejects_unsafe_rules(policy, rule, fragment):
    errors = policy_check.validate(_mutated(policy, **rule))
    assert any(fragment in e for e in errors), errors


def test_validator_rejects_overlapping_and_public_vlans(policy):
    bad = copy.deepcopy(policy)
    bad["sites"][1]["vlans"].append({"id": 99, "name": "dup", "zone": "corp", "cidr": "10.10.20.0/24"})
    bad["sites"][2]["vlans"].append({"id": 98, "name": "pub", "zone": "corp", "cidr": "8.8.8.0/24"})
    bad["sites"][0]["vlans"].append({"id": 10, "name": "again", "zone": "mgmt", "cidr": "10.10.99.0/24"})
    errors = policy_check.validate(bad)
    assert any("overlaps" in e for e in errors)
    assert any("RFC 1918" in e for e in errors)
    assert any("duplicate VLAN id" in e for e in errors)


def test_validator_rejects_real_wan_and_default_allow(policy):
    bad = copy.deepcopy(policy)
    bad["default_action"] = "allow"
    bad["sites"][0]["wan_address"] = "8.8.8.8"
    errors = policy_check.validate(bad)
    assert "default_action must be drop" in errors
    assert any("RFC 5737" in e for e in errors)
    assert any("site-peers" in e for e in errors)


def test_cli(capsys):
    assert policy_check.main(["x"]) == 0
    assert "0 errors" in capsys.readouterr().out
    assert policy_check.main(["x", str(policy_check.DEFAULT_POLICY), "guest", "corp", "smb"]) == 0
    assert "drop [R900]" in capsys.readouterr().out
