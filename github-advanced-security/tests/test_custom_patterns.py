"""Exercise the custom secret scanning patterns with tokens generated at test time.

No token-shaped string is stored in the repository, so gitleaks and GitHub's own
secret scanning stay quiet on this file.
"""

import secrets
import string

import pytest

import patterns

ALNUM = string.ascii_letters + string.digits


def _rand(alphabet: str, n: int) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(n))


def api_key(env="live"):
    return f"exco_{env}_{_rand(ALNUM, 32)}"


def webhook_secret():
    return "whsec_exco_" + secrets.token_hex(20)


def db_url(password=None):
    password = password or _rand(ALNUM, 16)
    return f"postgresql://app_user:{password}@db1.internal.example.com"


def names(text):
    return [name for name, _ in patterns.scan(text)]


def test_all_patterns_load_with_severity():
    loaded = patterns.load()
    assert len(loaded) == 3
    assert {p.severity for p in loaded} <= {"high", "critical"}


@pytest.mark.parametrize(
    ("make", "name"),
    [
        (lambda: api_key("live"), "Example Co. portal API key"),
        (lambda: api_key("test"), "Example Co. portal API key"),
        (webhook_secret, "Example Co. webhook signing secret"),
        (db_url, "Example Co. internal database URL with password"),
    ],
)
@pytest.mark.parametrize("wrap", ["{}", "KEY={}\n", 'config = {{"token": "{}"}}', "export X='{}'"])
def test_positive_matches(make, name, wrap):
    token = make()
    hits = patterns.scan(wrap.format(token))
    assert hits == [(name, token)]


@pytest.mark.parametrize(
    "text",
    [
        "exco_live_" + "a" * 31,  # too short
        "xexco_live_" + "A" * 32,  # glued to a preceding alnum (before_secret)
        "exco_live_" + "A" * 32 + "Z",  # 33 chars: after_secret rejects it
        "exco_test_" + "0" * 32,  # documented placeholder (must_not_match)
        "whsec_exco_" + "g" * 40,  # not hex
        "postgresql://app_user:changeme123@db1.internal.example.com/portal",  # placeholder password
        "postgresql://app_user:short@db1.internal.example.com/portal",  # password under 8 chars
        "postgresql://app_user:" + "Q" * 12 + "@db1.example.com/portal",  # not an internal host
    ],
)
def test_negative_cases(text):
    assert patterns.scan(text) == []


def test_multiple_secrets_in_one_file():
    text = f"a={api_key()}\nb={webhook_secret()}\nc={db_url()}\n"
    assert len(names(text)) == 3
