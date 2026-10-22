"""Load the custom secret scanning patterns and apply them the way GitHub does.

A match needs `before_secret`, then the secret, then `after_secret`; a candidate that matches
any `must_not_match` regex is discarded.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

PATTERN_FILE = Path(__file__).with_name("custom_patterns.yml")


@dataclass(frozen=True)
class Pattern:
    name: str
    regex: re.Pattern[str]
    must_not_match: tuple[re.Pattern[str], ...]
    severity: str


def _py(expr: str) -> str:
    # Hyperscan/PCRE end-of-subject \z is spelled \Z in Python before 3.14.
    return expr.replace(r"\z", r"\Z")


def load(path: Path = PATTERN_FILE) -> list[Pattern]:
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    defaults = doc["defaults"]
    out = []
    for p in doc["patterns"]:
        before = _py(p.get("before_secret", defaults["before_secret"]))
        after = _py(p.get("after_secret", defaults["after_secret"]))
        regex = re.compile(f"(?:{before})(?P<secret>{p['secret_format']})(?=(?:{after}))")
        excludes = tuple(re.compile(x) for x in p.get("must_not_match", []))
        out.append(Pattern(p["name"], regex, excludes, p["severity"]))
    return out


def scan(text: str, patterns: list[Pattern] | None = None) -> list[tuple[str, str]]:
    """Return (pattern name, secret) for every match in `text`."""
    hits = []
    for pattern in patterns or load():
        for m in pattern.regex.finditer(text):
            secret = m.group("secret")
            if not any(x.search(secret) for x in pattern.must_not_match):
                hits.append((pattern.name, secret))
    return hits
