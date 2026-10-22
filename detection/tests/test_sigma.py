"""Validate every Sigma rule and evaluate it against synthetic events.

Each rule is converted to SQL with the official pySigma SQLite backend and run against an
in-memory table built from sigma/tests/events.yml, so the test proves real matching
behaviour, not just YAML syntax.
"""

import sqlite3
from pathlib import Path

import pytest
import yaml
from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection
from sigma.validators.core import validators
from sigma.validation import SigmaValidator

ROOT = Path(__file__).resolve().parents[1] / "sigma"
RULE_FILES = sorted((ROOT / "rules").glob("*.yml"))
EVENTS = yaml.safe_load((ROOT / "tests" / "events.yml").read_text(encoding="utf-8"))


def _collection(path: Path) -> SigmaCollection:
    return SigmaCollection.from_yaml(path.read_text(encoding="utf-8"))


def _matches(rule_path: Path) -> set[str]:
    collection = _collection(rule_path)
    category = collection.rules[0].logsource.category
    events = EVENTS[category]
    columns = sorted({k for e in events for k in e})
    db = sqlite3.connect(":memory:")
    db.execute(f"CREATE TABLE logs ({', '.join(columns)})")
    db.executemany(
        f"INSERT INTO logs VALUES ({', '.join('?' for _ in columns)})",
        [tuple(e.get(c) for c in columns) for e in events],
    )
    hits: set[str] = set()
    for query in sqliteBackend().convert(collection):
        hits |= {row[columns.index("id")] for row in db.execute(query)}
    return hits


def test_rules_exist():
    assert len(RULE_FILES) >= 3


@pytest.mark.parametrize("rule_path", RULE_FILES, ids=lambda p: p.stem)
def test_rule_passes_pysigma_validators(rule_path):
    collection = _collection(rule_path)
    assert not collection.errors
    issues = SigmaValidator(validators.values()).validate_rules(collection)
    assert issues == [], [str(i) for i in issues]


@pytest.mark.parametrize("rule_path", RULE_FILES, ids=lambda p: p.stem)
def test_rule_has_expectations_and_metadata(rule_path):
    rule = _collection(rule_path).rules[0]
    assert str(rule.id) in {str(k) for k in EVENTS["expected"]}
    assert rule.falsepositives, "document false positives for the analyst"
    assert rule.level is not None


@pytest.mark.parametrize("rule_path", RULE_FILES, ids=lambda p: p.stem)
def test_rule_matches_exactly_the_expected_events(rule_path):
    rule_id = str(_collection(rule_path).rules[0].id)
    assert _matches(rule_path) == set(EVENTS["expected"][rule_id])
