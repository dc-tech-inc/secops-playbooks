"""Compile the YARA rules and test them against the EICAR string and benign files only.

The EICAR test string is assembled in memory (reversed below) and never written to disk,
so antivirus on a contributor's machine does not quarantine the repository.
"""

import secrets
from pathlib import Path

import pytest
import yara

ROOT = Path(__file__).resolve().parents[1] / "yara"
RULES = yara.compile(filepaths={p.stem: str(p) for p in (ROOT / "rules").glob("*.yar")})
BENIGN = sorted((ROOT / "tests" / "benign").iterdir())

EICAR = "*H+H$!ELIF-TSET-SURIVITNA-DRADNATS-RACIE$}7)CC7)^P(45XZP\\4[PA@%P!O5X"[::-1].encode()


def _names(data: bytes) -> set[str]:
    return {m.rule for m in RULES.match(data=data)}


def test_eicar_string_is_the_spec_length():
    assert len(EICAR) == 68


def test_eicar_matches():
    assert _names(EICAR) == {"EICAR_Test_File"}


def test_eicar_with_trailing_whitespace_matches():
    assert "EICAR_Test_File" in _names(EICAR + b"\r\n")


@pytest.mark.parametrize(
    "data",
    [
        b"padding " + EICAR,  # not at offset 0
        EICAR[:-1],  # truncated
        EICAR + b" " * 100,  # too large for the spec
    ],
    ids=["offset", "truncated", "oversized"],
)
def test_eicar_near_misses_do_not_match(data):
    assert "EICAR_Test_File" not in _names(data)


def test_canary_marker_ascii_and_utf16():
    marker = f"EXCO-CANARY-{secrets.token_hex(8)}"
    assert _names(f"Board pack Q3\n{marker}\n".encode()) == {"ExampleCo_Canary_Document"}
    assert _names(f"Board pack {marker}".encode("utf-16-le")) == {"ExampleCo_Canary_Document"}


@pytest.mark.parametrize("path", BENIGN, ids=lambda p: p.name)
def test_benign_files_do_not_match(path):
    assert RULES.match(str(path)) == []
