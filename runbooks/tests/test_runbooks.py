from pathlib import Path

import pytest

import runbook_lint

RUNBOOKS = sorted((runbook_lint.REPO / "runbooks").glob("RB-*.md"))


def test_there_are_runbooks_and_a_tabletop():
    assert len(RUNBOOKS) >= 4
    assert list((runbook_lint.REPO / "runbooks" / "tabletop").glob("TT-*.md"))


@pytest.mark.parametrize("path", RUNBOOKS, ids=lambda p: p.stem)
def test_runbook_sections(path):
    assert runbook_lint.section_errors(path.read_text(encoding="utf-8")) == []


def test_repository_markdown_is_clean():
    assert runbook_lint.lint() == []


def test_main_reports_clean(capsys):
    assert runbook_lint.main() == 0
    assert "0 findings" in capsys.readouterr().out


def test_section_errors_detects_order_and_missing():
    text = "\n".join(f"## {s}" for s in reversed(runbook_lint.SECTIONS))
    assert runbook_lint.section_errors(text)
    assert runbook_lint.section_errors("## Trigger\n")


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("contact soc@example.com", 0),
        ("contact someone@realcompany.io", 1),
        ("call 704-555-0100 now", 1),
        ("call (704) 555 0100 now", 1),
        ("CVE-2024-3094 and rule 942200 and 10.10.20.0/23", 0),
        ("version 1.2.3 released 2026-10-22", 0),
    ],
)
def test_privacy_errors(text, expected):
    assert len(runbook_lint.privacy_errors(text)) == expected


def test_link_errors(tmp_path: Path):
    (tmp_path / "ok.md").write_text("x", encoding="utf-8")
    doc = tmp_path / "doc.md"
    doc.write_text("[a](ok.md) [b](missing.md) [c](https://example.com) [d](#top) [e](ok.md#part)", encoding="utf-8")
    assert runbook_lint.link_errors(doc) == ["broken link 'missing.md'"]


def test_lint_flags_runbook_problems(tmp_path: Path):
    rb = tmp_path / "runbooks"
    rb.mkdir()
    (rb / "RB-99-test.md").write_text("## Trigger\nmail admin@corp.test\n[x](nope.md)\n", encoding="utf-8")
    findings = runbook_lint.lint(tmp_path)
    assert len(findings) == 3
