"""Lint the runbooks and the repository's Markdown.

- Runbooks (RB-*.md) must have the standard sections, in order.
- Relative links in any Markdown file must point at files that exist.
- No e-mail address outside example.com/example.org and nothing shaped like a phone number.

Usage: python runbooks/runbook_lint.py   (exit 1 on any finding)
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SECTIONS = [
    "Trigger",
    "Severity",
    "Roles",
    "Detect and analyze",
    "Contain",
    "Eradicate",
    "Recover",
    "Evidence to keep",
    "Communication",
    "Post-incident",
]
LINK = re.compile(r"\]\(([^)\s]+)\)")
EMAIL = re.compile(r"[\w.+-]+@([\w-]+\.)+[a-z]{2,}", re.IGNORECASE)
PHONE = re.compile(r"(?<![\w.-])(\+?\d{1,3}[ .-])?\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}(?![\w.-])")
ALLOWED_EMAIL_DOMAINS = ("example.com", "example.org", "example.net")
SKIP_DIRS = {".git", ".venv", "node_modules", ".terraform", "data"}


def markdown_files(root: Path = REPO) -> list[Path]:
    return sorted(p for p in root.rglob("*.md") if not SKIP_DIRS.intersection(p.relative_to(root).parts))


def section_errors(text: str) -> list[str]:
    found = [line[3:].strip() for line in text.splitlines() if line.startswith("## ")]
    if found != SECTIONS:
        return [f"sections are {found}, expected {SECTIONS}"]
    return []


def link_errors(path: Path) -> list[str]:
    errors = []
    for target in LINK.findall(path.read_text(encoding="utf-8")):
        if re.match(r"^[a-z]+:", target) or target.startswith("#"):
            continue
        file_part = target.split("#", 1)[0]
        if file_part and not (path.parent / file_part).exists():
            errors.append(f"broken link {target!r}")
    return errors


def privacy_errors(text: str) -> list[str]:
    errors = []
    for match in EMAIL.finditer(text):
        if not match.group(0).lower().endswith(ALLOWED_EMAIL_DOMAINS):
            errors.append(f"e-mail address outside example domains: {match.group(0)}")
    for match in PHONE.finditer(text):
        errors.append(f"phone-like number: {match.group(0)}")
    return errors


def lint(root: Path = REPO) -> list[str]:
    findings = []
    for path in markdown_files(root):
        rel = path.relative_to(root).as_posix()
        text = path.read_text(encoding="utf-8")
        problems = link_errors(path) + privacy_errors(text)
        if path.parent.name == "runbooks" and path.name.startswith("RB-"):
            problems += section_errors(text)
        findings += [f"{rel}: {p}" for p in problems]
    return findings


def main() -> int:
    findings = lint()
    for finding in findings:
        print(finding)
    print(f"{len(markdown_files())} markdown files, {len(findings)} findings")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
