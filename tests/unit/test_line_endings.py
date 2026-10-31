"""H1: every text file that ships in the wheel or in the repository uses LF line endings.

A CRLF checkout changes the bytes of packaged data (e.g. the Semgrep MANIFEST.json), so a
wheel built from a fresh clone and one built from such a working tree have different hashes.
"""

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
TEXT_SUFFIXES = {".py", ".pyi", ".json", ".toml", ".yaml", ".yml", ".txt", ".md", ".cfg"}


def _text_files(*roots: str) -> list[Path]:
    files = []
    for root in roots:
        base = ROOT / root
        candidates = [base] if base.is_file() else sorted(base.rglob("*"))
        files += [p for p in candidates if p.is_file() and p.suffix in TEXT_SUFFIXES
                  and "__pycache__" not in p.parts]  # fmt: skip
    return files


@pytest.mark.parametrize("scope", ["src", "schemas", "tests", "pyproject.toml"])
def test_text_files_use_lf_only(scope):
    offenders = [p.relative_to(ROOT).as_posix() for p in _text_files(scope)
                 if b"\r\n" in p.read_bytes()]  # fmt: skip
    assert offenders == [], f"CRLF line endings in: {offenders}"


def test_gitattributes_pins_lf_for_packaged_and_source_files():
    text = (ROOT / ".gitattributes").read_text(encoding="utf-8")
    for pattern in ("*.py text eol=lf", "*.json text eol=lf", "*.toml text eol=lf",
                    "*.yaml text eol=lf"):  # fmt: skip
        assert pattern in text, f"missing {pattern!r} in .gitattributes"
