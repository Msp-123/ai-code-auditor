"""File names must not be able to spoof or break reports and terminal output."""

import os

import pytest
from typer.testing import CliRunner

from auditor.cli import app


def scan_and_read(root, out_dir):
    result = CliRunner().invoke(app, ["scan", str(root), "--output-dir", str(out_dir)])
    assert result.exit_code == 0, result.output
    run_dir = next(out_dir.iterdir())
    return result.output, (run_dir / "report.md").read_text(encoding="utf-8")


def test_bidi_override_in_names_is_escaped_in_markdown_and_terminal(make_tree, out_dir):
    # "‮" makes "evil‮yp.exe" render as "evilexe.py" in many viewers.
    root = make_tree({".env‮yp.exe": "X"}, name="proj‮txt")

    terminal, markdown = scan_and_read(root, out_dir)

    assert "‮" not in markdown
    assert "‮" not in terminal
    assert "\\u202e" in markdown


def test_zero_width_and_fullwidth_env_lookalikes_are_sensitive(make_tree, out_dir):
    root = make_tree({".e​nv": "X", "．ｅｎｖ": "Y", "app.py": ""})

    _, markdown = scan_and_read(root, out_dir)

    assert "2 file(s) match sensitive-file patterns" in markdown


def test_markdown_syntax_in_names_cannot_inject_structure(make_tree, out_dir):
    # Sensitive (*.pem) files are listed by name in report.md, so they exercise rendering.
    names = ["# Injected heading.pem", "a`b``c.pem", "[link](http-x).pem", "__bold__.pem"]
    if os.name != "nt":  # characters that are invalid in Windows file names
        names += ["pipe|cell.pem", "*star*.pem"]
    root = make_tree({name: "" for name in names})

    _, markdown = scan_and_read(root, out_dir)
    lines = markdown.splitlines()

    assert not any(line.startswith("# Injected") for line in lines)
    for name in names:
        stem = name.removesuffix(".pem")[:6]
        listed = [line for line in lines if stem in line]
        assert listed, f"{name!r} not listed"
        assert all(line.startswith("- `") for line in listed)  # always a code span item


@pytest.mark.skipif(os.name == "nt", reason="newlines/escape chars are invalid in Windows names")
def test_control_characters_in_names_cannot_forge_report_lines(make_tree, out_dir):
    root = make_tree({"app.py": ""})
    (root / ".env\n## FORGED SECTION").write_text("", encoding="utf-8")
    (root / ".env\x1b[2J").write_text("", encoding="utf-8")

    terminal, markdown = scan_and_read(root, out_dir)

    assert "\n## FORGED SECTION" not in markdown
    assert "\x1b" not in markdown and "\x1b" not in terminal
