"""Stage 6: untrusted text in every report field is neutralised (the nine places found in
step 0, D-048). Markdown: no HTML, no link, no table break, no control/bidi characters;
terminal: no control, ANSI or bidi characters."""

import re

from typer.testing import CliRunner

from auditor.application.audit_service import run_audit
from auditor.core.models import (
    Confidence,
    Finding,
    FindingCategory,
    LimitedFile,
    NotAnalyzedFile,
    NotAnalyzedReason,
    Severity,
    SuppressedFindings,
    ToolExecution,
    ToolStatus,
    VerificationStatus,
)
from auditor.reports.markdown_report import render_markdown
from auditor.reports.terminal_summary import summary
from auditor.scanners.base import ScanOutcome

HOSTILE = "a\x1b[31m‮​<img src=x onerror=alert(1)>[go](http://evil.invalid)|x|`b`*c*"


class Hostile:
    name = "ruff"

    def scan(self, context):
        execution = ToolExecution(
            tool="ruff", version=HOSTILE, status=ToolStatus.SUCCESS, reason=HOSTILE,
            warnings=[HOSTILE],
            suppressed=[SuppressedFindings(rule_id="S101", reason=HOSTILE, count=1)],
            coverage_limitations=[LimitedFile(relative_path="a.py", reason="X", detail=HOSTILE)],
            not_analyzed=[NotAnalyzedFile(relative_path=HOSTILE, reason=NotAnalyzedReason.IO_ERROR,
                                          detail=HOSTILE)],
            settings={"ruleset_version": HOSTILE},
        )  # fmt: skip
        finding = Finding(
            finding_id="ruff-1", fingerprint="1" * 64, source_tool="ruff", rule_id=HOSTILE,
            title=HOSTILE, description=HOSTILE, category=FindingCategory.SECURITY,
            severity=Severity.HIGH, confidence=Confidence.HIGH,
            verification_status=VerificationStatus.NEEDS_REVIEW, relative_path=HOSTILE,
            start_line=1,
        )  # fmt: skip
        return ScanOutcome(execution, [finding])


def prose(markdown: str) -> str:
    """The document without code spans (CommonMark never renders their content)."""
    unescaped = markdown.replace("\\`", "")
    return re.sub(r"(`+)(?:(?!\1).)*?\1", "", unescaped)


def test_hostile_text_cannot_change_the_markdown_document(sample_repo, out_dir):
    run = run_audit(sample_repo, out_dir, scanners=[Hostile()])
    markdown = render_markdown(run.audit)
    text = prose(markdown)

    assert "\x1b" not in markdown and "‮" not in markdown and "​" not in markdown
    assert "<img" not in text  # HTML neutralised (&lt;img)
    assert not re.search(r"(?<!\\)\]\(", text)  # no link can close
    assert not re.search(r"(?<!\\)\*c(?<!\\)\*", text)  # no emphasis
    columns, previous = None, ""
    for line in markdown.splitlines():
        if line.startswith("|"):
            cells = len(re.split(r"(?<!\\)\|", prose(line)))
            if not previous.startswith("|"):
                columns = cells  # header row of a new table
            assert cells == columns, line  # untrusted text never adds a column
        previous = line
    assert (out_dir / run.audit.run.run_id / "report.md").read_text("utf-8") == markdown


def test_hostile_text_cannot_reach_the_terminal_raw(sample_repo, out_dir):
    run = run_audit(sample_repo, out_dir, scanners=[Hostile()])

    out, err = summary(run.audit, run.reports)

    for line in out + err:
        assert not any(ord(c) < 32 for c in line), line
        assert "‮" not in line and "​" not in line


def test_the_cli_scan_output_is_safe_too(sample_repo, out_dir, monkeypatch):
    import auditor.application.audit_service as service
    from auditor.cli import app

    monkeypatch.setattr(service, "RuffAdapter", lambda *a, **k: Hostile())
    result = CliRunner().invoke(app, ["scan", str(sample_repo), "--output-dir", str(out_dir)])

    assert "\x1b" not in result.output and "‮" not in result.output
