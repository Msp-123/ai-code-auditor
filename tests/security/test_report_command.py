"""``auditor report <RUN_ID>``: read-only, untrusted input, no scanner, git or network (D-048)."""

import hashlib
import json
import socket
import subprocess
import sys

import pytest
from typer.testing import CliRunner

from auditor.application.audit_service import run_audit
from auditor.cli import app
from auditor.reports.loader import ReportLoadError, load_report

runner = CliRunner()


@pytest.fixture
def stored(sample_repo, out_dir):
    run = run_audit(sample_repo, out_dir, scanners=[])
    return run, out_dir


def report(*args):
    return runner.invoke(app, ["report", *map(str, args)])


@pytest.fixture
def no_processes_or_network(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("auditor report must not start a process or open a socket")

    monkeypatch.setattr(subprocess, "Popen", refuse)
    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


@pytest.mark.parametrize("fmt", ["summary", "markdown", "json"])
def test_a_stored_report_is_shown_without_any_process_or_network(
    stored, no_processes_or_network, fmt
):
    run, out_dir = stored

    result = report(run.audit.run.run_id, "--reports-dir", out_dir, "--format", fmt)

    assert result.exit_code == 0, result.output
    if fmt == "json":
        assert json.loads(result.output)["run"]["run_id"] == run.audit.run.run_id
    elif fmt == "markdown":
        assert result.output.startswith("# AI Code Auditor - Audit Report")
    else:
        assert "Status:" in result.output and "Gate:" in result.output


@pytest.mark.parametrize(
    "run_id",
    [
        "..", "../x", "..\\..\\Windows", "C:\\Windows", "\\\\server\\share", "\\\\?\\C:\\x",
        "CON", "NUL", "aux.txt", "20261030T120000Z-1a2b3c:ads", "20261030T120000Z-1A2B3C",
        ".20261030T120000Z-1a2b3c.incomplete", "20261030T120000Z-1a2b3c/../x", "",
    ],
)  # fmt: skip
def test_run_ids_outside_the_strict_pattern_are_refused(stored, run_id):
    _, out_dir = stored

    with pytest.raises(ReportLoadError, match="invalid run id"):
        load_report(run_id, out_dir)
    assert report(run_id, "--reports-dir", out_dir).exit_code == 2


def _run_dir(stored):
    run, out_dir = stored
    return run.audit.run.run_id, out_dir, out_dir / run.audit.run.run_id


def test_a_changed_file_is_detected(stored):
    run_id, out_dir, run_dir = _run_dir(stored)
    (run_dir / "report.json").write_bytes((run_dir / "report.json").read_bytes() + b" ")

    with pytest.raises(ReportLoadError, match="does not match the integrity record"):
        load_report(run_id, out_dir)


def test_a_run_without_integrity_record_is_refused(stored):
    run_id, out_dir, run_dir = _run_dir(stored)
    (run_dir / "SHA256SUMS.json").unlink()

    with pytest.raises(ReportLoadError, match="no integrity record"):
        load_report(run_id, out_dir)


def test_a_consistent_but_invalid_report_is_refused(stored):
    """Changing a report and its record together passes the hash (not a signature), but an
    invalid document still fails the schema."""
    run_id, out_dir, run_dir = _run_dir(stored)
    (run_dir / "report.json").write_text('{"report_schema": "something else"}', encoding="utf-8")
    record = json.loads((run_dir / "SHA256SUMS.json").read_text("utf-8"))
    record["files"]["report.json"] = hashlib.sha256(
        (run_dir / "report.json").read_bytes()
    ).hexdigest()
    (run_dir / "SHA256SUMS.json").write_text(json.dumps(record), encoding="utf-8")

    with pytest.raises(ReportLoadError, match="v1 report schema"):
        load_report(run_id, out_dir)


@pytest.mark.parametrize("entry", ["../outside.json", "report.json\\..\\x", "evil.exe"])
def test_an_integrity_record_cannot_point_to_other_files(stored, entry):
    run_id, out_dir, run_dir = _run_dir(stored)
    record = json.loads((run_dir / "SHA256SUMS.json").read_text("utf-8"))
    record["files"][entry] = "0" * 64
    (run_dir / "SHA256SUMS.json").write_text(json.dumps(record), encoding="utf-8")

    with pytest.raises(ReportLoadError, match="unexpected entry"):
        load_report(run_id, out_dir)


@pytest.mark.skipif(sys.platform != "win32", reason="NTFS junctions are Windows-only")
def test_a_run_directory_swapped_for_a_junction_is_not_followed(stored, junction, tmp_path):
    import shutil

    run_id, out_dir, run_dir = _run_dir(stored)
    elsewhere = tmp_path / "elsewhere"
    shutil.copytree(run_dir, elsewhere)
    shutil.rmtree(run_dir)
    junction(run_dir, elsewhere)

    with pytest.raises(ReportLoadError, match="link or junction"):
        load_report(run_id, out_dir)


def test_oversized_files_are_refused(stored, monkeypatch):
    import auditor.reports.loader as loader

    run_id, out_dir, _ = _run_dir(stored)
    monkeypatch.setattr(loader, "MAX_REPORT_BYTES", 10)

    with pytest.raises(ReportLoadError, match="cannot be read safely"):
        load_report(run_id, out_dir)


def test_hostile_report_content_is_escaped_in_every_format(stored):
    """A consistent (re-hashed) report with hostile text cannot inject into terminal/Markdown."""
    run_id, out_dir, run_dir = _run_dir(stored)
    data = json.loads((run_dir / "report.json").read_text("utf-8"))
    hostile = "x\x1b[2J\u202e<script>alert(1)</script>[click](http://evil.invalid) | `"
    data["target_name"] = hostile
    data["warnings"] = [hostile]
    (run_dir / "report.json").write_text(json.dumps(data), encoding="utf-8")
    record = json.loads((run_dir / "SHA256SUMS.json").read_text("utf-8"))
    record["files"]["report.json"] = hashlib.sha256(
        (run_dir / "report.json").read_bytes()
    ).hexdigest()
    (run_dir / "SHA256SUMS.json").write_text(json.dumps(record), encoding="utf-8")

    for fmt in ("summary", "markdown"):  # terminal: no control/ANSI/bidi characters
        output = report(run_id, "--reports-dir", out_dir, "--format", fmt).output
        assert "\x1b" not in output and "\u202e" not in output
    # Markdown additionally: no HTML and no link syntax outside code spans (whose content
    # CommonMark never renders as HTML or links); a terminal renders neither
    import re

    unescaped = output.replace("\\`", "")  # an escaped backtick opens no code span
    prose = re.sub(r"(`+)(?:(?!\1).)*?\1", "", unescaped)
    assert "<script>" not in prose
    assert not re.search(r"(?<!\\)\]\(", prose)  # an escaped "\]" can never close a link
    assert "&lt;script\\>" in prose and "\\[click\\]" in prose  # the warning, escaped
