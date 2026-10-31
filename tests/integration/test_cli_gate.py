"""Stage 6: the quality gate and the exit-code contract through the CLI (D-048)."""

import json

import pytest
from typer.testing import CliRunner

import auditor.application.audit_service as service
from auditor.cli import app
from auditor.core.models import (
    Confidence,
    Finding,
    FindingCategory,
    Severity,
    ToolExecution,
    ToolStatus,
    VerificationStatus,
)
from auditor.scanners.base import ScanOutcome

runner = CliRunner()


def fake_ruff(severities=(), status=ToolStatus.SUCCESS):
    class FakeRuff:
        name = "ruff"

        def __init__(self, *args, **kwargs):
            pass

        def scan(self, context):
            findings = [
                Finding(finding_id=f"ruff-{i}", fingerprint=f"{i:064d}", source_tool="ruff",
                        rule_id=f"R{i}", title="t", description="d",
                        category=FindingCategory.SECURITY, severity=s, confidence=Confidence.HIGH,
                        verification_status=VerificationStatus.NEEDS_REVIEW, relative_path="a.py",
                        start_line=i + 1)
                for i, s in enumerate(severities)
            ]  # fmt: skip
            return ScanOutcome(ToolExecution(tool="ruff", version="1", status=status,
                                             reason="r"), findings)  # fmt: skip

    return FakeRuff


def scan(monkeypatch, out_dir, root, *args, severities=(), status=ToolStatus.SUCCESS):
    monkeypatch.setattr(service, "RuffAdapter", fake_ruff(severities, status))
    result = runner.invoke(app, ["scan", str(root), "--output-dir", str(out_dir), *args])
    reports = list(out_dir.glob("*/report.json"))
    report = json.loads(reports[0].read_text("utf-8")) if reports else None
    return result, report


@pytest.mark.parametrize(
    ("args", "severities", "status", "code", "gate"),
    [
        ((), (Severity.CRITICAL,), ToolStatus.SUCCESS, 0, "NOT_EVALUATED"),
        (("--fail-on", "high"), (Severity.HIGH,), ToolStatus.SUCCESS, 4, "FAILED"),
        (("--fail-on", "critical"), (Severity.HIGH,), ToolStatus.SUCCESS, 0, "PASSED"),
        (("--fail-on", "high"), (Severity.UNRATED,), ToolStatus.SUCCESS, 4, "FAILED"),
        (("--fail-on", "high", "--unrated-as", "medium"), (Severity.UNRATED,),
         ToolStatus.SUCCESS, 0, "PASSED"),
        (("--fail-on", "high", "--unrated-as", "ignore"), (Severity.UNRATED,),
         ToolStatus.SUCCESS, 0, "PASSED"),
        ((), (), ToolStatus.ERROR, 3, "NOT_EVALUATED"),
        (("--fail-on", "low"), (), ToolStatus.ERROR, 3, "PASSED"),
        (("--fail-on", "medium"), (Severity.MEDIUM,), ToolStatus.ERROR, 4, "FAILED"),
    ],
)  # fmt: skip
def test_exit_code_matrix_through_the_cli(
    sample_repo, out_dir, monkeypatch, args, severities, status, code, gate
):
    result, report = scan(monkeypatch, out_dir, sample_repo, *args, severities=severities,
                          status=status)  # fmt: skip

    assert result.exit_code == code, result.output
    assert report["gate"]["status"] == gate
    partial = status is ToolStatus.ERROR
    assert report["coverage"]["status"] == ("PARTIAL" if partial else "COMPLETE")
    if gate == "FAILED":
        assert "QUALITY GATE FAILED" in result.output
    if partial:  # both states are visible, independently
        assert "WARNING: PARTIAL scan" in result.output
    unrated = [f for f in report["findings"] if f["severity"] == "UNRATED"]
    assert all(f["severity"] == "UNRATED" for f in unrated)  # the real severity is kept


@pytest.mark.parametrize(
    "args", [("--fail-on", "severe"), ("--fail-on", "unrated"), ("--unrated-as", "critical")]
)
def test_invalid_gate_options_are_invalid_input(sample_repo, out_dir, monkeypatch, args):
    result, report = scan(monkeypatch, out_dir, sample_repo, *args)

    assert result.exit_code == 2 and report is None


def test_disabled_areas_are_in_the_first_lines_and_complete_stays_complete(
    sample_repo, out_dir, monkeypatch
):
    result, report = scan(monkeypatch, out_dir, sample_repo, "--disable-scanner", "semgrep")

    head = result.output.splitlines()[:6]
    assert any(line.startswith("Disabled:  static_security (semgrep)") for line in head)
    area = next(a for a in report["coverage"]["areas"] if a["area"] == "static_security")
    assert area["status"] == "DISABLED" and report["coverage"]["status"] == "COMPLETE"
    assert result.exit_code == 0


def test_quiet_prints_only_the_summary(sample_repo, out_dir, monkeypatch):
    result, _ = scan(monkeypatch, out_dir, sample_repo, "--quiet")

    labels = [line.split(":")[0] for line in result.output.splitlines() if line]
    assert labels[:2] == ["AI Code Auditor - audit (read-only)".split(":")[0], "Target"]
    assert {"Status", "Coverage", "Total", "Gate", "Report"} <= set(labels)
    assert "Files" not in labels and "Legacy" not in labels


def test_areas_distinguish_not_requested_and_not_applicable(sample_repo, out_dir, monkeypatch):
    _, report = scan(monkeypatch, out_dir, sample_repo)
    states = {a["area"]: a["status"] for a in report["coverage"]["areas"]}

    assert states["secrets_history"] == "NOT_REQUESTED"
    assert states["code_quality"] == "COMPLETE"
    assert report["permissions"] == {"network": False, "git_history": False,
                                     "disabled_scanners": []}  # fmt: skip
