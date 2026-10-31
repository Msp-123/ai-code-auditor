"""H6 through the CLI: the context distribution is visible in the terminal and in report.md."""

import json

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
PATHS = ["src/app.py", "tests/test_app.py", "tests/test_b.py", "docs/guide.rst", "examples/demo.py"]


class FakeRuff:
    name = "ruff"

    def __init__(self, *args, **kwargs):
        pass

    def scan(self, context):
        findings = [
            Finding(finding_id=f"ruff-{i}", fingerprint=f"{i:064d}", source_tool="ruff",
                    rule_id="S105", title="t", description="d", category=FindingCategory.SECURITY,
                    severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
                    verification_status=VerificationStatus.NEEDS_REVIEW, relative_path=path,
                    start_line=1)
            for i, path in enumerate(PATHS)
        ]  # fmt: skip
        return ScanOutcome(ToolExecution(tool="ruff", version="1", status=ToolStatus.SUCCESS,
                                         reason="r"), findings)  # fmt: skip


def test_context_distribution_is_shown_and_declared_path_based(sample_repo, out_dir, monkeypatch):
    monkeypatch.setattr(service, "RuffAdapter", FakeRuff)

    result = runner.invoke(app, ["scan", str(sample_repo), "--output-dir", str(out_dir)])

    assert (
        "Context:   production 1, test 2, docs 1, examples 1 (path-based, not a security proof)"
        in result.output
    )
    (run_dir,) = out_dir.glob("2*")
    report = json.loads((run_dir / "report.json").read_text("utf-8"))
    assert report["outcome"]["by_context"] == {"docs": 1, "examples": 1, "production": 1, "test": 2}
    markdown = (run_dir / "report.md").read_text("utf-8")
    assert "- Context: production 1, test 2, docs 1, examples 1" in markdown
    assert "path-based, not a security proof" in markdown
    assert "[test]" in markdown and "[production]" in markdown  # per-finding context in the list
