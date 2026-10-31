"""Audit orchestration: scanner outcomes are turned into honest overall coverage."""

import pytest

from auditor.application.audit_service import run_audit
from auditor.core.models import ToolExecution, ToolStatus
from auditor.scanners.base import ScanOutcome


class _Exploding:
    name = "ruff"

    def scan(self, context):
        raise KeyError("adapter bug")


class _Fixed:
    name = "ruff"

    def __init__(self, status):
        self.status = status

    def scan(self, context):
        return ScanOutcome(
            ToolExecution(tool="ruff", version="0", status=self.status, reason="test"), []
        )


def test_adapter_bug_becomes_error_not_a_clean_result(sample_repo, out_dir):
    run = run_audit(sample_repo, out_dir, scanners=[_Exploding()])

    (execution,) = run.findings.tool_executions
    assert execution.status is ToolStatus.ERROR
    assert "KeyError" in execution.reason
    assert run.findings.status.value == "PARTIAL"
    assert [r.value for r in run.findings.incomplete_reasons] == ["SCANNER_ERROR"]


@pytest.mark.parametrize(
    ("status", "reason"),
    [
        (ToolStatus.SUCCESS, None),
        (ToolStatus.SKIPPED, None),
        (ToolStatus.ERROR, "SCANNER_ERROR"),
        (ToolStatus.TIMED_OUT, "SCANNER_TIMED_OUT"),
        (ToolStatus.NOT_INSTALLED, "SCANNER_NOT_INSTALLED"),
    ],
)
def test_scanner_status_maps_to_overall_coverage(sample_repo, out_dir, status, reason):
    run = run_audit(sample_repo, out_dir, scanners=[_Fixed(status)])

    assert [r.value for r in run.findings.incomplete_reasons] == ([reason] if reason else [])


class _OverconfidentScanner:
    """A (buggy or future) adapter that claims a finding is CONFIRMED."""

    name = "ruff"

    def scan(self, context):
        from auditor.core.models import (
            Confidence,
            Finding,
            FindingCategory,
            Severity,
            VerificationStatus,
        )

        finding = Finding(
            finding_id="x",
            fingerprint="0" * 64,
            source_tool="ruff",
            rule_id="S602",
            title="t",
            description="d",
            category=FindingCategory.SECURITY,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            verification_status=VerificationStatus.CONFIRMED,
            relative_path="setup.py",
        )
        return ScanOutcome(
            ToolExecution(tool="ruff", version="0", status=ToolStatus.SUCCESS, reason="ok"),
            [finding],
        )


def test_scanner_output_is_never_accepted_as_confirmed(sample_repo, out_dir):
    run = run_audit(sample_repo, out_dir, scanners=[_OverconfidentScanner()])

    (finding,) = run.findings.findings
    assert finding.verification_status.value == "NEEDS_REVIEW"
    assert any("CONFIRMED" in w for w in run.findings.tool_executions[0].warnings)


def test_discovery_partial_carries_into_the_audit(make_tree, out_dir):
    from auditor.core.policy import ScanPolicy

    root = make_tree({f"f{i}.py": "" for i in range(5)})

    run = run_audit(root, out_dir, ScanPolicy(max_files=2), scanners=[_Fixed(ToolStatus.SUCCESS)])

    assert [r.value for r in run.findings.incomplete_reasons] == ["MAX_FILES"]
