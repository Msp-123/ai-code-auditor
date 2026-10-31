import pytest
from pydantic import ValidationError

from auditor.core.models import (
    Confidence,
    Finding,
    FindingCategory,
    FindingsReport,
    IncompleteReason,
    NotAnalyzedFile,
    NotAnalyzedReason,
    ScanStatus,
    Severity,
    ToolExecution,
    ToolStatus,
    VerificationStatus,
)
from auditor.findings.fingerprint import compute_fingerprint


def make_finding(**overrides) -> Finding:
    data = {
        "finding_id": "ruff-0123456789abcdef",
        "fingerprint": "0" * 64,
        "source_tool": "ruff",
        "rule_id": "S602",
        "title": "subprocess-popen-with-shell-equals-true",
        "description": "`subprocess` call with `shell=True`",
        "category": FindingCategory.SECURITY,
        "severity": Severity.HIGH,
        "original_severity": "error",
        "confidence": Confidence.MEDIUM,
        "verification_status": VerificationStatus.NEEDS_REVIEW,
        "relative_path": "pkg/bad.py",
        "start_line": 3,
        "start_column": 1,
        "end_line": 3,
        "end_column": 30,
    }
    data.update(overrides)
    return Finding(**data)


def make_execution(**overrides) -> ToolExecution:
    data = {
        "tool": "ruff",
        "version": "0.17.3",
        "status": ToolStatus.SUCCESS,
        "reason": "Completed",
        "exit_codes": [1],
        "duration_seconds": 0.5,
        "files_requested": 2,
        "files_analyzed": 2,
    }
    data.update(overrides)
    return ToolExecution(**data)


def test_finding_round_trip():
    finding = make_finding()

    assert Finding.model_validate_json(finding.model_dump_json()) == finding


@pytest.mark.parametrize("status", list(VerificationStatus))
def test_shared_model_supports_every_verification_status(status):
    # CONFIRMED is reserved for a future independent verification step (e.g. Stage 11);
    # scanner adapters never produce it (see test_ruff_adapter / test_audit_service).
    assert make_finding(verification_status=status).verification_status is status


def test_line_numbers_must_be_positive():
    with pytest.raises(ValidationError):
        make_finding(start_line=0)


def test_findings_report_counts_and_round_trip():
    report = FindingsReport(
        run_id="r1",
        status=ScanStatus.PARTIAL,
        incomplete_reasons=[IncompleteReason.FILES_NOT_ANALYZED],
        tool_executions=[
            make_execution(
                not_analyzed=[
                    NotAnalyzedFile(relative_path="bad.py", reason=NotAnalyzedReason.PARSE_ERROR)
                ]
            )
        ],
        findings=[make_finding(), make_finding(finding_id="x", severity=Severity.LOW)],
    )

    dumped = report.model_dump(mode="json")
    assert dumped["findings_by_severity"] == {"HIGH": 1, "LOW": 1}
    assert FindingsReport.model_validate_json(report.model_dump_json()) == report


def test_findings_report_status_must_match_reasons():
    with pytest.raises(ValidationError, match="PARTIAL"):
        FindingsReport(
            run_id="r1",
            status=ScanStatus.COMPLETE,
            incomplete_reasons=[IncompleteReason.SCANNER_ERROR],
            tool_executions=[],
            findings=[],
        )


def test_fingerprint_is_stable_and_distinguishes_columns_and_messages():
    base = {
        "tool": "ruff",
        "rule_id": "F401",
        "relative_path": "a.py",
        "start": (1, 8),
        "end": (1, 10),
        "message": "`os` imported but unused",
    }
    first = compute_fingerprint(**base)

    assert first == compute_fingerprint(**base)
    assert len(first) == 64
    assert first != compute_fingerprint(**{**base, "start": (1, 12)})
    assert first != compute_fingerprint(**{**base, "message": "`sys` imported but unused"})
    assert first != compute_fingerprint(**{**base, "relative_path": "b.py"})
