"""Stage 6 step 4: quality gate and the exit-code matrix (D-048)."""

import pytest

from auditor.core.audit_report import GateStatus
from auditor.core.models import (
    Confidence,
    Finding,
    FindingCategory,
    ScanStatus,
    Severity,
    VerificationStatus,
)
from auditor.findings.gate import (
    EXIT_GATE_FAILED,
    EXIT_INTERNAL_ERROR,
    EXIT_INVALID_INPUT,
    EXIT_OK,
    EXIT_PARTIAL,
    GatePolicy,
    decide_exit,
    evaluate_gate,
    parse_policy,
)


def f(fid, severity):
    return Finding(finding_id=fid, fingerprint=fid, source_tool="x", rule_id="r", title="t",
                   description="d", category=FindingCategory.SECURITY, severity=severity,
                   confidence=Confidence.HIGH, verification_status=VerificationStatus.NEEDS_REVIEW,
                   relative_path="a.py")  # fmt: skip


FINDINGS = [f("c", Severity.CRITICAL), f("h", Severity.HIGH), f("u", Severity.UNRATED),
            f("m", Severity.MEDIUM), f("l", Severity.LOW), f("i", Severity.INFO)]  # fmt: skip


def test_default_policy_does_not_evaluate():
    result = evaluate_gate(FINDINGS, GatePolicy())

    assert result.status is GateStatus.NOT_EVALUATED and result.fail_on == "none"
    assert result.unrated_as == "high"  # user decision K3


@pytest.mark.parametrize(
    ("fail_on", "unrated_as", "counted"),
    [
        ("critical", "high", {"c"}),
        ("high", "high", {"c", "h", "u"}),  # UNRATED counts as HIGH by default
        ("high", "medium", {"c", "h"}),
        ("high", "ignore", {"c", "h"}),
        ("medium", "medium", {"c", "h", "u", "m"}),
        ("medium", "ignore", {"c", "h", "m"}),
        ("low", "high", {"c", "h", "u", "m", "l"}),  # INFO is below LOW
    ],
)
def test_thresholds_and_unrated_mapping(fail_on, unrated_as, counted):
    result = evaluate_gate(FINDINGS, parse_policy(fail_on, unrated_as))

    assert result.status is GateStatus.FAILED
    assert set(result.counted_finding_ids) == counted and result.counted == len(counted)


def test_the_gate_never_changes_a_findings_severity():
    findings = list(FINDINGS)

    evaluate_gate(findings, parse_policy("high", "high"))

    assert [x.severity for x in findings] == [x.severity for x in FINDINGS]


def test_no_finding_at_or_above_the_threshold_passes():
    result = evaluate_gate([f("l", Severity.LOW)], parse_policy("medium", "high"))

    assert result.status is GateStatus.PASSED and result.counted == 0


@pytest.mark.parametrize(("value", "message"), [("severe", "fail-on"), ("unrated", "fail-on")])
def test_invalid_policy_values_are_rejected(value, message):
    with pytest.raises(ValueError, match=message):
        parse_policy(value, "high")
    with pytest.raises(ValueError, match="unrated-as"):
        parse_policy("high", "critical-ish")


@pytest.mark.parametrize(
    ("coverage", "gate", "expected"),
    [
        (ScanStatus.COMPLETE, GateStatus.NOT_EVALUATED, EXIT_OK),
        (ScanStatus.COMPLETE, GateStatus.PASSED, EXIT_OK),
        (ScanStatus.COMPLETE, GateStatus.FAILED, EXIT_GATE_FAILED),
        (ScanStatus.PARTIAL, GateStatus.NOT_EVALUATED, EXIT_PARTIAL),
        (ScanStatus.PARTIAL, GateStatus.PASSED, EXIT_PARTIAL),
        (ScanStatus.PARTIAL, GateStatus.FAILED, EXIT_GATE_FAILED),  # gate before partial
    ],
)
def test_exit_code_matrix(coverage, gate, expected):
    assert decide_exit(coverage, gate) == expected


def test_exit_code_values_are_the_documented_contract():
    assert (EXIT_OK, EXIT_INTERNAL_ERROR, EXIT_INVALID_INPUT, EXIT_PARTIAL, EXIT_GATE_FAILED) == (
        0, 1, 2, 3, 4)  # fmt: skip
