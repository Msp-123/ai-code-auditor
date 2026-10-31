"""Stage 6 step 1: the canonical v1 report model, UNRATED, identifiers and the JSON Schema."""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from auditor.core.audit_report import (
    REPORT_SCHEMA_ID,
    SUPPORTED_SCHEMA_VERSIONS,
    AreaStatus,
    AuditReport,
    CoverageArea,
    report_json_schema,
)
from auditor.core.models import (
    SEVERITY_RANK,
    Confidence,
    Finding,
    FindingCategory,
    FindingIdentifiers,
    ScanStatus,
    Severity,
    VerificationStatus,
)
from auditor.reports.findings_report import legacy_finding

SCHEMA_FILE = Path(__file__).resolve().parents[2] / "schemas" / "report-v1.schema.json"


def finding(**overrides):
    values = dict(
        finding_id="x-1", fingerprint="f" * 64, source_tool="pip-audit",
        rule_id="pip-audit.PYSEC-1", title="t", description="d",
        category=FindingCategory.SECURITY, severity=Severity.UNRATED,
        original_severity="UNRATED", confidence=Confidence.HIGH,
        verification_status=VerificationStatus.NEEDS_REVIEW, relative_path="requirements.txt",
        start_line=1,
    )  # fmt: skip
    values.update(overrides)
    return Finding(**values)


def test_unrated_is_a_severity_ranked_after_high():
    assert Severity.UNRATED in Severity
    ranked = sorted(Severity, key=SEVERITY_RANK.__getitem__)
    assert ranked == [Severity.CRITICAL, Severity.HIGH, Severity.UNRATED, Severity.MEDIUM,
                      Severity.LOW, Severity.INFO]  # fmt: skip


def test_legacy_findings_keep_the_medium_placeholder_and_the_old_fields():
    f = finding(identifiers=FindingIdentifiers(package="jinja2", version="2.10",
                                               vulnerability_ids=["PYSEC-1"]),
                group_ids=["g1"])  # fmt: skip

    legacy = legacy_finding(f)

    assert (legacy["severity"], legacy["original_severity"]) == ("MEDIUM", "UNRATED")
    assert "identifiers" not in legacy and "group_ids" not in legacy
    other = legacy_finding(finding(severity=Severity.HIGH, original_severity="error"))
    assert other["severity"] == "HIGH"  # other scanners are untouched


def test_working_tree_content_ids_never_leave_the_process():
    f = finding(content_ids={"sha1": "a" * 40})

    assert "content_ids" not in f.model_dump() and "a" * 40 not in f.model_dump_json()
    assert f.content_ids == {"sha1": "a" * 40}
    assert "content_ids" not in json.dumps(report_json_schema())


def test_the_committed_json_schema_matches_the_model():
    committed = json.loads(SCHEMA_FILE.read_text(encoding="utf-8"))

    assert committed == report_json_schema()
    assert committed["properties"]["schema_version"]["enum"] == list(SUPPORTED_SCHEMA_VERSIONS)
    assert committed["properties"]["report_schema"]["const"] == REPORT_SCHEMA_ID


def _area(name, status):
    return CoverageArea(area=name, tool=None, status=status, reason="r")


@pytest.mark.parametrize(
    "status", [AreaStatus.PARTIAL, AreaStatus.FAILED, AreaStatus.NOT_PERMITTED]
)
def test_complete_is_impossible_with_an_incomplete_area(status, minimal_report):
    with pytest.raises(ValueError, match="COMPLETE"):
        minimal_report(ScanStatus.COMPLETE, [_area("dependencies", status)])


@pytest.mark.parametrize(
    "status",
    [AreaStatus.COMPLETE, AreaStatus.NOT_APPLICABLE, AreaStatus.NOT_REQUESTED, AreaStatus.DISABLED],
)
def test_complete_is_allowed_with_these_area_states(status, minimal_report):
    report = minimal_report(ScanStatus.COMPLETE, [_area("secrets_history", status)])

    assert report.coverage.status is ScanStatus.COMPLETE


@pytest.fixture
def minimal_report():
    from auditor.core.audit_report import Coverage, GateResult, Outcome, Permissions, RunInfo
    from auditor.core.models import LimitsSummary, RepositoryInventory

    now = datetime(2026, 1, 1, tzinfo=UTC)

    def make(status, areas):
        inventory = RepositoryInventory(
            run_id="20260101T000000Z-abcdef", started_at=now, finished_at=now, root_name="t",
            status=ScanStatus.COMPLETE, incomplete_reasons=[], vcs_metadata=[],
            entries_visited=0, unvisited_directories=0,
            limits=LimitsSummary(max_files=1, max_entries_visited=1, max_depth=1,
                                 max_file_size_bytes=1, max_duration_seconds=1),
            files=[], excluded=[], scanners=[], warnings=[],
        )  # fmt: skip
        return AuditReport(
            mode="audit",
            run=RunInfo(run_id=inventory.run_id, started_at=now, finished_at=now,
                        duration_seconds=0.0, auditor_version="0", platform="x", python="3"),
            target_name="t",
            permissions=Permissions(network=False, git_history=False, disabled_scanners=[]),
            coverage=Coverage(status=status, incomplete_reasons=[] if status is
                              ScanStatus.COMPLETE else ["SCANNER_ERROR"], areas=areas),
            outcome=Outcome.empty(),
            gate=GateResult.not_evaluated(),
            discovery=inventory,
        )  # fmt: skip

    return make
