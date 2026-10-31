"""H6: the canonical report gives every finding a path-based context (all tools alike)."""

import json
from datetime import UTC, datetime

from auditor.application.report_builder import build_audit_report
from auditor.core.audit_report import (
    REPORT_SCHEMA_VERSION,
    SUPPORTED_SCHEMA_VERSIONS,
    AuditReport,
    Permissions,
)
from auditor.core.models import (
    Confidence,
    FileContext,
    Finding,
    FindingCategory,
    LimitsSummary,
    RepositoryInventory,
    ScanStatus,
    Severity,
    VerificationStatus,
)
from auditor.reports.findings_report import legacy_finding

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def finding(**overrides):
    values = dict(
        finding_id="x-1", fingerprint="f" * 64, source_tool="ruff", rule_id="S105", title="t",
        description="d", category=FindingCategory.SECURITY, severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM, verification_status=VerificationStatus.NEEDS_REVIEW,
        relative_path="src/app.py", start_line=1,
    )  # fmt: skip
    values.update(overrides)
    return Finding(**values)


def inventory():
    return RepositoryInventory(
        run_id="20260101T000000Z-abcdef", started_at=NOW, finished_at=NOW, root_name="t",
        status=ScanStatus.COMPLETE, incomplete_reasons=[], vcs_metadata=[], entries_visited=0,
        unvisited_directories=0,
        limits=LimitsSummary(max_files=1, max_entries_visited=1, max_depth=1,
                             max_file_size_bytes=1, max_duration_seconds=1),
        files=[], excluded=[], scanners=[], warnings=[],
    )  # fmt: skip


def build(*findings):
    return build_audit_report(
        mode="audit", inventory=inventory(),
        permissions=Permissions(network=False, git_history=False, disabled_scanners=[]),
        status=ScanStatus.COMPLETE, incomplete_reasons=[], findings=list(findings),
    )  # fmt: skip


def test_every_finding_gets_a_context_and_its_basis_whatever_the_tool():
    audit = build(
        finding(finding_id="a", relative_path="src/app.py"),
        finding(
            finding_id="b", source_tool="semgrep", rule_id="x", relative_path="tests/test_a.py"
        ),
        finding(
            finding_id="c",
            source_tool="gitleaks-history",
            rule_id="gitleaks.generic-api-key",
            relative_path="docs/config.rst",
        ),  # fmt: skip
        finding(
            finding_id="d",
            source_tool="pip-audit",
            rule_id="p",
            relative_path="examples/requirements.txt",
        ),
        finding(
            finding_id="e",
            source_tool="gitleaks",
            rule_id="gitleaks.x",
            relative_path="deploy/app.yaml",
        ),
    )
    by_id = {f.finding_id: f for f in audit.findings}
    assert by_id["a"].context is FileContext.PRODUCTION
    assert (
        by_id["b"].context is FileContext.TEST and by_id["b"].context_basis == "directory 'tests'"
    )
    assert by_id["c"].context is FileContext.DOCS
    assert by_id["d"].context is FileContext.EXAMPLES
    assert by_id["e"].context is FileContext.CONFIG
    assert all(f.context_basis for f in audit.findings)


def test_a_redacted_path_has_unknown_context():
    (f,) = build(finding(relative_path="<redacted>", path_redacted=True)).findings
    assert f.context is FileContext.UNKNOWN and f.context_basis == "path redacted"


def test_the_test_path_tag_is_added_once_for_every_tool():
    audit = build(
        finding(finding_id="a", relative_path="tests/test_a.py"),
        finding(
            finding_id="b",
            source_tool="gitleaks",
            rule_id="gitleaks.x",
            relative_path="tests/data.txt",
            tags=["secret", "test-path"],
        ),  # fmt: skip
        finding(finding_id="c", relative_path="src/app.py", tags=["x"]),
    )
    tags = {f.finding_id: f.tags for f in audit.findings}
    assert tags["a"] == ["test-path"]
    assert tags["b"] == ["secret", "test-path"]  # not duplicated
    assert tags["c"] == ["x"]


def test_the_outcome_counts_findings_by_context():
    audit = build(
        finding(finding_id="a", relative_path="src/app.py"),
        finding(finding_id="b", relative_path="tests/test_a.py"),
        finding(finding_id="c", relative_path="tests/test_b.py"),
        finding(finding_id="d", relative_path="docs/x.rst"),
    )
    assert audit.outcome.by_context == {"docs": 1, "production": 1, "test": 2}


def test_legacy_findings_json_keeps_its_old_shape():
    data = legacy_finding(finding())
    assert "context" not in data and "context_basis" not in data


def test_schema_is_1_1_0_and_a_1_0_0_report_still_validates():
    assert REPORT_SCHEMA_VERSION == "1.1.0" and SUPPORTED_SCHEMA_VERSIONS == ("1.0.0", "1.1.0")
    audit = build(finding())
    old = json.loads(audit.model_dump_json())
    old["schema_version"] = "1.0.0"
    del old["findings"][0]["context"], old["findings"][0]["context_basis"]
    del old["outcome"]["by_context"]
    loaded = AuditReport.model_validate(old)
    assert loaded.findings[0].context is FileContext.UNKNOWN
    assert loaded.outcome.by_context == {}
