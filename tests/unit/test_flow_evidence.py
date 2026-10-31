"""H5: applying verified data flows to findings (upgrade only, never create, never drop)."""

import textwrap

from auditor.core.models import (
    Confidence,
    Finding,
    FindingCategory,
    Severity,
    VerificationStatus,
)
from auditor.findings.flow_verification import FlowObservation, apply_flow_evidence

VIEW = """
    from flask import request
    import lib
    def v():
        return lib.find(request.form["u"])
    def seed():
        return lib.find("constant")
"""
LIB = """
    import sqlite3
    def find(name):
        c = sqlite3.connect("db").cursor()
        return c.execute("SELECT * FROM t WHERE n = '%s'" % name).fetchall()
    def other(name):
        c = sqlite3.connect("db").cursor()
        return c.execute("SELECT * FROM t WHERE n = '%s'" % name).fetchall()
"""


def finding(**overrides):
    values = dict(
        finding_id="f", fingerprint="0" * 64, source_tool="semgrep",
        rule_id="auditor.python.sql-injection.formatted-sql-query", title="t", description="d",
        category=FindingCategory.SECURITY, severity=Severity.MEDIUM, original_severity="WARNING",
        confidence=Confidence.MEDIUM, verification_status=VerificationStatus.NEEDS_REVIEW,
        relative_path="lib.py", start_line=4,
    )  # fmt: skip
    values.update(overrides)
    return Finding(**values)


def project(tmp_path):
    for name, text in {"view.py": VIEW, "lib.py": LIB}.items():
        (tmp_path / name).write_text(textwrap.dedent(text).lstrip("\n"), encoding="utf-8")
    return tmp_path


def observations():
    # what the Semgrep adapter extracts from the two evidence rules (1-based columns)
    return [
        FlowObservation(kind="sql_sink", relative_path="lib.py", line=4, column=16),
        FlowObservation(kind="sql_sink", relative_path="lib.py", line=7, column=16),
        FlowObservation(kind="request_call", relative_path="view.py", line=4, column=21),
    ]


def test_verified_locations_are_upgraded_and_everything_else_is_untouched(tmp_path):
    root = project(tmp_path)
    before = [
        finding(finding_id="semgrep-a"),
        finding(finding_id="ruff-a", source_tool="ruff", rule_id="S608", original_severity=None),
        finding(finding_id="semgrep-b", start_line=7),  # `other` is never called with request data
        finding(finding_id="ruff-x", source_tool="ruff", rule_id="S105", start_line=4),
    ]

    after, verified = apply_flow_evidence(root, before, observations())

    by_id = {f.finding_id: f for f in after}
    assert len(after) == len(before) and verified == 1  # one location, nothing created or lost
    for fid in ("semgrep-a", "ruff-a"):
        f = by_id[fid]
        assert f.severity is Severity.HIGH and f.confidence is Confidence.HIGH
        assert f.verification_status is VerificationStatus.NEEDS_REVIEW  # never CONFIRMED
        assert "verified-data-flow" in f.tags
        assert f.fingerprint == "0" * 64  # identity unchanged
    assert by_id["semgrep-a"].original_severity == "WARNING"
    assert by_id["semgrep-b"].severity is Severity.MEDIUM and by_id["semgrep-b"].evidence == []
    assert by_id["ruff-x"].severity is Severity.MEDIUM


def test_evidence_holds_only_locations_and_names(tmp_path):
    root = project(tmp_path)

    (f, *_), _ = apply_flow_evidence(root, [finding()], observations())

    (evidence,) = f.evidence
    assert evidence.kind == "verified_data_flow"
    assert evidence.reference == "view.py:4 request data -> find(name) -> lib.py:4 SQL text"
    assert "request.form" not in evidence.reference and "SELECT" not in evidence.reference
    assert str(root) not in evidence.reference


def test_without_a_verified_flow_nothing_changes(tmp_path):
    root = project(tmp_path)
    before = [finding()]

    after, verified = apply_flow_evidence(root, before, observations()[:2])  # no request call

    assert after == before and verified == 0


def test_only_sql_pattern_rules_are_upgraded(tmp_path):
    root = project(tmp_path)
    before = [finding(rule_id="auditor.python.misconfig.flask-debug-enabled")]

    after, verified = apply_flow_evidence(root, before, observations())

    assert after == before and verified == 0
