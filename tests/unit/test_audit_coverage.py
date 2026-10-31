"""Service-level coverage: Ruff/Semgrep reconciliation, disabled scanners, per-file matrix.

All scanners here are fakes, so these tests are about the audit service alone.
"""

from auditor.application.audit_service import run_audit
from auditor.core.models import (
    Confidence,
    CoverageStatus,
    Finding,
    FindingCategory,
    NotAnalyzedFile,
    NotAnalyzedReason,
    Severity,
    ToolExecution,
    ToolStatus,
    VerificationStatus,
)
from auditor.reports.markdown_report import render_markdown
from auditor.scanners.base import ScanOutcome

PY_FILES = [  # the .py files of the conftest SAMPLE_SPEC
    "setup.py",
    "src/app/__init__.py",
    "src/app/main.py",
    "tests/conftest.py",
    "tests/test_main.py",
]


def finding(tool, path="src/app/main.py"):
    return Finding(
        finding_id=f"{tool}-1",
        fingerprint="0" * 64,
        source_tool=tool,
        rule_id="X1",
        title="t",
        description="d",
        category=FindingCategory.SECURITY,
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        verification_status=VerificationStatus.NEEDS_REVIEW,
        relative_path=path,
    )


class Fake:
    def __init__(self, name, status=ToolStatus.SUCCESS, not_analyzed=(), findings=(), raises=False):
        self.name = name
        self.status = status
        self.not_analyzed = list(not_analyzed)
        self.findings = list(findings)
        self.raises = raises
        self.workspace = None

    def scan(self, context):
        self.workspace = context.workspace
        if self.raises:
            raise RuntimeError("boom")
        analyzed = (
            0 if self.status is ToolStatus.NOT_INSTALLED else len(PY_FILES) - len(self.not_analyzed)
        )
        return ScanOutcome(
            ToolExecution(
                tool=self.name,
                version="1",
                status=self.status,
                reason="fake",
                files_requested=len(PY_FILES),
                files_analyzed=analyzed,
                not_analyzed=self.not_analyzed,
            ),
            self.findings,
            applicable=list(PY_FILES),
        )


def parse_error(path):
    return NotAnalyzedFile(relative_path=path, reason=NotAnalyzedReason.PARSE_ERROR)


def execution(run, tool):
    return next(e for e in run.findings.tool_executions if e.tool == tool)


# ------------------------------------------------- Ç1: Ruff parse errors vs Semgrep


def test_semgrep_scanned_file_with_ruff_parse_error_is_marked_limited(sample_repo, out_dir):
    ruff = Fake("ruff", not_analyzed=[parse_error("src/app/main.py")])
    semgrep = Fake("semgrep", findings=[finding("semgrep")])

    run = run_audit(sample_repo, out_dir, scanners=[ruff, semgrep])
    sg = execution(run, "semgrep")

    (limited,) = sg.coverage_limitations
    assert limited.relative_path == "src/app/main.py"
    assert limited.reason == "SYNTAX_ERROR_RECOVERY"
    assert [f.source_tool for f in run.findings.findings] == ["semgrep"]  # kept, not deleted
    reasons = [r.value for r in run.findings.incomplete_reasons]
    assert "FILES_ANALYZED_WITH_LIMITATIONS" in reasons
    row = next(c for c in run.findings.file_coverage if c.relative_path == "src/app/main.py")
    assert row.scanners["semgrep"].status is CoverageStatus.SCANNED_WITH_LIMITATIONS
    assert row.scanners["ruff"].status is CoverageStatus.NOT_ANALYZED


def test_no_limitation_without_ruff_parse_errors(sample_repo, out_dir):
    # Version-gated syntax is a compatibility *finding* in Ruff, never a PARSE_ERROR entry.
    run = run_audit(sample_repo, out_dir, scanners=[Fake("ruff"), Fake("semgrep")])

    assert execution(run, "semgrep").coverage_limitations == []
    assert run.findings.status.value == "COMPLETE"


def test_file_semgrep_did_not_analyze_is_not_double_reported(sample_repo, out_dir):
    ruff = Fake("ruff", not_analyzed=[parse_error("setup.py")])
    semgrep = Fake(
        "semgrep",
        not_analyzed=[
            NotAnalyzedFile(relative_path="setup.py", reason=NotAnalyzedReason.TOOL_ERROR)
        ],
    )

    run = run_audit(sample_repo, out_dir, scanners=[ruff, semgrep])

    assert execution(run, "semgrep").coverage_limitations == []


def test_ruff_not_completing_is_reported_as_unverified_syntax(sample_repo, out_dir):
    run = run_audit(
        sample_repo,
        out_dir,
        scanners=[Fake("ruff", status=ToolStatus.NOT_INSTALLED), Fake("semgrep")],
    )

    sg = execution(run, "semgrep")
    assert sg.status is ToolStatus.SUCCESS  # Semgrep results are kept
    assert any("could not be independently verified" in w for w in sg.warnings)


def test_limitations_are_never_presented_as_completeness_guarantee(sample_repo, out_dir):
    run = run_audit(sample_repo, out_dir, scanners=[Fake("ruff"), Fake("semgrep")])

    markdown = render_markdown(run.audit)  # canonical report (Stage 6)
    assert "does not guarantee" in markdown


# ------------------------------------------------------------------ independence


def test_semgrep_failure_keeps_ruff_results(sample_repo, out_dir):
    ruff = Fake("ruff", findings=[finding("ruff")])

    run = run_audit(sample_repo, out_dir, scanners=[ruff, Fake("semgrep", raises=True)])

    assert [f.source_tool for f in run.findings.findings] == ["ruff"]
    assert execution(run, "semgrep").status is ToolStatus.ERROR
    assert "SCANNER_ERROR" in [r.value for r in run.findings.incomplete_reasons]


def test_ruff_failure_keeps_semgrep_results(sample_repo, out_dir):
    semgrep = Fake("semgrep", findings=[finding("semgrep")])

    run = run_audit(sample_repo, out_dir, scanners=[Fake("ruff", raises=True), semgrep])

    assert [f.source_tool for f in run.findings.findings] == ["semgrep"]


def test_each_scanner_gets_its_own_workspace(sample_repo, out_dir):
    ruff, semgrep = Fake("ruff"), Fake("semgrep")

    run_audit(sample_repo, out_dir, scanners=[ruff, semgrep])

    assert ruff.workspace.name == "ruff" and semgrep.workspace.name == "semgrep"
    assert ruff.workspace != semgrep.workspace


# --------------------------------------------------------------- disabled scanners


def test_disabled_semgrep_is_skipped_visibly_but_not_partial(sample_repo, out_dir):
    semgrep = Fake("semgrep")

    run = run_audit(sample_repo, out_dir, scanners=[Fake("ruff"), semgrep], disabled={"semgrep"})

    sg = execution(run, "semgrep")
    assert semgrep.workspace is None  # never invoked
    assert sg.status is ToolStatus.SKIPPED
    assert sg.settings["disabled_by_user"] == "true"
    assert run.findings.status.value == "COMPLETE"
    row = next(c for c in run.findings.file_coverage if c.relative_path == "setup.py")
    assert row.scanners["semgrep"].status is CoverageStatus.NOT_RUN
    markdown = render_markdown(run.audit)  # canonical report (Stage 6)
    assert "disabled by the user" in markdown and "not a complete security audit" in markdown


# --------------------------------------------------------------- per-file coverage


def test_every_inventory_file_has_a_coverage_state_per_scanner(sample_repo, out_dir):
    run = run_audit(sample_repo, out_dir, scanners=[Fake("ruff"), Fake("semgrep")])

    paths = {c.relative_path: c for c in run.findings.file_coverage}
    assert set(paths) == {f.relative_path for f in run.inventory.files}
    for row in paths.values():
        assert set(row.scanners) == {"ruff", "semgrep"}
    assert paths["README.md"].scanners["ruff"].status is CoverageStatus.NOT_APPLICABLE
    assert paths["setup.py"].scanners["semgrep"].status is CoverageStatus.SCANNED


def test_scanner_that_never_ran_marks_files_not_run(sample_repo, out_dir):
    run = run_audit(
        sample_repo,
        out_dir,
        scanners=[Fake("ruff"), Fake("semgrep", status=ToolStatus.NOT_INSTALLED)],
    )

    row = next(c for c in run.findings.file_coverage if c.relative_path == "setup.py")
    assert row.scanners["semgrep"].status is CoverageStatus.NOT_RUN
    assert row.scanners["semgrep"].reason == "NOT_INSTALLED"
