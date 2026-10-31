"""D-042: a workspace that cannot be removed is a reported security error (CLEANUP_FAILED,
PARTIAL, exit 3) - never silent - while the scanner findings are kept intact.
"""

import json
import os
import time

import pytest
from typer.testing import CliRunner

import auditor.application.audit_service as service
from auditor.application.audit_service import run_audit
from auditor.cli import app
from auditor.core.models import (
    Confidence,
    Finding,
    FindingCategory,
    FindingsReport,
    IncompleteReason,
    OperationalErrorCode,
    ScanStatus,
    Severity,
    ToolExecution,
    ToolStatus,
    VerificationStatus,
)
from auditor.scanners.base import ScanOutcome
from auditor.scanners.semgrep_adapter import short_temp_base
from auditor.scanners.workspace import PrivateWorkspace, remove_owned_workspace

runner = CliRunner()
COPY_NAME = "leaked_copy_of_app.py"


def semgrep_finding():
    return Finding(
        finding_id="semgrep-1",
        fingerprint="1" * 64,
        source_tool="semgrep",
        rule_id="auditor.python.code-injection.eval",
        title="eval of user input",
        description="d",
        category=FindingCategory.SECURITY,
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        verification_status=VerificationStatus.NEEDS_REVIEW,
        relative_path="app.py",
    )


class _Lock:
    """Makes a directory's content undeletable for a while (open handle / read-only dir)."""

    def __init__(self):
        self.handles = []
        self.dirs = []

    def hold(self, directory):
        target = directory / COPY_NAME
        target.write_text("SOURCE_COPY = 1\n", encoding="utf-8")
        if os.name == "nt":
            self.handles.append(open(target, encoding="utf-8"))  # noqa: SIM115
        else:
            if os.geteuid() == 0:
                pytest.skip("root ignores directory permissions")
            os.chmod(directory, 0o500)
            self.dirs.append(directory)

    def release(self):
        for handle in self.handles:
            handle.close()
        for directory in self.dirs:
            os.chmod(directory, 0o700)


@pytest.fixture
def lock():
    held = _Lock()
    yield held
    held.release()


class LeakyScanner:
    """Like the Semgrep adapter: its own short scratch with a source copy that cannot be
    removed. Optionally raises afterwards (the failure must still be reported)."""

    name = "semgrep"

    def __init__(self, lock, raises=False):
        self.lock = lock
        self.raises = raises
        self.scratch = None

    def scan(self, context):
        space = PrivateWorkspace(
            context.root,
            short_temp_base(),
            prefix="r-",
            component="semgrep",
            contents="copies of scanned source files",
            failures=context.cleanup_failures,
        )
        with space as scratch:
            self.scratch = scratch
            sub = scratch / "m"
            sub.mkdir()
            self.lock.hold(sub)
        if self.raises:
            raise RuntimeError("adapter failed after its cleanup")
        return ScanOutcome(
            ToolExecution(tool="semgrep", version="1", status=ToolStatus.SUCCESS, reason="ok"),
            [semgrep_finding()],
            applicable=["app.py"],
        )


def _cleanup(scanner):
    scanner.lock.release()
    if scanner.scratch is not None:
        assert remove_owned_workspace(scanner.scratch) is None


def _texts(run_dir, output):
    return [output] + [p.read_text("utf-8") for p in run_dir.iterdir() if p.is_file()]


def test_cleanup_failure_is_a_security_error_with_exit_3(make_tree, out_dir, lock, monkeypatch):
    root = make_tree({"app.py": "import os\nx = eval(input())\n"})
    clean = runner.invoke(
        app,
        ["scan", str(root), "--output-dir", str(out_dir / "clean"), "--disable-scanner", "semgrep"],
    )
    clean_dir = next((out_dir / "clean").iterdir())
    clean_report = FindingsReport.model_validate_json((clean_dir / "findings.json").read_text())
    scanner = LeakyScanner(lock)
    monkeypatch.setattr(service, "SemgrepAdapter", lambda *a, **k: scanner)

    try:
        result = runner.invoke(app, ["scan", str(root), "--output-dir", str(out_dir / "leak")])
        run_dir = next((out_dir / "leak").iterdir())
        report = FindingsReport.model_validate_json((run_dir / "findings.json").read_text())

        assert clean.exit_code == 0, clean.output
        assert result.exit_code == 3, result.output
        assert "SECURITY ERROR [CLEANUP_FAILED] (semgrep)" in result.output
        assert report.status is ScanStatus.PARTIAL
        assert IncompleteReason.CLEANUP_FAILED in report.incomplete_reasons
        (error,) = report.operational_errors
        assert error.code is OperationalErrorCode.CLEANUP_FAILED
        assert error.workspace == scanner.scratch.name
        assert "SENSITIVE DATA" in error.message
        markdown = (run_dir / "report.md").read_text("utf-8")
        assert "SECURITY ERROR [CLEANUP_FAILED]" in markdown and "SENSITIVE DATA" in markdown
        # Findings survive: Ruff's are identical to a clean run, Semgrep's are kept.
        ruff = [
            (f.rule_id, f.relative_path, f.start_line)
            for f in report.findings
            if f.source_tool == "ruff"
        ]
        assert ruff == [(f.rule_id, f.relative_path, f.start_line) for f in clean_report.findings]
        assert ruff and [f.finding_id for f in report.findings if f.source_tool == "semgrep"]
        # No full temp paths and no names of the leftover files anywhere.
        for text in _texts(run_dir, result.output):
            assert str(short_temp_base()) not in text
            assert str(scanner.scratch) not in text
            assert COPY_NAME not in text
    finally:
        _cleanup(scanner)


def test_cleanup_failure_is_reported_even_when_the_adapter_raises(sample_repo, out_dir, lock):
    scanner = LeakyScanner(lock, raises=True)
    try:
        run = run_audit(sample_repo, out_dir, scanners=[scanner])

        (execution,) = run.findings.tool_executions
        assert execution.status is ToolStatus.ERROR
        assert [e.code for e in run.findings.operational_errors] == [
            OperationalErrorCode.CLEANUP_FAILED
        ]
        assert IncompleteReason.CLEANUP_FAILED in run.findings.incomplete_reasons
    finally:
        _cleanup(scanner)


class RawOutputScanner:
    """Writes raw output into the service workspace and ends with a given status."""

    def __init__(self, name, status=ToolStatus.SUCCESS, raises=False, lock=None):
        self.name = name
        self.status = status
        self.raises = raises
        self.lock = lock
        self.workspace = None

    def scan(self, context):
        self.workspace = context.workspace
        assert context.cleanup_failures == []
        (context.workspace / "raw.json").write_text('{"code": "SECRET_LINE"}', "utf-8")
        deep = os.path.join(str(context.workspace), *(["directory_name_x"] * 16))
        os.makedirs("\\\\?\\" + deep if os.name == "nt" else deep)
        if self.lock is not None:
            self.lock.hold(context.workspace)
        if self.raises:
            raise RuntimeError("boom")
        execution = ToolExecution(tool=self.name, version="1", status=self.status, reason="x")
        return ScanOutcome(execution, [])


@pytest.mark.parametrize(
    ("status", "raises"),
    [
        (ToolStatus.SUCCESS, False),
        (ToolStatus.ERROR, False),
        (ToolStatus.TIMED_OUT, False),
        (ToolStatus.ERROR, True),
    ],
)
def test_service_workspace_is_removed_after_every_outcome(
    sample_repo, out_dir, tmp_path, status, raises
):
    scanner = RawOutputScanner("ruff", status, raises)

    run = run_audit(sample_repo, out_dir, scanners=[scanner])

    temp_base = tmp_path / "appdata" / "ai-code-auditor" / "tmp"
    assert list(temp_base.iterdir()) == []
    assert run.findings.operational_errors == []
    assert IncompleteReason.CLEANUP_FAILED not in run.findings.incomplete_reasons


def test_service_workspace_failure_is_reported(sample_repo, out_dir, lock):
    scanner = RawOutputScanner("ruff", lock=lock)
    try:
        run = run_audit(sample_repo, out_dir, scanners=[scanner])

        (error,) = run.findings.operational_errors
        assert error.component == "scanner-output"
        assert run.findings.status is ScanStatus.PARTIAL
        assert "raw scanner output" in error.message
        findings_json = json.loads(run.reports.findings_json.read_text("utf-8"))
        assert findings_json["operational_errors"][0]["code"] == "CLEANUP_FAILED"
    finally:
        lock.release()
        assert remove_owned_workspace(scanner.workspace.parent) is None


def test_new_scan_reports_old_leftovers_but_never_deletes_them(make_tree, out_dir, tmp_path):
    """D-042 policy: only the current run's own workspace is removed automatically."""
    temp_base = tmp_path / "appdata" / "ai-code-auditor" / "tmp"
    leftover = temp_base / "run-oldleft1"
    leftover.mkdir(parents=True)
    (leftover / "raw.json").write_text('{"code": "OLD_SOURCE_EXCERPT"}', encoding="utf-8")
    old = time.time() - 3 * 24 * 3600
    os.utime(leftover, (old, old))
    root = make_tree({"app.py": "import os\n"})

    result = runner.invoke(app, ["scan", str(root), "--output-dir", str(out_dir)])
    run_dir = next(out_dir.iterdir())
    report = FindingsReport.model_validate_json((run_dir / "findings.json").read_text("utf-8"))

    assert result.exit_code == 0, result.output  # earlier runs do not make this one partial
    assert (leftover / "raw.json").read_text(encoding="utf-8") == '{"code": "OLD_SOURCE_EXCERPT"}'
    assert sorted(p.name for p in temp_base.iterdir()) == ["run-oldleft1"]  # own one removed
    (warning,) = report.operational_warnings
    assert warning.code is OperationalErrorCode.STALE_WORKSPACES_FOUND
    assert "1 temporary folder(s)" in warning.message and "SENSITIVE DATA" in warning.message
    assert "SECURITY WARNING [STALE_WORKSPACES_FOUND] (scanner-output)" in result.output
    markdown = (run_dir / "report.md").read_text("utf-8")
    assert "SECURITY WARNING [STALE_WORKSPACES_FOUND]" in markdown
    for text in _texts(run_dir, result.output):
        assert str(temp_base) not in text and "OLD_SOURCE_EXCERPT" not in text
    assert report.operational_errors == []
