"""Stage 6: atomic report output and the integrity record (G2, D-048).

A report directory becomes ``<run_id>`` only after every file was written, renamed from its
``.partial`` name and checked against SHA256SUMS.json. Any failure leaves a hidden
``.<run_id>.incomplete`` directory whose files are still named ``*.partial`` and which has no
integrity record, so nothing in it looks like a finished report.
"""

import hashlib
import json
import os

import pytest

import auditor.reports.writer as writer
from auditor.application.audit_service import run_discovery
from auditor.core.audit_report import REPORT_SCHEMA_VERSION
from auditor.core.errors import ReportWriteError

FINAL = {"report.json", "inventory.json", "report.md", "SHA256SUMS.json"}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def only_dir(out_dir):
    (entry,) = list(out_dir.iterdir())
    return entry


def test_a_finished_report_has_every_file_and_a_matching_integrity_record(sample_repo, out_dir):
    run = run_discovery(sample_repo, out_dir)

    directory = only_dir(out_dir)
    assert directory.name == run.inventory.run_id
    assert {p.name for p in directory.iterdir()} == FINAL
    record = json.loads((directory / "SHA256SUMS.json").read_text("utf-8"))
    assert record["algorithm"] == "sha256" and "not a signature" in record["note"]
    assert record["files"] == {name: sha(directory / name) for name in FINAL - {"SHA256SUMS.json"}}
    assert record["report_schema_version"] == REPORT_SCHEMA_VERSION


@pytest.mark.parametrize("failing", ["report.json", "inventory.json", "report.md"])
def test_a_failed_write_leaves_only_partial_files_and_no_integrity_record(
    sample_repo, out_dir, monkeypatch, failing
):
    original = writer.create_private_file

    def fail(path, content):
        if path.name == f"{failing}.partial":
            raise OSError("disk full (simulated)")
        return original(path, content)

    monkeypatch.setattr(writer, "create_private_file", fail)

    with pytest.raises(ReportWriteError, match="No complete report exists"):
        run_discovery(sample_repo, out_dir)

    staging = only_dir(out_dir)
    assert staging.name.startswith(".") and staging.name.endswith(".incomplete")
    names = {p.name for p in staging.iterdir()}
    assert "SHA256SUMS.json" not in names
    assert all(n.endswith(".partial") for n in names), names  # G2: nothing looks final


def test_g2_markdown_failure_publishes_nothing_and_keeps_json_only_as_partial(
    sample_repo, out_dir, monkeypatch
):
    def broken(_audit):
        raise RuntimeError("renderer bug with C:\\Users\\someone\\secret path")

    monkeypatch.setattr(writer, "render_markdown", broken)

    with pytest.raises(ReportWriteError) as failed:
        run_discovery(sample_repo, out_dir)

    staging = only_dir(out_dir)
    assert staging.name.endswith(".incomplete")
    assert {p.name for p in staging.iterdir()} == {"report.json.partial", "inventory.json.partial"}
    assert "someone" not in str(failed.value) and "RuntimeError" in str(failed.value)


def test_a_failed_integrity_check_before_publishing_is_an_error(sample_repo, out_dir, monkeypatch):
    original = writer._finalise_names

    def tamper(staging, names):
        original(staging, names)
        (staging / "report.md").write_text("changed after hashing", encoding="utf-8")

    monkeypatch.setattr(writer, "_finalise_names", tamper)

    with pytest.raises(ReportWriteError, match="integrity"):
        run_discovery(sample_repo, out_dir)
    assert only_dir(out_dir).name.endswith(".incomplete")


def test_publishing_never_replaces_an_existing_run_directory(sample_repo, out_dir, monkeypatch):
    """Windows os.replace onto an existing directory fails; the existing one is untouched."""
    import auditor.application.audit_service as service

    fixed = "20260101T000000Z-abcdef"
    monkeypatch.setattr(service, "new_run_id", lambda now: fixed)
    (out_dir / fixed).mkdir(parents=True)
    (out_dir / fixed / "keep.txt").write_text("existing", encoding="utf-8")

    with pytest.raises(ReportWriteError):
        run_discovery(sample_repo, out_dir)

    assert (out_dir / fixed / "keep.txt").read_text(encoding="utf-8") == "existing"
    assert sorted(p.name for p in (out_dir / fixed).iterdir()) == ["keep.txt"]


def test_g3_incomplete_directories_of_earlier_runs_are_reported_never_deleted(sample_repo, out_dir):
    leftover = out_dir / ".20250101T000000Z-012345.incomplete"
    leftover.mkdir(parents=True)
    (leftover / "inventory.json.partial").write_text("{}", encoding="utf-8")

    run = run_discovery(sample_repo, out_dir)

    report = json.loads((out_dir / run.inventory.run_id / "report.json").read_text("utf-8"))
    (warning,) = [w for w in report["operational_warnings"]
                  if w["code"] == "INCOMPLETE_REPORTS_FOUND"]  # fmt: skip
    assert "1 incomplete report directory" in warning["message"]
    assert leftover.exists() and os.listdir(leftover) == ["inventory.json.partial"]
