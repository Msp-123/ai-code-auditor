import json

import pytest

import auditor.reports.writer as writer
from auditor.application.audit_service import run_discovery
from auditor.core.errors import ReportWriteError
from auditor.core.models import RepositoryInventory
from auditor.core.policy import ScanPolicy


def test_reports_are_written_to_run_directory(sample_repo, out_dir):
    run = run_discovery(sample_repo, out_dir)

    assert run.reports.directory == out_dir.resolve() / run.inventory.run_id
    assert run.reports.inventory_json.is_file()
    assert run.reports.markdown.is_file()
    assert [p.name for p in out_dir.iterdir()] == [run.inventory.run_id]  # no staging left


def test_inventory_json_matches_schema(sample_repo, out_dir):
    run = run_discovery(sample_repo, out_dir)

    raw = run.reports.inventory_json.read_text(encoding="utf-8")
    restored = RepositoryInventory.model_validate_json(raw)

    assert restored.files == run.inventory.files
    assert json.loads(raw)["files_by_category"]["test"] == 2


def test_report_files_are_utf8_with_lf_newlines(make_tree, out_dir):
    root = make_tree({"çalışma_İ.py": "", ".env": "X"}, name="proje_ğüş")

    run = run_discovery(root, out_dir)
    json_bytes = run.reports.inventory_json.read_bytes()
    md_bytes = run.reports.markdown.read_bytes()

    assert b"\r\n" not in json_bytes and b"\r\n" not in md_bytes
    assert "çalışma_İ.py" in json_bytes.decode("utf-8")  # full file list lives in JSON
    assert "proje_ğüş" in md_bytes.decode("utf-8")


def test_markdown_states_scanners_were_not_run(sample_repo, out_dir):
    markdown = run_discovery(sample_repo, out_dir).reports.markdown.read_text(encoding="utf-8")

    assert "Status: **COMPLETE**" in markdown
    assert "no findings exist yet" in markdown
    # run_discovery is the discovery-only path: Ruff exists but did not run here.
    for tool in ("ruff", "semgrep", "gitleaks", "pip-audit"):
        assert f"| {tool} | SKIPPED | Not run (discovery only) |" in markdown
    assert "PARTIAL" not in markdown


def test_partial_scan_is_flagged_prominently(make_tree, out_dir):
    root = make_tree({f"f{i}.py": "" for i in range(5)})

    run = run_discovery(root, out_dir, ScanPolicy(max_files=2))
    markdown = run.reports.markdown.read_text(encoding="utf-8")
    data = json.loads(run.reports.inventory_json.read_text(encoding="utf-8"))

    assert markdown.splitlines()[2].startswith("> **WARNING: PARTIAL SCAN")
    assert "Status: **PARTIAL**" in markdown
    assert data["status"] == "PARTIAL"
    assert data["incomplete_reasons"] == ["MAX_FILES"]


def test_failed_write_never_leaves_a_complete_looking_report(sample_repo, out_dir, monkeypatch):
    def broken(_inventory):
        raise RuntimeError("disk full")

    monkeypatch.setattr(writer, "render_markdown", broken)

    with pytest.raises(ReportWriteError, match="incomplete"):
        run_discovery(sample_repo, out_dir)

    names = [p.name for p in out_dir.iterdir()]
    assert len(names) == 1
    assert names[0].startswith(".") and names[0].endswith(".incomplete")
    assert not (out_dir / names[0] / "report.md").exists()


def test_default_output_dir_is_per_user_location(sample_repo, tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "localappdata"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "localappdata"))

    run = run_discovery(sample_repo)

    expected_base = (tmp_path / "localappdata" / "ai-code-auditor" / "reports").resolve()
    assert run.reports.directory.parent == expected_base
