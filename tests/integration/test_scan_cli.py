"""End-to-end tests of ``auditor scan`` through the real CLI."""

import json
import os
import subprocess
import sys

from typer.testing import CliRunner

from auditor.cli import app
from auditor.core.models import RepositoryInventory

runner = CliRunner()


def scan(*args):
    return runner.invoke(app, ["scan", *map(str, args)])


def only_run_dir(out_dir):
    dirs = list(out_dir.iterdir())
    assert len(dirs) == 1
    return dirs[0]


def test_scan_complete(sample_repo, out_dir):
    result = scan(sample_repo, "--output-dir", out_dir)

    assert result.exit_code == 0, result.output
    assert "Status:    COMPLETE" in result.output
    assert "not implemented yet" not in result.output  # all four scanners exist
    run_dir = only_run_dir(out_dir)
    inventory = RepositoryInventory.model_validate_json(
        (run_dir / "inventory.json").read_text(encoding="utf-8")
    )
    assert len(inventory.files) == 8
    # Stage 2: Ruff runs; the scanners of later stages are still honestly SKIPPED.
    statuses = {s.tool: s.status.value for s in inventory.scanners}
    assert statuses == {
        "ruff": "SUCCESS",
        "semgrep": "SKIPPED",
        "gitleaks": "SKIPPED",
        "pip-audit": "SKIPPED",
    }
    assert (run_dir / "report.md").is_file()
    assert (run_dir / "findings.json").is_file()


def test_scan_missing_target_exits_2_without_traceback(tmp_path, out_dir):
    result = scan(tmp_path / "missing", "--output-dir", out_dir)

    assert result.exit_code == 2
    assert "NOT_FOUND" in result.output
    assert "Traceback" not in result.output
    assert not out_dir.exists()


def test_scan_file_target_exits_2(tmp_path, out_dir):
    file = tmp_path / "a.py"
    file.write_text("", encoding="utf-8")

    result = scan(file, "--output-dir", out_dir)

    assert result.exit_code == 2
    assert "NOT_A_DIRECTORY" in result.output


def test_scan_refuses_output_inside_target(sample_repo):
    before = sorted(p.name for p in sample_repo.iterdir())

    result = scan(sample_repo, "--output-dir", sample_repo / "reports")

    assert result.exit_code == 2
    assert "OUTPUT_INSIDE_TARGET" in result.output
    assert sorted(p.name for p in sample_repo.iterdir()) == before


def test_scan_from_inside_target_with_default_output(sample_repo, tmp_path, monkeypatch):
    # Running "auditor scan ." from the project root must still never write into it.
    monkeypatch.chdir(sample_repo)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "appdata"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "appdata"))
    before = sorted(p.name for p in sample_repo.iterdir())

    result = scan(".")

    assert result.exit_code == 0, result.output
    assert sorted(p.name for p in sample_repo.iterdir()) == before
    assert only_run_dir(tmp_path / "appdata" / "ai-code-auditor" / "reports")


def test_scan_partial_exits_3_and_says_so(make_tree, out_dir):
    root = make_tree({f"f{i}.py": "" for i in range(5)})

    result = scan(root, "--output-dir", out_dir, "--max-files", "2")

    assert result.exit_code == 3
    assert "Status:    PARTIAL" in result.output
    assert "INCOMPLETE" in result.output
    data = json.loads((only_run_dir(out_dir) / "inventory.json").read_text(encoding="utf-8"))
    assert data["status"] == "PARTIAL"


def test_scan_rejects_non_positive_max_files(sample_repo, out_dir):
    result = scan(sample_repo, "--output-dir", out_dir, "--max-files", "0")

    assert result.exit_code == 2


def test_scan_write_failure_exits_1(sample_repo, out_dir, monkeypatch):
    import auditor.reports.writer as writer

    def broken(_inventory):
        raise OSError("disk full")

    monkeypatch.setattr(writer, "render_json", broken)

    result = scan(sample_repo, "--output-dir", out_dir)

    assert result.exit_code == 1
    assert "REPORT_WRITE" in result.output
    assert not any((p / "report.md").exists() for p in out_dir.iterdir())


def test_unexpected_error_exits_1_without_details(sample_repo, out_dir, monkeypatch):
    import auditor.cli as cli

    def boom(*_args, **_kwargs):
        raise RuntimeError("internal detail C:\\secret\\path")

    monkeypatch.setattr(cli, "run_audit", boom)

    result = scan(sample_repo, "--output-dir", out_dir)

    assert result.exit_code == 1
    assert "INTERNAL ERROR: RuntimeError" in result.output
    assert "secret" not in result.output


def test_real_process_on_cp1254_console_with_unicode_target(make_tree, out_dir):
    # A legacy code page cannot encode these characters; the CLI must not crash.
    root = make_tree({"a.py": ""}, name="日本語_🚀_proje")
    completed = subprocess.run(  # noqa: S603 - runs our own package only
        [sys.executable, "-m", "auditor", "scan", str(root), "--output-dir", str(out_dir)],
        shell=False,
        capture_output=True,
        env={**os.environ, "PYTHONIOENCODING": "cp1254", "PYTHONUTF8": "0"},
        timeout=60,
        check=False,
    )
    stdout = completed.stdout.decode("cp1254")

    assert completed.returncode == 0, completed.stderr.decode("cp1254", "replace")
    assert "\\u65e5" in stdout  # escaped, not crashed
    assert "_proje" in stdout
