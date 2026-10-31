"""End-to-end ``auditor scan`` with the real, pinned Ruff from the auditor's environment."""

import json
import os
import shutil

import pytest
from typer.testing import CliRunner

import auditor.scanners.ruff_adapter as ruff_adapter
from auditor.cli import app
from auditor.core.models import FindingsReport, RepositoryInventory

runner = CliRunner()

BAD = "import os\nimport subprocess\nsubprocess.run('ls', shell=True)\nx = eval(input())\n"
PROJECT = {
    "pkg": {"__init__.py": "", "bad.py": BAD, "clean.py": "VALUE = 1\n"},
    "setup.py": "import sys\n",
    "tests": {"test_ok.py": "def test_ok():\n    assert True\n", "data": {"fixture.json": "{}"}},
}


@pytest.fixture(autouse=True)
def private_app_dirs(tmp_path, monkeypatch):
    # Keep the per-user default directories inside the test sandbox.
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "appdata"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "appdata"))


def scan(root, out_dir, *extra):
    return runner.invoke(app, ["scan", str(root), "--output-dir", str(out_dir), *extra])


def load(out_dir):
    run_dir = next(out_dir.iterdir())
    inventory = RepositoryInventory.model_validate_json(
        (run_dir / "inventory.json").read_text(encoding="utf-8")
    )
    findings = FindingsReport.model_validate_json(
        (run_dir / "findings.json").read_text(encoding="utf-8")
    )
    return inventory, findings, (run_dir / "report.md").read_text(encoding="utf-8")


def located(findings):
    return {(f.rule_id, f.relative_path, f.start_line) for f in findings.findings}


def test_real_ruff_findings_are_reported_and_linked_to_inventory(make_tree, out_dir):
    root = make_tree(PROJECT)

    result = scan(root, out_dir)
    inventory, findings, markdown = load(out_dir)

    assert result.exit_code == 0, result.output
    assert {
        ("F401", "pkg/bad.py", 1),
        ("S602", "pkg/bad.py", 3),
        ("S307", "pkg/bad.py", 4),
        ("F401", "setup.py", 1),  # setup.py is linted although it is a "manifest"
    } <= located(findings)
    inventory_paths = {f.relative_path for f in inventory.files}
    assert all(f.relative_path in inventory_paths for f in findings.findings)
    execution = next(e for e in findings.tool_executions if e.tool == "ruff")
    assert (execution.tool, execution.status.value, execution.version) == (
        "ruff",
        "SUCCESS",
        "0.17.3",
    )
    assert execution.files_requested == 5  # 4 .py in pkg/tests + setup.py; fixture.json excluded
    assert execution.files_analyzed == 5
    assert findings.status.value == "COMPLETE"
    ruff_coverage = next(s for s in inventory.scanners if s.tool == "ruff")
    assert ruff_coverage.status.value == "SUCCESS"
    assert "## Ruff" in markdown and "S602" in markdown
    assert "3.12 (default (assumed))" in markdown
    assert "assumed" in result.output


def test_s101_policy_with_real_ruff(make_tree, out_dir):
    root = make_tree(
        {
            "app": {"core.py": "def check(x):\n    assert x > 0\n    return x\n"},
            "tests": {
                "test_core.py": "def test_a():\n    assert 1\n    assert 2\n",
                "conftest.py": "assert True\nVALUE = eval(input())\n",
            },
        }
    )

    result = scan(root, out_dir)
    _, findings, markdown = load(out_dir)

    assert result.exit_code == 0, result.output
    # production assert and the eval in a test file are still reported
    assert located(findings) == {("S101", "app/core.py", 2), ("S307", "tests/conftest.py", 2)}
    (suppressed,) = findings.tool_executions[0].suppressed
    assert (suppressed.rule_id, suppressed.count) == ("S101", 3)
    assert "Suppressed by policy" in markdown and "S101" in markdown
    assert "3 suppressed" in result.output


def test_target_python_option_changes_version_checks(make_tree, out_dir):
    match = "def f(v):\n    match v:\n        case 1:\n            return 1\n    return 0\n"
    root = make_tree({"m.py": match})

    result = scan(root, out_dir, "--target-python", "3.8")
    _, findings, markdown = load(out_dir)

    assert result.exit_code == 0, result.output  # version issue is a finding, not a gap
    (finding,) = findings.findings
    assert finding.category.value == "compatibility"
    assert findings.tool_executions[0].settings["target_python"] == "3.8"
    assert "3.8 (--target-python)" in markdown


@pytest.mark.parametrize("bad", ["3.6", "banana", "3.11 --fix"])
def test_invalid_target_python_exits_2(make_tree, out_dir, bad):
    result = scan(make_tree({"a.py": ""}), out_dir, "--target-python", bad)

    assert result.exit_code == 2
    assert not out_dir.exists()


def test_parse_error_makes_the_scan_partial(make_tree, out_dir):
    root = make_tree({"broken.py": "def f(:\n    x = eval(input())\n", "ok.py": "import os\n"})

    result = scan(root, out_dir)
    _, findings, markdown = load(out_dir)

    assert result.exit_code == 3
    assert findings.status.value == "PARTIAL"
    assert [r.value for r in findings.incomplete_reasons] == ["FILES_NOT_ANALYZED"]
    (item,) = findings.tool_executions[0].not_analyzed
    assert (item.relative_path, item.reason.value) == ("broken.py", "PARSE_ERROR")
    assert ("F401", "ok.py", 1) in located(findings)  # the other file was still analyzed
    assert "Not analyzed by Ruff" in markdown and "broken.py" in markdown


def test_non_utf8_file_is_not_analyzed(make_tree, out_dir):
    root = make_tree({"latin1.py": b"# \xe7\xf0\nx = 1\n"})

    result = scan(root, out_dir)
    _, findings, _ = load(out_dir)

    assert result.exit_code == 3
    assert findings.findings == []
    assert findings.tool_executions[0].not_analyzed[0].reason.value == "IO_ERROR"


def test_clean_project_has_zero_findings_but_states_what_ran(make_tree, out_dir):
    result = scan(make_tree({"a.py": "VALUE = 1\n"}), out_dir)
    _, findings, markdown = load(out_dir)

    assert result.exit_code == 0
    assert findings.findings == []
    assert findings.tool_executions[0].status.value == "SUCCESS"
    assert "0 findings" in markdown
    assert "E4,E7,E9,F,B,S,C901" in markdown


def test_project_without_python_files_skips_ruff(make_tree, out_dir):
    result = scan(make_tree({"README.md": "# x\n"}), out_dir)
    _, findings, _ = load(out_dir)

    assert result.exit_code == 0
    assert findings.tool_executions[0].status.value == "SKIPPED"


def test_missing_ruff_is_reported_and_never_clean(make_tree, out_dir, monkeypatch):
    monkeypatch.setattr(ruff_adapter, "find_ruff_executable", lambda: None)

    result = scan(make_tree({"a.py": "import os\n"}), out_dir)
    inventory, findings, markdown = load(out_dir)

    assert result.exit_code == 3
    assert findings.tool_executions[0].status.value == "NOT_INSTALLED"
    assert [r.value for r in findings.incomplete_reasons] == ["SCANNER_NOT_INSTALLED"]
    assert "WARNING: PARTIAL SCAN" in markdown
    assert next(s for s in inventory.scanners if s.tool == "ruff").status.value == "NOT_INSTALLED"


def test_unicode_and_special_character_paths(make_tree, out_dir):
    root = make_tree({"çalışma & ğüş (1)": {"modül ü.py": "import os\n"}}, name="proje İ 日本")

    result = scan(root, out_dir)
    _, findings, _ = load(out_dir)

    assert result.exit_code == 0, result.output
    assert ("F401", "çalışma & ğüş (1)/modül ü.py", 1) in located(findings)


def test_file_beyond_windows_max_path_is_analyzed(tmp_path, out_dir):
    root = tmp_path / "target"
    root.mkdir()
    prefix = "\\\\?\\" if os.name == "nt" else ""
    current = prefix + str(root)
    for _ in range(30):
        current = os.path.join(current, "directory_name")
        os.mkdir(current)
    with open(os.path.join(current, "deep.py"), "w", encoding="utf-8") as handle:
        handle.write("import os\n")
    try:
        result = scan(root, out_dir)
        _, findings, _ = load(out_dir)

        assert result.exit_code == 0, result.output
        (finding,) = findings.findings
        assert finding.rule_id == "F401"
        assert len(str(root)) + len(finding.relative_path) > 260
    finally:
        shutil.rmtree(prefix + str(root))


def test_raw_output_workspace_is_removed_after_the_run(make_tree, out_dir, tmp_path):
    scan(make_tree(PROJECT), out_dir)

    temp_base = tmp_path / "appdata" / "ai-code-auditor" / "tmp"
    assert temp_base.is_dir()
    assert list(temp_base.iterdir()) == []


def test_findings_json_never_contains_fix_edit_contents(make_tree, out_dir):
    scan(make_tree({"a.py": "import os\nimport sys\n"}), out_dir)
    raw = (next(out_dir.iterdir()) / "findings.json").read_text(encoding="utf-8")

    data = json.loads(raw)
    assert all(f["fix_available"] for f in data["findings"])
    assert '"edits"' not in raw and '"content"' not in raw
