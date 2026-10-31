"""Ruff adapter logic, driven by a fake ruff (our own script) for deterministic fault injection."""

import json
import sys
import textwrap
from pathlib import Path

import pytest

import auditor.scanners.ruff_adapter as ruff_adapter
from auditor.core.models import (
    FileCategory,
    FileEntry,
    FindingCategory,
    NotAnalyzedReason,
    Severity,
    ToolStatus,
)
from auditor.scanners.base import ScanContext
from auditor.scanners.ruff_adapter import (
    RuffAdapter,
    RuffOptions,
    classify_rule,
    select_python_files,
    to_ruff_target,
)

FAKE_RUFF = textwrap.dedent(
    """
    import json, sys, time
    from pathlib import Path
    scenario = json.loads((Path(__file__).parent / "scenario.json").read_text("utf-8"))
    args = sys.argv[1:]
    if args == ["--version"]:
        print(scenario.get("version_output", "ruff 0.17.3"))
        sys.exit(0)
    with open(scenario["record"], "a", encoding="utf-8") as fh:
        fh.write(json.dumps(args) + "\\n")
    time.sleep(scenario.get("sleep", 0))
    files = args[args.index("--") + 1:]
    out = args[args.index("--output-file") + 1]
    if "raw" in scenario:
        Path(out).write_bytes(scenario["raw"].encode("latin-1"))
    elif scenario.get("write", True):
        diags = []
        for d in scenario.get("diagnostics", []):
            d = dict(d)
            index = d.pop("file_index", 0)
            d.setdefault("filename", files[index] if index < len(files) else "?")
            diags.append(d)
        Path(out).write_text(json.dumps(diags), "utf-8")
    sys.stderr.write(scenario.get("stderr", ""))
    sys.exit(scenario.get("exit", 1 if scenario.get("diagnostics") else 0))
    """
)


def diag(code, row=1, col=1, message="msg", name="rule-name", file_index=0, **extra):
    return {
        "code": code,
        "name": name,
        "message": message,
        "location": {"row": row, "column": col},
        "end_location": {"row": row, "column": col + 3},
        "fix": None,
        "url": f"https://docs.astral.sh/ruff/rules/{name}",
        "severity": "error",
        "file_index": file_index,
        **extra,
    }


def entry(path, category=FileCategory.PYTHON_SOURCE):
    return FileEntry(
        relative_path=path,
        size_bytes=1,
        category=category,
        is_sensitive=False,
        ai_context_allowed=True,
        secret_scan_eligible=True,
        oversized=False,
    )


@pytest.fixture
def project(make_tree):
    root = make_tree(
        {"pkg": {"a.py": "", "b.py": ""}, "setup.py": "", "tests": {"data.json": "{}"}}
    ).resolve()
    files = [
        entry("pkg/a.py"),
        entry("pkg/b.py"),
        entry("setup.py", FileCategory.DEPENDENCY_MANIFEST),
        entry("tests/data.json", FileCategory.CONFIG),
    ]
    return root, files


@pytest.fixture
def fake(tmp_path):
    fake_dir = tmp_path / "fake_ruff"
    fake_dir.mkdir()
    (fake_dir / "ruff.py").write_text(FAKE_RUFF, encoding="utf-8")
    record = fake_dir / "argv.jsonl"

    def configure(**scenario):
        scenario.setdefault("record", str(record))
        (fake_dir / "scenario.json").write_text(json.dumps(scenario), encoding="utf-8")
        return [sys.executable, str(fake_dir / "ruff.py")]

    configure.calls = lambda: (
        [json.loads(line) for line in record.read_text("utf-8").splitlines()]
        if record.exists()
        else []
    )
    return configure


@pytest.fixture
def workspace(tmp_path):
    path = tmp_path / "ws"
    path.mkdir()
    return path


def scan(project, workspace, command, **options):
    root, files = project
    adapter = RuffAdapter(RuffOptions(**options), command=command)
    return adapter.scan(ScanContext(root=root, files=files, workspace=workspace))


# --------------------------------------------------------------------------- selection


def test_python_files_are_selected_by_extension_not_category():
    files = [
        entry("setup.py", FileCategory.DEPENDENCY_MANIFEST),
        entry("tests/test_x.py", FileCategory.TEST),
        entry("stubs/mod.pyi", FileCategory.PYTHON_SOURCE),
        entry("LEGACY.PY", FileCategory.OTHER),
        entry("tests/fixtures/data.json", FileCategory.CONFIG),
        entry("notebook.ipynb", FileCategory.OTHER),
        entry("README.md", FileCategory.DOC),
    ]

    selected = [f.relative_path for f in select_python_files(files)]

    assert selected == ["setup.py", "tests/test_x.py", "stubs/mod.pyi", "LEGACY.PY"]


@pytest.mark.parametrize(
    ("given", "expected"),
    [("3.7", "py37"), ("3.8", "py38"), ("3.11", "py311"), ("3.12", "py312"), ("3.15", "py315")],
)
def test_target_python_is_converted(given, expected):
    assert to_ruff_target(given) == expected


def test_default_target_python_is_3_12():
    assert ruff_adapter.DEFAULT_TARGET_PYTHON == "3.12"


@pytest.mark.parametrize(
    "bad", ["3.6", "3.16", "4.0", "py311", "3.x", "", " 3.12", "3.12.1", "3.11; rm -rf /"]
)
def test_invalid_target_python_is_rejected(bad):
    with pytest.raises(ValueError, match="target"):
        to_ruff_target(bad)


@pytest.mark.parametrize(
    ("code", "severity", "category"),
    [
        ("invalid-syntax", Severity.HIGH, FindingCategory.CORRECTNESS),
        ("E999", Severity.HIGH, FindingCategory.CORRECTNESS),
        ("S602", Severity.HIGH, FindingCategory.SECURITY),
        ("S307", Severity.HIGH, FindingCategory.SECURITY),
        ("S105", Severity.MEDIUM, FindingCategory.SECURITY),
        ("S101", Severity.LOW, FindingCategory.SECURITY),
        ("F821", Severity.MEDIUM, FindingCategory.CORRECTNESS),
        ("F401", Severity.LOW, FindingCategory.MAINTAINABILITY),
        ("B006", Severity.MEDIUM, FindingCategory.CORRECTNESS),
        ("E711", Severity.LOW, FindingCategory.STYLE),
        ("C901", Severity.LOW, FindingCategory.MAINTAINABILITY),
        ("XYZ1", Severity.INFO, FindingCategory.OTHER),
    ],
)
def test_rule_classification(code, severity, category):
    info = classify_rule(code)

    assert (info.severity, info.category) == (severity, category)


# ------------------------------------------------------------------------------ status


def test_not_installed_when_no_trusted_executable(project, workspace, monkeypatch):
    monkeypatch.setattr(ruff_adapter, "find_ruff_executable", lambda: None)

    outcome = RuffAdapter(RuffOptions()).scan(
        ScanContext(root=project[0], files=project[1], workspace=workspace)
    )

    assert outcome.execution.status is ToolStatus.NOT_INSTALLED
    assert outcome.findings == []


def test_skipped_when_there_are_no_python_files(project, workspace, fake):
    root, _ = project
    adapter = RuffAdapter(RuffOptions(), command=fake())

    outcome = adapter.scan(
        ScanContext(root=root, files=[entry("README.md", FileCategory.DOC)], workspace=workspace)
    )

    assert outcome.execution.status is ToolStatus.SKIPPED
    assert "No Python files" in outcome.execution.reason


def test_success_maps_findings_to_inventory_paths(project, workspace, fake):
    command = fake(
        diagnostics=[
            diag("S602", row=3, message="`subprocess` call with `shell=True`", file_index=0),
            diag(
                "F401",
                row=1,
                message="`os` imported but unused",
                file_index=1,
                fix={
                    "message": "Remove unused import: `os`",
                    "applicability": "safe",
                    "edits": [
                        {
                            "content": "CODE-FROM-TARGET",
                            "location": {"row": 1, "column": 1},
                            "end_location": {"row": 2, "column": 1},
                        }
                    ],
                },
            ),
        ]
    )

    outcome = scan(project, workspace, command)
    by_rule = {f.rule_id: f for f in outcome.findings}

    assert outcome.execution.status is ToolStatus.SUCCESS
    assert outcome.execution.version == "0.17.3"
    assert outcome.execution.files_requested == 3  # a.py, b.py, setup.py (not data.json)
    assert outcome.execution.files_analyzed == 3
    assert by_rule["S602"].relative_path == "pkg/a.py"
    assert by_rule["S602"].severity is Severity.HIGH
    assert by_rule["S602"].start_line == 3
    assert by_rule["F401"].relative_path == "pkg/b.py"
    assert by_rule["F401"].fix_available
    assert by_rule["F401"].recommendation == "Remove unused import: `os`"
    assert all(f.verification_status.value == "NEEDS_REVIEW" for f in outcome.findings)
    assert "CODE-FROM-TARGET" not in json.dumps(
        [f.model_dump(mode="json") for f in outcome.findings]
    )


def test_command_line_is_isolated_and_files_follow_double_dash(project, workspace, fake):
    command = fake()

    outcome = scan(project, workspace, command)
    (argv,) = fake.calls()

    for flag in ("check", "--isolated", "--no-cache", "--ignore-noqa"):
        assert flag in argv
    assert argv[argv.index("--output-format") + 1] == "json"
    assert argv[argv.index("--select") + 1] == "E4,E7,E9,F,B,S,C901"
    assert argv[argv.index("--target-version") + 1] == "py312"
    files = argv[argv.index("--") + 1 :]
    assert len(files) == 3 and all(Path(f).is_absolute() for f in files)
    assert "--fix" not in argv and "--unsafe-fixes" not in argv
    assert outcome.execution.settings["target_python"] == "3.12"
    assert outcome.execution.settings["target_python_source"] == "default (assumed)"


def test_user_selected_target_python_is_used(project, workspace, fake):
    command = fake()

    outcome = scan(project, workspace, command, target_python="3.10")
    (argv,) = fake.calls()

    assert argv[argv.index("--target-version") + 1] == "py310"
    assert outcome.execution.settings["target_python_source"] == "--target-python"


def test_files_are_split_into_batches_under_the_command_length_limit(project, workspace, fake):
    command = fake()

    scan(project, workspace, command, max_command_chars=1)
    calls = fake.calls()

    assert len(calls) == 3
    passed = [arg for argv in calls for arg in argv[argv.index("--") + 1 :]]
    assert sorted(Path(p).name for p in passed) == ["a.py", "b.py", "setup.py"]


@pytest.mark.parametrize(
    ("scenario", "expected_reason"),
    [
        ({"exit": 2, "write": False, "stderr": "ruff failed: config"}, "exit code 2"),
        ({"exit": 1, "raw": "not json"}, "invalid JSON"),
        ({"exit": 1, "raw": json.dumps([{"code": "F401"}])}, "unexpected output format"),
        ({"exit": 1, "raw": json.dumps({"not": "a list"})}, "unexpected output format"),
        (
            {"exit": 1, "raw": "\udcff".encode("utf-8", "surrogateescape").decode("latin-1")},
            "not valid UTF-8",
        ),
        ({"exit": 0, "write": False}, "no output file"),
    ],
)
def test_tool_failures_are_errors_never_clean_results(
    project, workspace, fake, scenario, expected_reason
):
    outcome = scan(project, workspace, fake(**scenario))

    assert outcome.execution.status is ToolStatus.ERROR
    assert expected_reason in outcome.execution.reason
    assert outcome.findings == []
    assert {n.reason for n in outcome.execution.not_analyzed} == {NotAnalyzedReason.BATCH_FAILED}
    assert outcome.execution.files_analyzed == 0


def test_oversized_output_is_an_error(project, workspace, fake):
    outcome = scan(project, workspace, fake(diagnostics=[diag("F401")] * 50), max_output_bytes=100)

    assert outcome.execution.status is ToolStatus.ERROR
    assert "too large" in outcome.execution.reason


def test_timeout_is_reported_as_timed_out(project, workspace, fake):
    outcome = scan(project, workspace, fake(sleep=30), batch_timeout=1.0)

    assert outcome.execution.status is ToolStatus.TIMED_OUT
    assert {n.reason for n in outcome.execution.not_analyzed} == {NotAnalyzedReason.TIMED_OUT}


def test_finding_for_unexpected_path_is_dropped(project, workspace, fake, tmp_path):
    outside = str(tmp_path / "outside" / "secret.py")
    command = fake(diagnostics=[diag("S307", filename=outside), diag("F401", file_index=0)])

    outcome = scan(project, workspace, command)

    assert [f.rule_id for f in outcome.findings] == ["F401"]
    assert any("unexpected path" in w for w in outcome.execution.warnings)


def test_io_error_means_file_not_analyzed(project, workspace, fake):
    command = fake(
        diagnostics=[diag("E902", name="io-error", message="stream did not contain valid UTF-8")]
    )

    outcome = scan(project, workspace, command)

    assert outcome.findings == []
    (item,) = outcome.execution.not_analyzed
    assert (item.relative_path, item.reason) == ("pkg/a.py", NotAnalyzedReason.IO_ERROR)
    assert outcome.execution.files_analyzed == 2


def test_parse_error_is_a_finding_and_marks_file_not_analyzed(project, workspace, fake):
    command = fake(
        diagnostics=[
            diag("invalid-syntax", name=None, message="Expected `)`, found newline"),
            diag("invalid-syntax", name=None, row=2, message="Expected a parameter"),
        ]
    )

    outcome = scan(project, workspace, command)

    assert [f.rule_id for f in outcome.findings] == ["invalid-syntax", "invalid-syntax"]
    assert outcome.findings[0].severity is Severity.HIGH
    (item,) = outcome.execution.not_analyzed  # one entry per file, not per diagnostic
    assert item.reason is NotAnalyzedReason.PARSE_ERROR
    assert outcome.execution.files_analyzed == 2


def test_version_gated_syntax_is_compatibility_finding_and_file_counts_as_analyzed(
    project, workspace, fake
):
    message = "Cannot use `match` statement on Python 3.8 (syntax was added in Python 3.10)"
    command = fake(diagnostics=[diag("invalid-syntax", name=None, message=message)])

    outcome = scan(project, workspace, command, target_python="3.8")

    (finding,) = outcome.findings
    assert finding.category is FindingCategory.COMPATIBILITY
    assert finding.severity is Severity.MEDIUM
    assert outcome.execution.not_analyzed == []


def test_file_replaced_before_scan_is_not_passed_to_ruff(project, workspace, fake):
    root, _ = project
    (root / "pkg" / "b.py").unlink()
    (root / "pkg" / "b.py").mkdir()  # no longer a regular file
    command = fake()

    outcome = scan(project, workspace, command)
    (argv,) = fake.calls()

    assert not any(arg.endswith("b.py") for arg in argv)
    assert [(n.relative_path, n.reason) for n in outcome.execution.not_analyzed] == [
        ("pkg/b.py", NotAnalyzedReason.CHANGED_BEFORE_SCAN)
    ]


def test_identical_diagnostics_get_distinct_ids(project, workspace, fake):
    outcome = scan(project, workspace, fake(diagnostics=[diag("F401"), diag("F401")]))

    assert len({f.finding_id for f in outcome.findings}) == 2


def test_untrusted_reference_urls_are_dropped(project, workspace, fake):
    command = fake(diagnostics=[diag("F401", url="https://evil.example/phish")])

    (finding,) = scan(project, workspace, command).findings

    assert finding.references == []


# ------------------------------------------------- S101 (assert) policy for test files


@pytest.fixture
def mixed_project(make_tree):
    root = make_tree(
        {
            "app": {"core.py": ""},
            "tests": {"test_core.py": "", "conftest.py": ""},
            "test_root.py": "",
        },
        name="mixed",
    ).resolve()
    files = [
        entry("app/core.py"),
        entry("tests/test_core.py", FileCategory.TEST),
        entry("tests/conftest.py", FileCategory.TEST),
        entry("test_root.py", FileCategory.TEST),
    ]
    return root, files


def test_s101_in_test_files_is_suppressed_and_counted(mixed_project, workspace, fake):
    # file_index follows the inventory order: 0 app/core.py, 1..3 test files
    command = fake(
        diagnostics=[
            diag("S101", name="assert", file_index=1),
            diag("S101", name="assert", row=2, file_index=1),
            diag("S101", name="assert", file_index=2),
            diag("S101", name="assert", file_index=3),
        ]
    )

    outcome = scan(mixed_project, workspace, command)

    assert outcome.findings == []
    (suppressed,) = outcome.execution.suppressed
    assert (suppressed.rule_id, suppressed.count) == ("S101", 4)
    assert "test files" in suppressed.reason


def test_s101_in_production_code_is_still_reported(mixed_project, workspace, fake):
    command = fake(diagnostics=[diag("S101", name="assert", file_index=0)])

    outcome = scan(mixed_project, workspace, command)

    assert [(f.rule_id, f.relative_path) for f in outcome.findings] == [("S101", "app/core.py")]
    assert outcome.execution.suppressed == []


def test_other_security_rules_in_test_files_are_not_suppressed(mixed_project, workspace, fake):
    command = fake(
        diagnostics=[
            diag("S602", file_index=1),
            diag("S307", file_index=2),
            diag("S105", file_index=3),
            diag("S101", name="assert", file_index=1),
        ]
    )

    outcome = scan(mixed_project, workspace, command)

    assert sorted(f.rule_id for f in outcome.findings) == ["S105", "S307", "S602"]
    assert outcome.execution.suppressed[0].count == 1


# ---------------------------------------------------- verification status & trust notes


def test_ruff_findings_are_never_confirmed(project, workspace, fake):
    command = fake(diagnostics=[diag(code) for code in ("S602", "F821", "invalid-syntax")])

    outcome = scan(project, workspace, command)

    assert {f.verification_status.value for f in outcome.findings} == {"NEEDS_REVIEW"}


def test_executable_inside_target_is_flagged_as_trust_assumption(tmp_path):
    root = tmp_path / "target"
    (root / ".venv" / "Scripts").mkdir(parents=True)
    inside = root / ".venv" / "Scripts" / "ruff.exe"

    note = ruff_adapter.executable_trust_note(inside, root)

    assert note is not None and "trust" in note.lower()
    assert ruff_adapter.executable_trust_note(tmp_path / "elsewhere" / "ruff.exe", root) is None


def test_trusted_executable_comes_only_from_our_environment(tmp_path, monkeypatch):
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    exe = scripts / ("ruff.exe" if sys.platform == "win32" else "ruff")
    exe.write_bytes(b"")
    monkeypatch.setattr(ruff_adapter.sysconfig, "get_path", lambda name: str(scripts))
    monkeypatch.setenv("PATH", str(tmp_path / "elsewhere"))

    assert ruff_adapter.find_ruff_executable() == exe

    exe.unlink()
    assert ruff_adapter.find_ruff_executable() is None  # never falls back to PATH
