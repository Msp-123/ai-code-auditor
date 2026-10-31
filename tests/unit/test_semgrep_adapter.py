"""Semgrep adapter logic, driven by a fake semgrep (our own script) for fault injection."""

import json
import os
import shutil
import sys
import textwrap
from pathlib import Path

import pytest

from auditor.core.models import (
    FileCategory,
    FileEntry,
    NotAnalyzedReason,
    Severity,
    ToolStatus,
)
from auditor.discovery.repository import plain_path
from auditor.scanners.base import ScanContext
from auditor.scanners.semgrep_adapter import SemgrepAdapter, SemgrepOptions, short_temp_base
from auditor.scanners.semgrep_rules import RULES_DIR

FAKE_SEMGREP = textwrap.dedent(
    """
    import json, os, sys, time
    from pathlib import Path
    scenario = json.loads((Path(__file__).parent / "scenario.json").read_text("utf-8"))
    args = sys.argv[1:]
    if args == ["--version"]:
        print(scenario.get("version", "1.182.1"))
        sys.exit(0)
    with open(scenario["record"], "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"argv": args, "env": dict(os.environ), "cwd": os.getcwd(),
                             "files_exist": [os.path.exists(f) for f in
                                             args[args.index("--") + 1:]]}) + "\\n")
    time.sleep(scenario.get("sleep", 0))
    files = args[args.index("--") + 1:]
    out = args[args.index("--output") + 1]
    if scenario.get("copy_check"):
        rec = json.loads(Path(scenario["record"]).read_text("utf-8").splitlines()[-1])
        rec["copied_bytes"] = [Path(f).read_bytes().hex() for f in files]
        lines = Path(scenario["record"]).read_text("utf-8").splitlines()[:-1] + [json.dumps(rec)]
        Path(scenario["record"]).write_text("\\n".join(lines) + "\\n", "utf-8")
    if "raw" in scenario:
        Path(out).write_text(scenario["raw"], "utf-8")
    elif scenario.get("write", True):
        results = []
        for r in scenario.get("results", []):
            r = dict(r)
            r.setdefault("path", files[r.pop("file_index", 0)])
            results.append(r)
        errors = []
        for e in scenario.get("errors", []):
            e = dict(e)
            if "file_index" in e:
                e["path"] = files[e.pop("file_index")]
            errors.append(e)
        scanned = [f for i, f in enumerate(files) if i not in scenario.get("not_scanned", [])]
        paths = {"scanned": scanned}
        if scenario.get("skipped"):
            paths["skipped"] = [{"path": files[i], "reason": why}
                                for i, why in scenario["skipped"]]
        Path(out).write_text(json.dumps({"version": "1.182.1", "results": results,
                                          "errors": errors, "paths": paths}), "utf-8")
    sys.exit(scenario.get("exit", 0))
    """
)

RULE = "auditor.python.command-injection.tainted-shell-command"


def result(check_id=RULE, line=3, file_index=0, **extra):
    data = {
        "check_id": check_id,
        "file_index": file_index,
        "start": {"line": line, "col": 5, "offset": 10},
        "end": {"line": line, "col": 30, "offset": 35},
        "extra": {
            "message": "User-controlled data flows into a shell command.",
            "severity": "ERROR",
            "metadata": {
                "auditor_severity": "HIGH",
                "confidence": "HIGH",
                "cwe": ["CWE-78: OS Command Injection"],
                "owasp": ["A03:2021 - Injection"],
                "references": [
                    "https://cwe.mitre.org/data/definitions/78.html",
                    "http://insecure.example/ref",
                    "javascript:alert(1)",
                ],
                "auditor_recommendation": "Use an argument list with shell=False.",
            },
            "lines": "subprocess.run(SECRET_CODE_LINE, shell=True)",
            "metavars": {"$CMD": {"abstract_content": "SECRET_METAVAR_CONTENT"}},
            "fix": "SECRET_FIX_TEXT",
            "fingerprint": "requires login",
        },
    }
    data["extra"].update(extra)
    return data


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
    root = make_tree({"app": {"a.py": "", "b.py": ""}, "README.md": ""}).resolve()
    return root, [entry("app/a.py"), entry("app/b.py"), entry("README.md", FileCategory.DOC)]


@pytest.fixture
def workspace(tmp_path):
    path = tmp_path / "ws"
    path.mkdir()
    return path


@pytest.fixture
def fake(tmp_path):
    fake_dir = tmp_path / "fake_semgrep"
    fake_dir.mkdir()
    (fake_dir / "semgrep.py").write_text(FAKE_SEMGREP, encoding="utf-8")
    record = fake_dir / "calls.jsonl"

    def configure(**scenario):
        scenario.setdefault("record", str(record))
        (fake_dir / "scenario.json").write_text(json.dumps(scenario), encoding="utf-8")
        return [sys.executable, str(fake_dir / "semgrep.py")]

    configure.calls = lambda: (
        [json.loads(line) for line in record.read_text("utf-8").splitlines()]
        if record.exists()
        else []
    )
    return configure


def scan(project, workspace, command, **options):
    root, files = project
    adapter = SemgrepAdapter(SemgrepOptions(**options), command=command)
    return adapter.scan(ScanContext(root=root, files=files, workspace=workspace))


# ------------------------------------------------------------------------------ status


def test_not_installed_when_tool_environment_is_missing(project, workspace, tmp_path):
    adapter = SemgrepAdapter(SemgrepOptions(), tools_base=tmp_path / "no-tools")

    outcome = adapter.scan(ScanContext(root=project[0], files=project[1], workspace=workspace))

    assert outcome.execution.status is ToolStatus.NOT_INSTALLED
    assert outcome.findings == []


def test_executable_inside_the_target_is_refused(project, workspace):
    root, files = project
    planted = root / "semgrep.exe"
    planted.write_bytes(b"")

    outcome = SemgrepAdapter(SemgrepOptions(), command=[str(planted)]).scan(
        ScanContext(root=root, files=files, workspace=workspace)
    )

    assert outcome.execution.status is ToolStatus.ERROR
    assert "inside the scan target" in outcome.execution.reason


def test_skipped_without_python_files(project, workspace, fake):
    root, _ = project
    outcome = SemgrepAdapter(SemgrepOptions(), command=fake()).scan(
        ScanContext(root=root, files=[entry("README.md", FileCategory.DOC)], workspace=workspace)
    )

    assert outcome.execution.status is ToolStatus.SKIPPED


def test_too_long_temporary_path_is_reported_not_hidden(project, workspace, fake, tmp_path):
    long_base = tmp_path / ("w" * 40)

    outcome = scan(project, workspace, fake(), temp_base=long_base)

    assert outcome.execution.status is ToolStatus.ERROR
    assert "too long" in outcome.execution.reason
    assert fake.calls() == []  # semgrep was not even started
    assert list(long_base.iterdir()) == []  # the scratch dir was still removed


def test_scratch_directory_is_short_private_and_removed(project, workspace, fake):
    base = short_temp_base()
    before = set(base.iterdir()) if base.exists() else set()

    outcome = scan(project, workspace, fake())
    (call,) = fake.calls()
    home = Path(call["env"]["HOME"])

    assert outcome.execution.status is ToolStatus.SUCCESS
    assert home.parent.parent == base.resolve()
    assert len(str(home.parent)) <= 70
    assert not home.parent.exists()  # removed after the run
    assert set(base.iterdir()) == before


def test_scratch_directory_inside_the_target_is_refused(project, workspace, fake):
    root, _ = project

    outcome = scan(project, workspace, fake(), temp_base=root / "tmp")

    assert outcome.execution.status is ToolStatus.ERROR
    assert "temporary directory refused" in outcome.execution.reason
    assert not (root / "tmp").exists()


def test_tampered_ruleset_is_an_error(project, workspace, fake, tmp_path):
    rules = tmp_path / "rules"
    shutil.copytree(RULES_DIR, rules)
    (rules / "ssrf.yaml").write_text("rules: []\n", encoding="utf-8")

    outcome = scan(project, workspace, fake(), rules_dir=rules)

    assert outcome.execution.status is ToolStatus.ERROR
    assert "integrity" in outcome.execution.reason
    assert fake.calls() == []


# ------------------------------------------------------------------------ command & env


def test_command_line_and_environment_are_locked_down(project, workspace, fake, monkeypatch):
    monkeypatch.setenv("SEMGREP_APP_TOKEN", "FAKE-token-must-not-leak")
    monkeypatch.setenv("SEMGREP_RULES", "p/python")

    outcome = scan(project, workspace, fake())
    (call,) = fake.calls()
    argv, env = call["argv"], call["env"]

    assert argv[0] == "scan"
    for flag in (
        "--json",
        "--metrics=off",
        "--disable-version-check",
        "--disable-nosem",
        "--no-git-ignore",
        "--no-rewrite-rule-ids",
    ):
        assert flag in argv
    config = Path(argv[argv.index("--config") + 1])
    scratch = config.parent  # verified private copy, not the package dir or the target
    assert scratch.parent == short_temp_base().resolve()
    assert not config.is_relative_to(project[0])
    assert argv[argv.index("--timeout") + 1] == "30"
    files = argv[argv.index("--") + 1 :]
    assert sorted(Path(f).name for f in files) == ["a.py", "b.py"]  # README not passed
    assert all(Path(f).is_absolute() for f in files)
    joined = " ".join(argv)
    for forbidden in ("auto", "--validate", " ci", "login", "p/", "http"):
        assert forbidden not in joined
    assert Path(env["HOME"]).is_relative_to(scratch)
    assert Path(env["USERPROFILE"]).is_relative_to(scratch)
    assert Path(env["TEMP"]) == scratch
    assert "SEMGREP_APP_TOKEN" not in env and "SEMGREP_RULES" not in env
    assert env["SEMGREP_SEND_METRICS"] == "off"
    assert env["SEMGREP_ENABLE_VERSION_CHECK"] == "0"
    assert outcome.execution.settings["ruleset_version"]


# ------------------------------------------------------- private mirror (D-040 / walk fix)


def test_semgrep_only_sees_a_private_mirror_never_the_target(project, workspace, fake):
    root, _ = project

    outcome = scan(project, workspace, fake(results=[result(file_index=1)]))
    (call,) = fake.calls()
    passed = [Path(p) for p in call["argv"][call["argv"].index("--") + 1 :]]
    cwd = Path(call["cwd"])

    assert all(call["files_exist"])  # the copies existed while Semgrep ran
    assert not any(Path(plain_path(str(p))).is_relative_to(root) for p in passed)
    # cwd = mirror root, in the same (extended on Windows) form as the targets: no tree walk
    assert all(p.is_relative_to(cwd) for p in passed)
    plain_cwd = Path(plain_path(str(cwd)))
    assert plain_cwd.name == "m" and plain_cwd.parent.parent == short_temp_base().resolve()
    assert not plain_cwd.exists()  # mirror removed after the run
    (finding,) = outcome.findings
    assert finding.relative_path == "app/b.py"  # mapped back to the inventory path


def test_mirror_preserves_content_byte_for_byte(make_tree, workspace, fake):
    content = "# çalışma\r\nx = eval(input())  \n\tmixed\rendings\n"
    root = make_tree({"pkg": {"m.py": ""}}).resolve()
    (root / "pkg" / "m.py").write_bytes(content.encode("utf-8"))
    command = fake(copy_check=True)

    SemgrepAdapter(SemgrepOptions(), command=command).scan(
        ScanContext(root=root, files=[entry("pkg/m.py")], workspace=workspace)
    )
    (call,) = fake.calls()

    assert call["copied_bytes"] == [content.encode("utf-8").hex()]


def test_file_replaced_during_copy_is_not_analyzed(project, workspace, fake, monkeypatch):
    import auditor.scanners.semgrep_adapter as semgrep_adapter

    real_open = os.open

    def swap_then_open(path, flags, *args):
        if str(path).endswith("a.py") and not flags & os.O_WRONLY:
            target = Path(str(path).removeprefix("\\\\?\\"))
            target.unlink()
            target.write_text("planted", encoding="utf-8")  # new file, new identity
        return real_open(path, flags, *args)

    monkeypatch.setattr(semgrep_adapter.os, "open", swap_then_open)

    outcome = scan(project, workspace, fake())

    assert [(n.relative_path, n.reason) for n in outcome.execution.not_analyzed] == [
        ("app/a.py", NotAnalyzedReason.CHANGED_BEFORE_SCAN)
    ]


def test_file_larger_than_max_target_bytes_is_not_copied(project, workspace, fake):
    root, _ = project
    (root / "app" / "b.py").write_text("x = 1\n" * 50, encoding="utf-8")

    outcome = scan(project, workspace, fake(), max_target_bytes=100)
    (call,) = fake.calls()

    assert len(call["argv"][call["argv"].index("--") + 1 :]) == 1
    (item,) = outcome.execution.not_analyzed
    assert (item.relative_path, item.reason) == ("app/b.py", NotAnalyzedReason.SKIPPED_BY_TOOL)
    assert "max-target-bytes" in item.detail


# ------------------------------------------------------------------------------ mapping


def test_results_are_mapped_and_code_text_is_never_kept(project, workspace, fake):
    outcome = scan(project, workspace, fake(results=[result(file_index=1)]))
    (finding,) = outcome.findings

    assert outcome.execution.status is ToolStatus.SUCCESS
    assert (finding.rule_id, finding.relative_path, finding.start_line) == (RULE, "app/b.py", 3)
    assert finding.severity is Severity.HIGH
    assert finding.confidence.value == "HIGH"
    assert finding.verification_status.value == "NEEDS_REVIEW"
    assert finding.source_tool == "semgrep"
    assert "CWE-78: OS Command Injection" in finding.tags
    assert finding.references == ["https://cwe.mitre.org/data/definitions/78.html"]
    assert finding.recommendation == "Use an argument list with shell=False."
    dumped = finding.model_dump_json()
    for secret in ("SECRET_CODE_LINE", "SECRET_METAVAR_CONTENT", "SECRET_FIX_TEXT"):
        assert secret not in dumped


def test_severity_falls_back_to_semgrep_severity(project, workspace, fake):
    plain = result()
    plain["extra"]["metadata"] = {}
    plain["extra"]["severity"] = "WARNING"

    (finding,) = scan(project, workspace, fake(results=[plain])).findings

    assert finding.severity is Severity.MEDIUM
    assert finding.confidence.value == "LOW"


def test_results_from_unknown_rules_are_dropped(project, workspace, fake):
    outcome = scan(project, workspace, fake(results=[result("planted.rule"), result()]))

    assert [f.rule_id for f in outcome.findings] == [RULE]
    assert any("unknown rule" in w for w in outcome.execution.warnings)


def test_results_for_unexpected_paths_are_dropped(project, workspace, fake, tmp_path):
    stray = result()
    stray.pop("file_index")
    stray["path"] = str(tmp_path / "outside.py")

    outcome = scan(project, workspace, fake(results=[stray, result()]))

    assert len(outcome.findings) == 1
    assert any("unexpected path" in w for w in outcome.execution.warnings)


# ------------------------------------------------------------------------------ coverage


def test_every_passed_file_is_scanned_or_explained(project, workspace, fake):
    outcome = scan(project, workspace, fake(not_scanned=[1]))

    (item,) = outcome.execution.not_analyzed
    assert (item.relative_path, item.reason) == ("app/b.py", NotAnalyzedReason.SKIPPED_BY_TOOL)
    assert outcome.execution.files_analyzed == 1


def test_skipped_paths_keep_semgreps_reason(project, workspace, fake):
    outcome = scan(project, workspace, fake(not_scanned=[0], skipped=[[0, "too_big"]]))

    (item,) = outcome.execution.not_analyzed
    assert item.reason is NotAnalyzedReason.SKIPPED_BY_TOOL
    assert "too_big" in item.detail


@pytest.mark.parametrize(
    ("error_type", "reason"),
    [
        ("Timeout", NotAnalyzedReason.TIMED_OUT),
        ("Syntax error", NotAnalyzedReason.PARSE_ERROR),
        ("OutOfMemory", NotAnalyzedReason.TOOL_ERROR),
    ],
)
def test_file_level_errors_mean_not_analyzed(project, workspace, fake, error_type, reason):
    error = {"level": "error", "type": error_type, "message": "x", "file_index": 0}

    outcome = scan(project, workspace, fake(errors=[error]))

    assert [(n.relative_path, n.reason) for n in outcome.execution.not_analyzed] == [
        ("app/a.py", reason)
    ]


def test_run_level_error_without_path_is_an_error(project, workspace, fake):
    outcome = scan(
        project,
        workspace,
        fake(errors=[{"level": "error", "type": "Rule parse error", "message": "bad rule"}]),
    )

    assert outcome.execution.status is ToolStatus.ERROR


@pytest.mark.parametrize(
    ("scenario", "expected"),
    [
        ({"exit": 2, "write": False}, "exit code 2"),
        ({"exit": 0, "raw": "<ERROR: missing output>"}, "invalid JSON"),
        ({"exit": 0, "raw": json.dumps({"results": "nope"})}, "unexpected output format"),
        ({"exit": 0, "write": False}, "no output file"),
    ],
)
def test_tool_failures_are_errors_never_clean(project, workspace, fake, scenario, expected):
    outcome = scan(project, workspace, fake(**scenario))

    assert outcome.execution.status is ToolStatus.ERROR
    assert expected in outcome.execution.reason
    assert outcome.findings == []
    assert outcome.execution.files_analyzed == 0


def test_timeout_is_timed_out(project, workspace, fake):
    outcome = scan(project, workspace, fake(sleep=30), batch_timeout=2.0)

    assert outcome.execution.status is ToolStatus.TIMED_OUT
    assert {n.reason for n in outcome.execution.not_analyzed} == {NotAnalyzedReason.TIMED_OUT}


def test_version_other_than_the_tested_one_is_warned(project, workspace, fake):
    outcome = scan(project, workspace, fake(version="1.200.0"))

    assert any("1.182.1" in w for w in outcome.execution.warnings)


def test_long_paths_are_passed_in_extended_form_and_mapped_back(tmp_path, workspace, fake):
    root = (tmp_path / "target").resolve()
    rel_parts = ["directory_name_x"] * 14
    deep = "\\\\?\\" + os.path.join(str(root), *rel_parts) if os.name == "nt" else None
    if deep is None:
        pytest.skip("Windows MAX_PATH behaviour")
    os.makedirs(deep)
    with open(os.path.join(deep, "deep.py"), "w", encoding="utf-8"):
        pass
    rel = "/".join([*rel_parts, "deep.py"])
    base = short_temp_base()
    before = set(base.iterdir()) if base.exists() else set()
    context = ScanContext(root=root, files=[entry(rel)], workspace=workspace)
    try:
        outcome = SemgrepAdapter(SemgrepOptions(), command=fake(results=[result()])).scan(context)
        (call,) = fake.calls()
        passed = call["argv"][call["argv"].index("--") + 1 :]

        assert passed[0].startswith("\\\\?\\")
        assert [f.relative_path for f in outcome.findings] == [rel]
        assert outcome.execution.not_analyzed == []
        # D-042: the long-path mirror copy is removed too (it used to stay behind silently).
        assert context.cleanup_failures == []
        assert set(base.iterdir()) == before
    finally:
        shutil.rmtree("\\\\?\\" + str(root))


# ------------------------------------------------------------------ cleanup (D-042)


@pytest.mark.parametrize(
    ("scenario", "options", "status"),
    [
        ({"results": [result()]}, {}, ToolStatus.SUCCESS),
        ({"exit": 2, "write": False}, {}, ToolStatus.ERROR),
        ({"sleep": 30}, {"batch_timeout": 2.0}, ToolStatus.TIMED_OUT),
    ],
)
def test_scratch_and_source_copies_are_removed_after_every_status(
    project, workspace, fake, scenario, options, status
):
    root, files = project
    base = short_temp_base()
    before = set(base.iterdir()) if base.exists() else set()
    context = ScanContext(root=root, files=files, workspace=workspace)

    outcome = SemgrepAdapter(SemgrepOptions(**options), command=fake(**scenario)).scan(context)
    (call,) = fake.calls()

    assert outcome.execution.status is status
    assert all(call["files_exist"])  # the mirror copies existed during the run ...
    assert context.cleanup_failures == []
    assert set(base.iterdir()) == before  # ... and are gone afterwards


def test_scratch_is_removed_when_the_adapter_raises(project, workspace, fake, monkeypatch):
    import auditor.scanners.semgrep_adapter as adapter_module

    root, files = project
    base = short_temp_base()
    before = set(base.iterdir()) if base.exists() else set()
    seen = []

    def boom(ruleset, scratch):
        (scratch / "m").mkdir()
        (scratch / "m" / "copy.py").write_text("SOURCE_COPY = 1", encoding="utf-8")
        seen.append(scratch)
        raise RuntimeError("unexpected")

    monkeypatch.setattr(adapter_module, "materialize", boom)
    context = ScanContext(root=root, files=files, workspace=workspace)

    with pytest.raises(RuntimeError):
        SemgrepAdapter(SemgrepOptions(), command=fake()).scan(context)

    assert seen and not seen[0].exists()
    assert context.cleanup_failures == []
    assert set(base.iterdir()) == before


# --------------------------------------------------------------- H5 evidence rules (observations)


def test_evidence_rule_results_are_observations_not_findings(project, workspace, fake):
    evidence = result(check_id="auditor.python.flow-evidence.request-to-call-arg", line=7,
                      file_index=1)  # fmt: skip
    evidence["start"]["col"] = 21

    outcome = scan(project, workspace, fake(results=[evidence, result(file_index=0)]))

    assert [f.rule_id for f in outcome.findings] == [RULE]  # the real rule only
    (observation,) = outcome.observations
    assert observation.kind == "request_call" and observation.kind_rule == "request-to-call-arg"
    assert (observation.relative_path, observation.line, observation.column) == ("app/b.py", 7, 21)
    assert not any("unknown rule" in w for w in outcome.execution.warnings)
