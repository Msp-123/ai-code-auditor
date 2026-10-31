"""The target must not be able to influence, hijack or be modified by the Semgrep scan,
and Semgrep must not write to the real user profile (marked: semgrep)."""

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from auditor.cli import app
from auditor.core.models import FindingsReport
from auditor.scanners.semgrep_adapter import short_temp_base

pytestmark = pytest.mark.semgrep
runner = CliRunner()
SINK = "from flask import request\nimport os\nos.system('ls ' + request.args['d'])\n"
RULE = "auditor.python.command-injection.tainted-shell-command"


def scan(root, out_dir, *extra):
    result = runner.invoke(app, ["scan", str(root), "--output-dir", str(out_dir), *extra])
    run_dir = next(out_dir.iterdir())
    report = FindingsReport.model_validate_json((run_dir / "findings.json").read_text("utf-8"))
    return result, report, run_dir


def semgrep_rules(report):
    return sorted(
        (f.relative_path, f.rule_id) for f in report.findings if f.source_tool == "semgrep"
    )


def snapshot(root):
    state = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in dirnames + filenames:
            path = os.path.join(dirpath, name)
            st = os.lstat(path)
            digest = None
            if os.path.isfile(path):
                with open(path, "rb") as handle:
                    digest = hashlib.sha256(handle.read()).hexdigest()
            state[os.path.relpath(path, root)] = (st.st_size, st.st_mtime_ns, digest)
    return state


def test_hostile_semgrep_configs_and_ignore_files_cannot_narrow_the_scan(make_tree, out_dir):
    planted_rule = (
        "rules:\n- id: planted.everything\n  languages: [python]\n  severity: INFO\n"
        "  message: PLANTED\n  pattern: $X\n"
    )
    root = make_tree(
        {
            ".semgrep.yml": planted_rule,
            ".semgrep": {"planted.yml": planted_rule},
            ".semgrepignore": "*\n",
            ".gitignore": "*\n",
            "tests": {"test_app.py": SINK},  # Semgrep ignores tests/ by default
            "node_like": {".semgrepignore": "*\n", "app.py": SINK},
            "app.py": SINK,
        }
    )
    git = shutil.which("git")  # test setup only: make the target a real git repository
    if git is None:
        pytest.skip("git is needed to create a repository for the .gitignore case")
    subprocess.run([git, "init", "-q", str(root)], check=True, capture_output=True)  # noqa: S603

    result, report, _ = scan(root, out_dir)

    assert result.exit_code == 0, result.output
    assert semgrep_rules(report) == [
        ("app.py", RULE),
        ("node_like/app.py", RULE),
        ("tests/test_app.py", RULE),
    ]
    assert not any("PLANTED" in f.description for f in report.findings)


def test_nosemgrep_comments_cannot_hide_findings(make_tree, out_dir):
    code = SINK.replace("request.args['d'])", "request.args['d'])  # nosemgrep")

    _, report, _ = scan(make_tree({"app.py": code}), out_dir)

    assert semgrep_rules(report) == [("app.py", RULE)]


def test_semgrep_executables_planted_in_target_are_never_run(
    make_tree, out_dir, tmp_path, monkeypatch
):
    marker = tmp_path / "planted_semgrep_ran.marker"
    payload = f"open({str(marker)!r}, 'w').close()\n"
    script = f'@echo off\r\n"{sys.executable}" -c "{payload.strip()}"\r\n'
    root = make_tree(
        {
            "semgrep.bat": script,
            "semgrep.cmd": script,
            "semgrep.exe": b"MZ not a real executable",
            "semgrep.py": payload,
            ".venv": {"pyvenv.cfg": "home = x\n", "Scripts": {"semgrep.exe": b"MZ"}},
            "app.py": SINK,
        }
    )
    monkeypatch.chdir(root)
    monkeypatch.setenv("PATH", os.pathsep.join([str(root), str(root / ".venv" / "Scripts")]))

    result, report, _ = scan(root, out_dir)

    assert result.exit_code == 0, result.output
    assert next(e for e in report.tool_executions if e.tool == "semgrep").version == "1.182.1"
    assert not marker.exists()


def test_option_like_file_names_are_files(make_tree, out_dir):
    names = ["-h.py", "--config=evil.py", "--output=x.py", "--test.py"]
    root = make_tree({name: SINK for name in names})
    before = snapshot(root)

    result, report, _ = scan(root, out_dir)

    assert result.exit_code == 0, result.output
    assert sorted(path for path, _ in semgrep_rules(report)) == sorted(names)
    assert snapshot(root) == before


def test_target_is_unchanged_after_a_full_scan(make_tree, out_dir):
    root = make_tree({"pkg": {"a.py": SINK, "b.py": "import os\n"}, "broken.py": "def f(:\n"})
    before = snapshot(root)

    scan(root, out_dir)

    assert snapshot(root) == before
    assert sorted(os.listdir(root)) == ["broken.py", "pkg"]


def test_code_literals_and_secrets_do_not_leak(make_tree, out_dir):
    fake_secret = "kx9Qz2Lm8Vb4" + "Nc7Rt1Yw5Hs3" + "Jd6Fg0Pa"  # built at runtime
    code = SINK.replace("'ls '", f"'curl -H token:{fake_secret} '")
    root = make_tree({"app.py": code})

    result, report, run_dir = scan(root, out_dir)

    assert semgrep_rules(report) == [("app.py", RULE)]
    texts = [result.output, *(p.read_text("utf-8") for p in run_dir.iterdir())]
    assert all(fake_secret not in text for text in texts)
    assert all("requires login" not in text for text in texts)  # extra.lines never stored


def test_real_user_profile_and_short_temp_stay_clean(make_tree, out_dir):
    home_semgrep = Path.home() / ".semgrep"
    existed = home_semgrep.exists()
    state = sorted(p.name for p in home_semgrep.iterdir()) if existed else None
    base = short_temp_base()
    before = set(base.iterdir()) if base.exists() else set()

    scan(make_tree({"app.py": SINK}), out_dir)
    runner.invoke(app, ["doctor"])

    assert home_semgrep.exists() == existed
    if existed:
        assert sorted(p.name for p in home_semgrep.iterdir()) == state
    assert set(base.iterdir()) == before  # scratch, mirror, HOME redirect: all removed


def test_unreachable_proxy_does_not_break_the_offline_scan(make_tree, out_dir, monkeypatch):
    # Shows that no network access is *needed*. This is not an OS-level network block.
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        monkeypatch.setenv(key, "http://127.0.0.1:9")

    result, report, _ = scan(make_tree({"app.py": SINK}), out_dir)

    assert result.exit_code == 0, result.output
    assert semgrep_rules(report) == [("app.py", RULE)]


def test_temp_directory_inside_target_is_refused(make_tree, out_dir, monkeypatch):
    root = make_tree({"app.py": SINK})
    monkeypatch.setattr(tempfile, "tempdir", str(root))  # %TEMP% pointing into the target

    result, report, _ = scan(root, out_dir)

    sg = next(e for e in report.tool_executions if e.tool == "semgrep")
    assert result.exit_code == 3
    assert sg.status.value == "ERROR"
    assert not (root / "aca").exists()
