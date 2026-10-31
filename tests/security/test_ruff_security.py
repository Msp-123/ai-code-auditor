"""The target must not be able to influence, hijack or be modified by the Ruff scan."""

import hashlib
import os
import sys

import pytest
from typer.testing import CliRunner

from auditor.cli import app
from auditor.core.models import FindingsReport

runner = CliRunner()
EVAL = "x = eval(input())\n"


@pytest.fixture(autouse=True)
def private_app_dirs(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "appdata"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "appdata"))


def scan(root, out_dir):
    result = runner.invoke(app, ["scan", str(root), "--output-dir", str(out_dir)])
    run_dir = next(out_dir.iterdir())
    report = FindingsReport.model_validate_json((run_dir / "findings.json").read_text("utf-8"))
    return result, report, run_dir


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


def test_hostile_ruff_configuration_in_target_is_ignored(make_tree, out_dir, tmp_path):
    evil_cache = (tmp_path / "evil_cache").as_posix()
    hostile = (
        "[tool.ruff]\n"
        f"cache-dir = '{evil_cache}'\n"
        "extend = '../../outside/does-not-exist.toml'\n"
        "exclude = ['*']\n"
        "[tool.ruff.lint]\n"
        "ignore = ['ALL']\n"
        "per-file-ignores = {'*' = ['ALL']}\n"
    )
    root = make_tree(
        {
            "pyproject.toml": hostile,
            "ruff.toml": hostile.replace("[tool.ruff]", "").replace("[tool.ruff.lint]", "[lint]"),
            ".ruff.toml": "extend = 'C:/Windows/win.ini'\n",
            "app.py": EVAL,
        }
    )

    result, report, _ = scan(root, out_dir)

    assert result.exit_code == 0, result.output
    assert report.tool_executions[0].status.value == "SUCCESS"
    assert [f.rule_id for f in report.findings] == ["S307"]  # not hidden by ignore/exclude
    assert not os.path.exists(evil_cache)
    assert not (root / ".ruff_cache").exists()


def test_noqa_comments_cannot_hide_findings(make_tree, out_dir):
    root = make_tree({"app.py": "x = eval(input())  # noqa\ny = eval(input())  # noqa: S307\n"})

    _, report, _ = scan(root, out_dir)

    assert [(f.rule_id, f.start_line) for f in report.findings] == [("S307", 1), ("S307", 2)]


def test_ruff_executables_planted_in_target_are_never_run(
    make_tree, out_dir, tmp_path, monkeypatch
):
    marker = tmp_path / "planted_ruff_ran.marker"
    payload = f"open({str(marker)!r}, 'w').close()\n"
    script = f'@echo off\r\n"{sys.executable}" -c "{payload.strip()}"\r\n'
    root = make_tree(
        {
            "ruff.py": payload,
            "ruff.bat": script,
            "ruff.cmd": script,
            "ruff.exe": b"MZ not a real executable",
            ".venv": {
                "pyvenv.cfg": "home = x\n",
                "Scripts": {"ruff.exe": b"MZ"},
                "bin": {"ruff": payload},
            },
            "app.py": EVAL,
        }
    )
    # Make a PATH- or cwd-based lookup pick the planted binaries if the code ever did one.
    monkeypatch.chdir(root)
    monkeypatch.setenv("PATH", os.pathsep.join([str(root), str(root / ".venv" / "Scripts")]))

    result, report, _ = scan(root, out_dir)

    assert result.exit_code == 0, result.output
    assert report.tool_executions[0].version == "0.17.3"
    assert not marker.exists()


def test_option_like_file_names_are_treated_as_files(make_tree, out_dir):
    names = ["-h.py", "--fix.py", "--config=evil.py", "--output-file=x.py"]
    root = make_tree({name: EVAL for name in names})
    before = snapshot(root)

    result, report, _ = scan(root, out_dir)

    assert result.exit_code == 0, result.output
    assert sorted(f.relative_path for f in report.findings) == sorted(names)
    assert snapshot(root) == before  # in particular: --fix was never applied


def test_target_is_unchanged_after_a_full_ruff_scan(make_tree, out_dir):
    root = make_tree(
        {
            "pkg": {"a.py": "import os\nimport sys\n", "b.py": EVAL},
            "broken.py": "def f(:\n",
            "pyproject.toml": "[tool.ruff]\nline-length = 10\n",
        }
    )
    before = snapshot(root)

    scan(root, out_dir)

    assert snapshot(root) == before
    assert sorted(os.listdir(root)) == ["broken.py", "pkg", "pyproject.toml"]


def test_code_literals_in_messages_are_redacted_everywhere(make_tree, out_dir, tmp_path):
    fake_secret = "kx9Qz2Lm8Vb4" + "Nc7Rt1Yw5Hs3" + "Jd6Fg0Pa"  # built at runtime
    root = make_tree({"tmp_use.py": f"path = '/tmp/{fake_secret}'\n"})

    result, report, run_dir = scan(root, out_dir)

    (finding,) = report.findings
    assert finding.rule_id == "S108"
    assert "<redacted:" in finding.description
    outputs = [result.output, *(p.read_text("utf-8") for p in run_dir.iterdir())]
    assert all(fake_secret not in text for text in outputs)
    temp_base = tmp_path / "appdata" / "ai-code-auditor" / "tmp"
    assert list(temp_base.iterdir()) == []  # raw Ruff JSON (unredacted) is gone


def test_limitation_low_entropy_literal_is_not_redacted(make_tree, out_dir):
    # Documented limitation: redaction is heuristic. A short, low-entropy literal that Ruff
    # quotes in a message is kept. Secret detection proper is Gitleaks (Stage 4).
    root = make_tree({"tmp_use.py": "path = '/tmp/hunter2'\n"})

    _, report, _ = scan(root, out_dir)

    assert "/tmp/hunter2" in report.findings[0].description  # noqa: S108 - fixture text
