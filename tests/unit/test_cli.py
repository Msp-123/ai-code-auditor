import os
import subprocess
import sys
from importlib.metadata import version

import typer
from typer.testing import CliRunner

import auditor
from auditor.cli import app

runner = CliRunner()


def test_package_version_matches_metadata():
    assert auditor.__version__ == version("ai-code-auditor")


def test_help_exits_zero_and_lists_only_implemented_commands():
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "doctor" in result.output
    assert "scan" in result.output
    # Not-yet-implemented commands must not be offered (master plan §3.2).
    assert set(typer.main.get_command(app).commands) == {"doctor", "scan", "report"}


def test_version_option_prints_version():
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.output.strip() == f"auditor {auditor.__version__}"


def test_short_version_option():
    result = runner.invoke(app, ["-V"])

    assert result.exit_code == 0
    assert auditor.__version__ in result.output


def test_unknown_command_fails():
    result = runner.invoke(app, ["foo"])

    assert result.exit_code != 0


def test_module_entry_point_runs():
    # Runs our own package only — never a target project.
    # Decode as UTF-8 explicitly: the Windows locale code page (e.g. cp1254) cannot
    # decode Rich's box-drawing characters.
    completed = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "auditor", "--help"],
        shell=False,
        capture_output=True,
        encoding="utf-8",
        env={**os.environ, "PYTHONUTF8": "1"},
        timeout=30,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert "doctor" in completed.stdout


def test_subprocesses_inherit_the_test_temp_sandbox(sandboxed_short_temp):
    # Guards conftest: an ``auditor`` subprocess must never purge the developer's real %TEMP%.
    completed = subprocess.run(  # noqa: S603 - runs the interpreter only
        [
            sys.executable,
            "-c",
            "import os, tempfile; print(tempfile.gettempdir());"
            " [print(os.environ[k]) for k in ('TEMP', 'TMP', 'TMPDIR')]",
        ],
        shell=False,
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )

    # gettempdir(), TEMP, TMP, TMPDIR: all four point into the sandbox
    assert completed.stdout.splitlines() == [str(sandboxed_short_temp)] * 4
