import platform
import sys

import pytest
from typer.testing import CliRunner

from auditor.cli import app, check_python_version

runner = CliRunner()


def test_tests_run_on_python_312():
    assert sys.version_info[:2] == (3, 12)


@pytest.mark.parametrize("version_info", [(3, 12, 0), (3, 12, 1), (3, 13, 0)])
def test_check_python_version_accepts_supported(version_info):
    ok, message = check_python_version(version_info)

    assert ok
    assert ".".join(map(str, version_info)) in message


@pytest.mark.parametrize("version_info", [(3, 9, 6), (3, 10, 0), (3, 11, 9), (2, 7, 18)])
def test_check_python_version_rejects_unsupported(version_info):
    ok, message = check_python_version(version_info)

    assert not ok
    assert "3.12" in message


def test_doctor_reports_environment():
    result = runner.invoke(app, ["doctor"])

    assert result.exit_code == 0
    assert platform.python_version() in result.output
    assert platform.platform() in result.output
    assert "venv        yes" in result.output
    assert "status      OK" in result.output


def test_doctor_reports_the_trusted_ruff():
    result = runner.invoke(app, ["doctor"])

    assert "ruff        0.17.3 (" in result.output


def test_doctor_fails_when_ruff_is_missing(monkeypatch):
    import auditor.cli as cli

    monkeypatch.setattr(cli, "find_ruff_executable", lambda: None)

    result = runner.invoke(app, ["doctor"])

    assert result.exit_code == 1
    assert "ruff        NOT FOUND" in result.output
    assert "status      OK" not in result.output


def test_doctor_fails_on_unsupported_python(monkeypatch):
    monkeypatch.setattr(sys, "version_info", (3, 9, 6, "final", 0))

    result = runner.invoke(app, ["doctor"])

    assert result.exit_code == 1
    assert "3.12" in result.output
    assert "status      OK" not in result.output
