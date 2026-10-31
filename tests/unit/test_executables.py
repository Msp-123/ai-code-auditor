import sys
from pathlib import Path

from auditor.core.config import default_tools_base
from auditor.scanners.executables import semgrep_executable, trust_note

EXE = "semgrep.exe" if sys.platform == "win32" else "semgrep"
SCRIPTS = "Scripts" if sys.platform == "win32" else "bin"


def make_tool(base: Path) -> Path:
    scripts = base / "semgrep" / SCRIPTS
    scripts.mkdir(parents=True)
    exe = scripts / EXE
    exe.write_bytes(b"")
    return exe


def test_tools_base_defaults_to_app_data_dir():
    env = {"LOCALAPPDATA": r"C:\Users\u\AppData\Local"}

    base = default_tools_base(env=env, platform="win32", home=Path("/home/u"))

    assert base == Path(r"C:\Users\u\AppData\Local") / "ai-code-auditor" / "tools"


def test_tools_base_can_be_overridden_with_an_absolute_path(tmp_path):
    env = {"AUDITOR_TOOLS_DIR": str(tmp_path / "tools")}

    assert default_tools_base(env=env, platform="win32") == tmp_path / "tools"


def test_relative_tools_override_is_ignored():
    env = {"AUDITOR_TOOLS_DIR": "relative/tools", "LOCALAPPDATA": r"C:\L"}

    assert (
        default_tools_base(env=env, platform="win32") == Path(r"C:\L") / "ai-code-auditor" / "tools"
    )


def test_semgrep_is_taken_only_from_the_tools_directory(tmp_path, monkeypatch):
    exe = make_tool(tmp_path / "tools")

    assert semgrep_executable(tmp_path / "tools") == exe


def test_semgrep_on_path_is_never_used(tmp_path, monkeypatch):
    on_path = tmp_path / "pathdir"
    on_path.mkdir()
    (on_path / EXE).write_bytes(b"")
    monkeypatch.setenv("PATH", str(on_path))

    assert semgrep_executable(tmp_path / "empty-tools") is None


def test_trust_note_only_when_executable_is_inside_the_target(tmp_path):
    root = tmp_path / "target"
    (root / ".venv").mkdir(parents=True)

    assert "Trust assumption" in trust_note(root / ".venv" / "ruff.exe", root)
    assert trust_note(tmp_path / "tools" / "semgrep.exe", root) is None
