from pathlib import Path

from auditor.core.config import default_reports_base, default_temp_base

HOME = Path("/home/user")


def test_windows_uses_localappdata():
    base = default_reports_base(
        env={"LOCALAPPDATA": r"C:\Users\u\AppData\Local"}, platform="win32", home=HOME
    )
    assert base == Path(r"C:\Users\u\AppData\Local") / "ai-code-auditor" / "reports"


def test_windows_falls_back_to_home_when_localappdata_missing():
    base = default_reports_base(env={}, platform="win32", home=HOME)
    assert base == HOME / "AppData" / "Local" / "ai-code-auditor" / "reports"


def test_linux_uses_absolute_xdg_data_home():
    base = default_reports_base(env={"XDG_DATA_HOME": "/data/xdg"}, platform="linux", home=HOME)
    assert base == Path("/data/xdg") / "ai-code-auditor" / "reports"


def test_linux_ignores_relative_xdg_data_home():
    base = default_reports_base(env={"XDG_DATA_HOME": "relative/dir"}, platform="linux", home=HOME)
    assert base == HOME / ".local" / "share" / "ai-code-auditor" / "reports"


def test_linux_default_without_xdg():
    base = default_reports_base(env={}, platform="linux", home=HOME)
    assert base == HOME / ".local" / "share" / "ai-code-auditor" / "reports"


def test_temp_base_is_next_to_reports_in_the_app_directory():
    env = {"LOCALAPPDATA": r"C:\Users\u\AppData\Local"}

    temp = default_temp_base(env=env, platform="win32", home=HOME)

    assert temp == Path(r"C:\Users\u\AppData\Local") / "ai-code-auditor" / "tmp"
    assert temp.parent == default_reports_base(env=env, platform="win32", home=HOME).parent


def test_macos_uses_application_support():
    base = default_reports_base(env={}, platform="darwin", home=HOME)
    assert base == HOME / "Library" / "Application Support" / "ai-code-auditor" / "reports"
