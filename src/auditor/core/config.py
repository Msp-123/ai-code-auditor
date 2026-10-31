"""Application-level configuration: where the auditor keeps its own output."""

import os
import sys
from collections.abc import Mapping
from pathlib import Path

APP_DIR_NAME = "ai-code-auditor"


def default_reports_base(
    env: Mapping[str, str] | None = None,
    platform: str | None = None,
    home: Path | None = None,
) -> Path:
    """Per-user reports directory, independent of any scanned project.

    - Windows: ``%LOCALAPPDATA%\\ai-code-auditor\\reports``
    - Linux/other POSIX: ``$XDG_DATA_HOME/ai-code-auditor/reports``
      (default ``~/.local/share``; a relative ``XDG_DATA_HOME`` is ignored per the XDG spec)
    - macOS: ``~/Library/Application Support/ai-code-auditor/reports``
    """
    return app_data_base(env, platform, home) / "reports"


def default_temp_base(
    env: Mapping[str, str] | None = None,
    platform: str | None = None,
    home: Path | None = None,
) -> Path:
    """Private scratch space for raw scanner output (cleaned after every run)."""
    return app_data_base(env, platform, home) / "tmp"


def default_tools_base(
    env: Mapping[str, str] | None = None,
    platform: str | None = None,
    home: Path | None = None,
) -> Path:
    """Where separately installed scanner environments live (e.g. ``tools/semgrep``).

    ``AUDITOR_TOOLS_DIR`` (absolute paths only) lets the *user* choose another location; the
    scanned target can never influence it.
    """
    source = os.environ if env is None else env
    override = source.get("AUDITOR_TOOLS_DIR")
    if override and os.path.isabs(override):
        return Path(override)
    return app_data_base(env, platform, home) / "tools"


def app_data_base(
    env: Mapping[str, str] | None = None,
    platform: str | None = None,
    home: Path | None = None,
) -> Path:
    env = os.environ if env is None else env
    platform = sys.platform if platform is None else platform
    home = Path.home() if home is None else home

    if platform == "win32":
        local_app_data = env.get("LOCALAPPDATA")
        base = Path(local_app_data) if local_app_data else home / "AppData" / "Local"
    elif platform == "darwin":
        base = home / "Library" / "Application Support"
    else:
        xdg = env.get("XDG_DATA_HOME")
        base = Path(xdg) if xdg and os.path.isabs(xdg) else home / ".local" / "share"
    return base / APP_DIR_NAME
