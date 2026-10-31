"""Trusted scanner executables.

Executables are never looked up on PATH or in the current directory, and never taken from
the scanned target:

- Ruff: the binary installed next to the running interpreter (``ruff_adapter``, D-024).
- Semgrep: a dedicated, separately installed environment at a fixed per-user location
  (``<tools>/semgrep``), see D-035.
- Gitleaks: the official release binary at ``<tools>/gitleaks/<version>/``, pinned by SHA-256
  and verified before every run (D-043). The hash proves integrity against the release that
  was verified at install time; it does not independently prove the publisher's identity (the
  release carries no signature and the binary is not Authenticode-signed).
"""

import hashlib
import sys
from pathlib import Path

from auditor.core.config import default_tools_base
from auditor.discovery.repository import is_within

GITLEAKS_VERSION = "8.30.1"
# SHA-256 of gitleaks.exe extracted from gitleaks_8.30.1_windows_x64.zip (zip hash verified
# three ways: GitHub asset digest, release checksums file, local file; Stage 4a step 0).
GITLEAKS_SHA256 = {
    ("win32", "8.30.1"): "17157e2ee8b76fc8b1d8bee607a250e34b8a8023c8bc81822d4b5ee4d78fcb7c",
}


def gitleaks_executable(tools_base: Path | None = None) -> Path | None:
    base = tools_base if tools_base is not None else default_tools_base()
    name = "gitleaks.exe" if sys.platform == "win32" else "gitleaks"
    candidate = base / "gitleaks" / GITLEAKS_VERSION / name
    return candidate if candidate.is_file() else None


def pinned_gitleaks_sha256(platform: str = sys.platform) -> str | None:
    return GITLEAKS_SHA256.get((platform, GITLEAKS_VERSION))


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


PIP_AUDIT_VERSION = "2.10.1"


def pip_audit_python(tools_base: Path | None = None) -> Path | None:
    """Interpreter of the dedicated, hash-locked pip-audit environment (``<tools>/pip-audit``).

    Run as ``python -I -m pip_audit``: isolated mode ignores PYTHON* variables and user site.
    """
    base = tools_base if tools_base is not None else default_tools_base()
    venv = base / "pip-audit"
    if sys.platform == "win32":
        python, package = venv / "Scripts" / "python.exe", venv / "Lib" / "site-packages"
    else:
        python, package = (
            venv / "bin" / "python",
            next(venv.glob("lib/python*/site-packages"), venv),
        )
    return python if python.is_file() and (package / "pip_audit").is_dir() else None


def semgrep_executable(tools_base: Path | None = None) -> Path | None:
    base = tools_base if tools_base is not None else default_tools_base()
    scripts = "Scripts" if sys.platform == "win32" else "bin"
    name = "semgrep.exe" if sys.platform == "win32" else "semgrep"
    candidate = base / "semgrep" / scripts / name
    return candidate if candidate.is_file() else None


def resolves_inside(executable: Path, root: Path) -> bool:
    try:
        return is_within(Path(executable).resolve(), root)
    except OSError:
        return False


def trust_note(executable: Path, root: Path) -> str | None:
    """Explicit trust assumption when the auditor's own environment lies inside the target.

    Only the environment *running the auditor* is accepted there; no other executable from
    the target is ever run.
    """
    if not resolves_inside(executable, root):
        return None
    return (
        "Trust assumption: the auditor's own Python environment (including the Ruff "
        "executable) is located inside the scan target. It is used because it is the "
        "environment running the auditor; no other executable from the target is run."
    )
