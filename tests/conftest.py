"""Shared fixtures.

Fixture repositories are built programmatically under ``tmp_path`` instead of being committed:
a fixture containing ``.git``, ``.venv`` or ``.env`` cannot be committed cleanly, and fake
secrets are generated at runtime so this repository never contains secret-like literals.
"""

import os
import tempfile
import warnings
from collections.abc import Callable
from pathlib import Path

import pytest

from auditor.core.config import default_tools_base

TreeSpec = dict[str, "str | bytes | TreeSpec"]

SAMPLE_SPEC: TreeSpec = {
    "src": {"app": {"__init__.py": "", "main.py": "print('hello')\n"}},
    "tests": {"test_main.py": "def test_x():\n    pass\n", "conftest.py": ""},
    "requirements.txt": "typer==0.12.0\n",
    "pyproject.toml": "[project]\nname = 'sample'\n",
    "setup.py": "raise SystemExit('setup.py must never be executed')\n",
    "README.md": "# Sample\n",
    ".git": {"HEAD": "ref: refs/heads/main\n", "config": "[core]\n"},
    ".venv": {"pyvenv.cfg": "home = C:/Python312\n", "Lib": {"site.py": ""}},
    "node_modules": {"pkg": {"index.js": "module.exports = 1;\n"}},
    "__pycache__": {"main.cpython-312.pyc": b"\x00\x01"},
}


def build_tree(root: Path, spec: TreeSpec) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    for name, value in spec.items():
        path = root / name
        if isinstance(value, dict):
            build_tree(path, value)
        elif isinstance(value, bytes):
            path.write_bytes(value)
        else:
            path.write_text(value, encoding="utf-8")
    return root


# Captured before any test sandboxes LOCALAPPDATA: the separately installed scanner tools
# (e.g. Semgrep, D-035) are read from their real location, reports/temp go to the sandbox.
REAL_TOOLS_DIR = default_tools_base()


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "semgrep: runs the real Semgrep engine (slow)")
    config.addinivalue_line("markers", "gitleaks: runs the real Gitleaks binary")
    config.addinivalue_line("markers", "pip_audit: runs the real pip-audit (no network)")
    config.addinivalue_line("markers", "git_history: runs the real git on fixture repositories")
    config.addinivalue_line(
        "markers", "network: sends public test package names to api.osv.dev (opt-in)"
    )


def pytest_collection_modifyitems(config: pytest.Config, items) -> None:
    """Network tests run only with AUDITOR_NETWORK_TESTS=1 (explicit user permission)."""
    if os.environ.get("AUDITOR_NETWORK_TESTS") == "1":
        return
    skip = pytest.mark.skip(reason="network test: set AUDITOR_NETWORK_TESTS=1 to allow it")
    for item in items:
        if item.get_closest_marker("network") is not None:
            item.add_marker(skip)


class _SemgrepNotRunHere:
    """Stand-in for SemgrepAdapter in tests that are not about Semgrep (keeps them fast).

    Reported honestly as SKIPPED; tests marked ``@pytest.mark.semgrep`` use the real adapter.
    """

    name = "semgrep"
    marker = "semgrep"

    def __init__(self, options=None, *args, **kwargs):
        pass

    def scan(self, context):
        from auditor.core.models import ToolExecution, ToolStatus
        from auditor.scanners.base import ScanOutcome

        return ScanOutcome(
            ToolExecution(
                tool=self.name,
                version=None,
                status=ToolStatus.SKIPPED,
                reason=f"Not run in this test (pytest: not marked '{self.marker}')",
            ),
            [],
        )


class _GitleaksNotRunHere(_SemgrepNotRunHere):
    """Same for GitleaksAdapter; tests marked ``@pytest.mark.gitleaks`` use the real one."""

    name = "gitleaks"
    marker = "gitleaks"


class _PipAuditNotRunHere(_SemgrepNotRunHere):
    """Same for PipAuditAdapter; tests marked ``@pytest.mark.pip_audit`` use the real one."""

    name = "pip-audit"
    marker = "pip_audit"


@pytest.fixture(autouse=True)
def semgrep_only_where_needed(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch):
    import auditor.application.audit_service as service

    if request.node.get_closest_marker("semgrep") is None:
        monkeypatch.setattr(service, "SemgrepAdapter", _SemgrepNotRunHere)
    if request.node.get_closest_marker("gitleaks") is None:
        monkeypatch.setattr(service, "GitleaksAdapter", _GitleaksNotRunHere)
    if (
        request.node.get_closest_marker("pip_audit") is None
        and request.node.get_closest_marker("network") is None
    ):
        monkeypatch.setattr(service, "PipAuditAdapter", _PipAuditNotRunHere)


class GitBuilder:
    """A real git repository for tests, built with the test's own isolated git environment
    (no system/global config of the developer, fixed identity, no signing)."""

    def __init__(self, path: Path, git: str, home: Path, init_args: tuple[str, ...] = ()):
        import subprocess

        self._run = subprocess.run
        self.path, self.git_exe = path, git
        home.mkdir(parents=True, exist_ok=True)
        (home / "empty.gitconfig").write_text("", encoding="utf-8")
        self.env = {
            "SystemRoot": os.environ.get("SystemRoot", ""),
            "PATH": os.path.dirname(git),
            "HOME": str(home), "USERPROFILE": str(home), "TEMP": str(home), "TMP": str(home),
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": str(home / "empty.gitconfig"),
            "GIT_AUTHOR_NAME": "Fixture Person", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
            "GIT_COMMITTER_NAME": "Fixture Person",
            "GIT_COMMITTER_EMAIL": "fixture@example.invalid", "GIT_TERMINAL_PROMPT": "0",
        }  # fmt: skip
        path.mkdir(parents=True)
        self.git("init", "-q", "-b", "main", *init_args)

    def git(self, *args: str, stdin: bytes | None = None, check: bool = True) -> str:
        done = self._run(  # noqa: S603 - the test's own fixed argv
            [self.git_exe, "-c", "commit.gpgsign=false", *args], cwd=self.path, env=self.env,
            input=stdin, capture_output=True, timeout=120, check=False,
        )  # fmt: skip
        if check and done.returncode != 0:
            raise RuntimeError(f"fixture git {args[0]} failed with {done.returncode}")
        return done.stdout.decode("utf-8", "surrogateescape").strip()

    def write(self, relative: str, content: str | bytes) -> None:
        target = self.path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content.encode() if isinstance(content, str) else content)

    def commit(self, message: str = "change") -> str:
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-m", message)
        return self.git("rev-parse", "HEAD")


@pytest.fixture
def git_builder(tmp_path: Path) -> Callable[..., GitBuilder]:
    import shutil

    git = shutil.which("git")
    if git is None:
        pytest.skip("git is not installed")
    counter = iter(range(1000))

    def _make(name: str = "repo", init_args: tuple[str, ...] = ()) -> GitBuilder:
        home = tmp_path / f"git-home-{next(counter)}"
        return GitBuilder(tmp_path / name, git, home, init_args)

    return _make


@pytest.fixture(scope="session", autouse=True)
def sandboxed_short_temp(tmp_path_factory: pytest.TempPathFactory):
    """Semgrep's short scratch base (``%TEMP%\\aca``, D-039) points into a session sandbox.

    The real base may hold leftovers of the developer's own runs; tests must neither purge
    them (that is the user's decision) nor be influenced by them. The sandbox is still short
    enough for semgrep-core (see MAX_TEMP_PATH).
    """
    tmp_path_factory.getbasetemp()  # pytest's own temp root is fixed before tempdir changes
    from auditor.scanners.workspace import remove_owned_workspace

    real_base = Path(tempfile.gettempdir()) / "aca"
    real_base.mkdir(exist_ok=True)
    sandbox = Path(tempfile.mkdtemp(prefix="s-", dir=real_base))
    previous = tempfile.tempdir
    # Environment too: an ``auditor`` started as a subprocess must not use the real %TEMP%
    # (it once purged real leftovers there, see PROGRESS.md D-042).
    previous_env = {key: os.environ.get(key) for key in ("TEMP", "TMP", "TMPDIR")}
    tempfile.tempdir = str(sandbox)
    os.environ.update(dict.fromkeys(previous_env, str(sandbox)))
    try:
        yield sandbox
    finally:
        tempfile.tempdir = previous
        for key, value in previous_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        reason = remove_owned_workspace(sandbox)
        if reason is not None:
            warnings.warn(f"test temp sandbox not removed: {reason}", stacklevel=1)


@pytest.fixture(autouse=True)
def sandboxed_app_dirs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Default per-user report/temp directories point into the test sandbox, never the
    developer's real %LOCALAPPDATA% / XDG data directory."""
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "appdata"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "appdata"))
    monkeypatch.setenv("AUDITOR_TOOLS_DIR", str(REAL_TOOLS_DIR))


@pytest.fixture
def make_tree(tmp_path: Path) -> Callable[..., Path]:
    def _make(spec: TreeSpec, name: str = "target") -> Path:
        return build_tree(tmp_path / name, spec)

    return _make


@pytest.fixture
def sample_repo(make_tree: Callable[..., Path]) -> Path:
    return make_tree(SAMPLE_SPEC)


@pytest.fixture
def out_dir(tmp_path: Path) -> Path:
    """Report output directory that is a sibling of (never inside) the target."""
    return tmp_path / "out"


@pytest.fixture
def symlink() -> Callable[..., None]:
    """Create a symlink, or skip the test when the OS does not permit it."""

    def _symlink(link: Path, target: Path, target_is_directory: bool = False) -> None:
        try:
            os.symlink(target, link, target_is_directory=target_is_directory)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"symlink creation not permitted on this system: {exc}")

    return _symlink


@pytest.fixture
def junction() -> Callable[..., None]:
    """Create a Windows directory junction (no admin rights needed)."""

    def _junction(link: Path, target: Path) -> None:
        if os.name != "nt":
            pytest.skip("directory junctions exist only on Windows")
        import _winapi

        _winapi.CreateJunction(str(target), str(link))

    return _junction


class FakeSecrets:
    """Random, runtime-generated secrets in real token formats (never committed literals).

    ``cores`` holds the random part of every value; ``leaks(text)`` reports whether any core,
    or any 8-character window of one, occurs in a text (the canary check).
    """

    def __init__(self) -> None:
        import base64
        import json
        import secrets
        import string

        alnum = string.ascii_letters + string.digits
        b32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        self.cores: list[str] = []

        def rnd(alphabet: str, n: int) -> str:
            value = "".join(secrets.choice(alphabet) for _ in range(n))
            self.cores.append(value)
            return value

        header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
        claims = json.dumps({"sub": rnd(alnum, 12), "n": rnd(alnum, 10)}).encode()
        payload = base64.urlsafe_b64encode(claims).decode().rstrip("=")
        self.cores.append(payload)
        begin, end = "-----" + "BEGIN RSA PRIVATE KEY-----", "-----" + "END RSA PRIVATE KEY-----"
        self.values = {
            "aws": "AK" + "IA" + rnd(b32, 16),
            "github": "gh" + "p_" + rnd(alnum, 36),
            "slack": "xo"
            + "xb-"
            + rnd(string.digits, 12)
            + "-"
            + rnd(string.digits, 12)
            + "-"
            + rnd(alnum, 24),
            "generic": rnd(alnum, 32),
            "jwt": f"{header}.{payload}.{rnd(alnum + '-_', 43)}",
            "pem": "\n".join([begin, *(rnd(alnum + "+/", 64) for _ in range(12)), end]),
        }

    def __getitem__(self, key: str) -> str:
        return self.values[key]

    def leaks(self, text: str | bytes) -> bool:
        if isinstance(text, bytes):
            text = text.decode("utf-8", "replace")
        return any(core[i : i + 8] in text for core in self.cores for i in range(len(core) - 7))


@pytest.fixture
def fake_secrets() -> FakeSecrets:
    return FakeSecrets()
