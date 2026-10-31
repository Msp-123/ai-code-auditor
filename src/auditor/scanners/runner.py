"""Safe execution of trusted scanner executables.

- ``shell=False`` with an argument list; the executable must be an absolute path.
- stdin is closed, stdout discarded (scanners write results to a file we choose), stderr is
  captured to a file inside the private workspace and read back with a size cap.
- The environment is reduced to what a native tool needs on this OS: no API keys, no
  ``RUFF_*``/``SEMGREP_*`` configuration variables, TEMP pointing at our private workspace.
  Adapters may add explicit tool-specific values (``extra``).
- A timeout kills the whole process tree; descendants left behind after a normal exit are
  killed too (``process_tree``).
"""

import os
import subprocess
import threading
import time
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from auditor.scanners.process_tree import ProcessTree

DEFAULT_STDERR_LIMIT = 64 * 1024
_TRUNCATED = "\n[stderr truncated]"
# Variables some native tools need to start on Windows; everything else is dropped.
_PASSTHROUGH = ("SYSTEMROOT", "WINDIR", "SYSTEMDRIVE", "PATHEXT", "LANG", "LC_ALL")


@dataclass(frozen=True)
class ProcessResult:
    exit_code: int | None
    timed_out: bool
    duration_seconds: float
    stderr: str
    launch_error: str | None = None
    stdout: str = ""


def minimal_env(
    temp_dir: Path,
    source: Mapping[str, str] | None = None,
    extra: Mapping[str, str] | None = None,
) -> dict[str, str]:
    source = os.environ if source is None else source
    upper = {key.upper(): value for key, value in source.items()}
    env = {key: upper[key] for key in _PASSTHROUGH if key in upper}
    env.update({"TEMP": str(temp_dir), "TMP": str(temp_dir), "TMPDIR": str(temp_dir)})
    env["NO_COLOR"] = "1"
    env.update(extra or {})
    return env


def run_tool(
    argv: Sequence[str],
    *,
    cwd: Path,
    timeout: float,
    env: Mapping[str, str],
    stderr_limit: int = DEFAULT_STDERR_LIMIT,
    stdout_limit: int = 0,
) -> ProcessResult:
    """Run a trusted tool. ``stdout_limit=0`` discards stdout; otherwise it is captured, capped."""
    if not argv or not os.path.isabs(argv[0]):
        raise ValueError("the executable must be given as an absolute path")
    token = uuid.uuid4().hex
    stderr_path = cwd / f"stderr-{token}.log"
    stdout_path = cwd / f"stdout-{token}.log"
    started = time.monotonic()
    exit_code: int | None = None
    timed_out = False
    launch_error: str | None = None
    try:
        with (
            open(stderr_path, "x+b") as stderr_file,
            open(stdout_path, "x+b") if stdout_limit else open(os.devnull, "wb") as stdout_file,
        ):
            tree = ProcessTree()
            try:
                process = subprocess.Popen(  # noqa: S603 - fixed argv, shell=False, trusted exe
                    list(argv),
                    shell=False,
                    cwd=cwd,
                    env=dict(env),
                    stdin=subprocess.DEVNULL,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    **ProcessTree.popen_kwargs(),
                )
            except OSError as exc:
                launch_error = f"{type(exc).__name__}: {exc.strerror or exc}"
            else:
                tree.attach(process)
                try:
                    exit_code = process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    tree.kill()
                    process.wait()
                finally:
                    tree.close()
            stderr = _read_capped(stderr_file, stderr_limit, _TRUNCATED)
            stdout = _read_capped(stdout_file, stdout_limit, "") if stdout_limit else ""
    finally:
        for path in (stderr_path, stdout_path):
            try:
                os.remove(path)
            except OSError:
                pass
    duration = time.monotonic() - started
    return ProcessResult(exit_code, timed_out, duration, stderr, launch_error, stdout)


@dataclass(frozen=True)
class PipeResult:
    """Result of ``run_tool_stdin``. The tool's stderr is deliberately not kept: only its size."""

    exit_code: int | None
    timed_out: bool
    duration_seconds: float
    stdout: bytes
    stdout_truncated: bool
    stderr_bytes: int
    input_complete: bool  # every input byte was accepted by the tool's stdin
    launch_error: str | None = None


def run_tool_stdin(
    argv: Sequence[str],
    *,
    data: bytes,
    cwd: Path,
    timeout: float,
    env: Mapping[str, str],
    stdout_limit: int,
) -> PipeResult:
    """Run a trusted tool on ``data`` via stdin; stdout is collected in memory only.

    Nothing touches the disk: input, output and stderr go through pipes. Used for tools whose
    input or output may contain secrets (Gitleaks, D-043). stderr is drained and counted but
    its content is discarded, because a tool's logs may echo what it read.
    """
    if not argv or not os.path.isabs(argv[0]):
        raise ValueError("the executable must be given as an absolute path")
    started = time.monotonic()
    tree = ProcessTree()
    try:
        process = subprocess.Popen(  # noqa: S603 - fixed argv, shell=False, trusted exe
            list(argv),
            shell=False,
            cwd=cwd,
            env=dict(env),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            **ProcessTree.popen_kwargs(),
        )
    except OSError as exc:
        return PipeResult(
            None, False, 0.0, b"", False, 0, False, f"{type(exc).__name__}: {exc.strerror or exc}"
        )
    tree.attach(process)
    state = {"input_complete": False, "stdout": bytearray(), "truncated": False, "stderr": 0}

    def feed() -> None:
        try:
            process.stdin.write(data)
            process.stdin.close()
            state["input_complete"] = True
        except (BrokenPipeError, OSError, ValueError):
            pass

    def collect() -> None:
        while chunk := process.stdout.read(64 * 1024):
            room = stdout_limit - len(state["stdout"])
            if len(chunk) > room:
                state["truncated"] = True
            state["stdout"].extend(chunk[: max(room, 0)])  # keep draining: no deadlock

    def count_stderr() -> None:
        while chunk := process.stderr.read(64 * 1024):
            state["stderr"] += len(chunk)

    threads = [threading.Thread(target=t, daemon=True) for t in (feed, collect, count_stderr)]
    for thread in threads:
        thread.start()
    timed_out = False
    try:
        exit_code: int | None = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        tree.kill()
        exit_code = process.wait()
    finally:
        tree.close()
    for thread in threads:
        thread.join(timeout=5)
    for stream in (process.stdin, process.stdout, process.stderr):
        try:
            stream.close()
        except (OSError, ValueError):
            pass
    return PipeResult(
        exit_code=None if timed_out else exit_code,
        timed_out=timed_out,
        duration_seconds=time.monotonic() - started,
        stdout=bytes(state["stdout"]),
        stdout_truncated=state["truncated"],
        stderr_bytes=state["stderr"],
        input_complete=state["input_complete"],
    )


def _read_capped(handle, limit: int, marker: str) -> str:
    handle.seek(0)
    raw = handle.read(limit + 1)
    text = raw[:limit].decode("utf-8", "replace")
    return text + marker if len(raw) > limit else text
