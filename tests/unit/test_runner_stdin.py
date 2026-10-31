"""run_tool_stdin: data in through a pipe, report out through a pipe, nothing on disk."""

import os
import sys
import textwrap
import time

import pytest

from auditor.scanners.runner import minimal_env, run_tool_stdin

FAKE = textwrap.dedent(
    """
    import os, sys, time
    mode, arg = sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else ""
    if mode == "echo":                      # stdout = stdin
        sys.stdout.buffer.write(sys.stdin.buffer.read())
    if mode == "count":                     # stdout = number of stdin bytes
        print(len(sys.stdin.buffer.read()))
    if mode == "stderr":
        sys.stdin.buffer.read()
        sys.stderr.write(arg * 1000)
    if mode == "flood":                     # more stdout than allowed
        sys.stdin.buffer.read()
        sys.stdout.write("x" * int(arg))
    if mode == "noread":                    # exits without consuming stdin
        sys.exit(0)
    if mode == "sleep":
        time.sleep(float(arg))
    if mode == "exit":
        sys.stdin.buffer.read()
        sys.exit(int(arg))
    if mode == "files":                     # what is in the working directory afterwards?
        sys.stdin.buffer.read()
        print(sorted(os.listdir(".")))
    """
)


@pytest.fixture
def fake(tmp_path):
    script = tmp_path / "fake_stdin_tool.py"
    script.write_text(FAKE, encoding="utf-8")
    return [sys.executable, str(script)]


@pytest.fixture
def work(tmp_path):
    path = tmp_path / "work"
    path.mkdir()
    return path


def run(fake, work, *args, data=b"", **kw):
    kw.setdefault("timeout", 30)
    kw.setdefault("stdout_limit", 1024 * 1024)
    return run_tool_stdin([*fake, *args], data=data, cwd=work, env=minimal_env(work), **kw)


def test_data_goes_in_and_stdout_comes_back_in_memory(fake, work):
    payload = os.urandom(3 * 1024 * 1024)  # larger than any pipe buffer

    result = run(fake, work, "count", data=payload)

    assert result.exit_code == 0 and not result.timed_out
    assert result.input_complete
    assert result.stdout.strip() == str(len(payload)).encode()
    assert not result.stdout_truncated


def test_nothing_is_written_to_the_working_directory(fake, work):
    result = run(fake, work, "files", data=b"SECRET_LIKE_CONTENT")

    assert result.stdout.strip() == b"[]"
    assert list(work.iterdir()) == []


def test_stderr_content_is_never_returned_only_its_size(fake, work):
    result = run(fake, work, "stderr", "Q", data=b"x")

    assert result.stderr_bytes == 1000
    assert not hasattr(result, "stderr")


def test_stdout_over_the_limit_is_truncated_and_flagged(fake, work):
    result = run(fake, work, "flood", str(200_000), data=b"x", stdout_limit=1000)

    assert result.stdout_truncated
    assert len(result.stdout) == 1000
    assert result.exit_code == 0  # the tool still finished: the reader kept draining


def test_unconsumed_input_is_detected(fake, work):
    result = run(fake, work, "noread", data=os.urandom(4 * 1024 * 1024))

    assert result.exit_code == 0
    assert not result.input_complete  # exit 0 alone is not proof that the data was read


def test_timeout_kills_the_process(fake, work):
    started = time.monotonic()
    result = run(fake, work, "sleep", "30", timeout=1)

    assert result.timed_out
    assert time.monotonic() - started < 15


def test_nonzero_exit_is_reported(fake, work):
    assert run(fake, work, "exit", "3", data=b"x").exit_code == 3


def test_missing_executable_is_a_launch_error(work):
    missing = os.path.join(str(work), "nope.exe")
    result = run_tool_stdin(
        [missing], data=b"", cwd=work, env=minimal_env(work), timeout=5, stdout_limit=10
    )

    assert result.launch_error is not None and result.exit_code is None


def test_relative_executable_is_rejected(work):
    with pytest.raises(ValueError):
        run_tool_stdin(["gitleaks"], data=b"", cwd=work, env={}, timeout=5, stdout_limit=10)
