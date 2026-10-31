"""Safe subprocess runner, exercised with a fake tool (our own test script, never the target)."""

import json
import os
import sys
import textwrap
import time

import pytest

from auditor.scanners.runner import minimal_env, run_tool

FAKE_TOOL = textwrap.dedent(
    """
    import json, os, sys, time
    mode, arg = sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else ""
    if mode == "exit":
        sys.exit(int(arg))
    if mode == "sleep":
        time.sleep(float(arg))
    if mode == "stderr":
        sys.stderr.write("E" * int(arg))
    if mode == "record":
        with open(arg, "w", encoding="utf-8") as fh:
            json.dump({"argv": sys.argv, "env": dict(os.environ),
                       "stdin": sys.stdin.read()}, fh)
    if mode == "crash":
        raise RuntimeError("boom")
    if mode == "spawn":
        import subprocess
        beat = (
            "import sys, time\\nwhile True:\\n"
            "    open(sys.argv[1], 'w').write(str(time.time()))\\n    time.sleep(0.1)"
        )
        subprocess.Popen([sys.executable, "-c", beat, arg])
        time.sleep(0.5)
        if sys.argv[3] == "sleep":
            time.sleep(60)
    """
)


def _heartbeat_stopped(path, wait=1.5):
    """True if the grandchild stopped writing its heartbeat file."""
    if not path.exists():
        return True
    time.sleep(wait)
    first = path.stat().st_mtime_ns
    time.sleep(wait)
    return path.stat().st_mtime_ns == first


@pytest.fixture
def fake_tool(tmp_path):
    script = tmp_path / "fake_tool.py"
    script.write_text(FAKE_TOOL, encoding="utf-8")
    return [sys.executable, str(script)]


@pytest.fixture
def work(tmp_path):
    path = tmp_path / "work"
    path.mkdir()
    return path


def run(fake_tool, work, *args, timeout=30.0, env=None):
    return run_tool([*fake_tool, *args], cwd=work, timeout=timeout, env=env or minimal_env(work))


@pytest.mark.parametrize("code", [0, 1, 2, 7])
def test_exit_codes_are_reported(fake_tool, work, code):
    result = run(fake_tool, work, "exit", str(code))

    assert result.exit_code == code
    assert not result.timed_out
    assert result.launch_error is None


def test_timeout_kills_the_process(fake_tool, work):
    started = time.monotonic()

    result = run(fake_tool, work, "sleep", "30", timeout=1.0)

    assert result.timed_out
    assert result.exit_code is None
    assert time.monotonic() - started < 15


def test_stderr_is_capped(fake_tool, work):
    result = run_tool(
        [*fake_tool, "stderr", "500000"],
        cwd=work,
        timeout=30,
        env=minimal_env(work),
        stderr_limit=1000,
    )

    assert len(result.stderr) <= 1000 + len("\n[stderr truncated]")
    assert result.stderr.endswith("[stderr truncated]")


def test_crash_is_a_nonzero_exit_not_an_exception(fake_tool, work):
    result = run(fake_tool, work, "crash")

    assert result.exit_code not in (0, None)
    assert "RuntimeError" in result.stderr


def test_missing_executable_is_a_launch_error(work):
    missing = os.path.join(os.fspath(work), "does-not-exist.exe")

    result = run_tool([missing], cwd=work, timeout=5, env=minimal_env(work))

    assert result.launch_error is not None
    assert result.exit_code is None


def test_relative_executable_is_rejected(work):
    with pytest.raises(ValueError, match="absolute"):
        run_tool(["ruff", "check"], cwd=work, timeout=5, env=minimal_env(work))


def test_arguments_are_not_interpreted_by_a_shell(fake_tool, work):
    record = work / "record.json"
    marker = work / "pwned.txt"
    hostile = f"x & echo pwned > {marker} ; $(touch {marker}) | `whoami`"

    result = run(fake_tool, work, "record", str(record), hostile)

    assert result.exit_code == 0
    assert json.loads(record.read_text(encoding="utf-8"))["argv"][-1] == hostile
    assert not marker.exists()


def test_child_gets_minimal_environment_and_no_stdin(fake_tool, work, monkeypatch):
    monkeypatch.setenv("AUDITOR_TEST_API_KEY", "FAKE-should-not-leak")
    monkeypatch.setenv("RUFF_CACHE_DIR", str(work / "evil-cache"))
    record = work / "record.json"

    run(fake_tool, work, "record", str(record), env=minimal_env(work))
    seen = json.loads(record.read_text(encoding="utf-8"))

    assert "AUDITOR_TEST_API_KEY" not in seen["env"]
    assert not any(key.upper().startswith("RUFF_") for key in seen["env"])
    assert seen["env"]["TEMP"] == str(work)
    assert seen["stdin"] == ""


def test_timeout_kills_the_whole_process_tree(fake_tool, work, tmp_path):
    beat = tmp_path / "grandchild.beat"

    result = run(fake_tool, work, "spawn", str(beat), "sleep", timeout=3.0)

    assert result.timed_out
    assert beat.exists(), "grandchild never started; test is not meaningful"
    assert _heartbeat_stopped(beat), "grandchild survived the timeout"


def test_grandchildren_left_behind_after_normal_exit_are_killed(fake_tool, work, tmp_path):
    beat = tmp_path / "orphan.beat"

    result = run(fake_tool, work, "spawn", str(beat), "exit")

    assert result.exit_code == 0
    assert beat.exists()
    assert _heartbeat_stopped(beat), "orphaned grandchild kept running"


def test_tool_specific_environment_is_added(fake_tool, work):
    record = work / "record.json"
    env = minimal_env(work, extra={"HOME": str(work / "home"), "SEMGREP_SEND_METRICS": "off"})

    run(fake_tool, work, "record", str(record), env=env)
    seen = json.loads(record.read_text(encoding="utf-8"))["env"]

    assert seen["HOME"] == str(work / "home")
    assert seen["SEMGREP_SEND_METRICS"] == "off"


def test_stderr_file_does_not_linger_in_workspace(fake_tool, work):
    run(fake_tool, work, "stderr", "10")

    assert list(work.iterdir()) == []
