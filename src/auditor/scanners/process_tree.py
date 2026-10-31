"""Terminate a tool *and everything it spawned*.

Killing only the direct child is not enough: wrappers such as Semgrep's Python launcher start
native helpers (``semgrep-core``) that would survive as orphans. Shown by tests: without this,
a grandchild kept running after both a timeout and a normal exit.

- Windows: the child is assigned to a Job Object with ``KILL_ON_JOB_CLOSE``; terminating or
  closing the job ends the whole tree. If a job cannot be created, ``taskkill /T /F`` (absolute
  System32 path) is the fallback for timeouts.
- POSIX: the child starts its own session; the process group is killed.

Residual risk: a descendant spawned in the few milliseconds between process creation and job
assignment is not in the job (Popen offers no suspended start). Tools used here start their
helpers much later than that.
"""

import os
import signal
import subprocess
import sys
from typing import Any


class ProcessTree:
    def __init__(self) -> None:
        self._job: Any = None
        self._process: subprocess.Popen | None = None

    @staticmethod
    def popen_kwargs() -> dict[str, Any]:
        return {} if sys.platform == "win32" else {"start_new_session": True}

    def attach(self, process: subprocess.Popen) -> None:
        self._process = process
        if sys.platform == "win32":
            self._job = _create_kill_on_close_job()
            if self._job is not None and not _assign(self._job, process):
                _close(self._job)
                self._job = None

    def kill(self) -> None:
        """Kill the whole tree now (timeout)."""
        if self._process is None:
            return
        if sys.platform == "win32":
            if self._job is not None:
                _terminate(self._job)
            else:
                taskkill = os.path.join(
                    os.environ.get("SYSTEMROOT", r"C:\Windows"), "System32", "taskkill.exe"
                )
                subprocess.run(  # noqa: S603 - fixed argv, absolute system path
                    [taskkill, "/T", "/F", "/PID", str(self._process.pid)],
                    shell=False,
                    capture_output=True,
                    check=False,
                )
        else:
            self._kill_group()
        try:
            self._process.kill()
        except OSError:
            pass

    def close(self) -> None:
        """After the tool finished: make sure no descendant keeps running."""
        if sys.platform == "win32":
            if self._job is not None:
                _close(self._job)  # KILL_ON_JOB_CLOSE ends leftover descendants
                self._job = None
        elif self._process is not None:
            self._kill_group()

    def _kill_group(self) -> None:
        try:
            os.killpg(self._process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            pass


# ------------------------------------------------------------------- Windows Job Object

if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS = 9
    _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000

    class _BasicLimit(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_int64),
            ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class _IoCounters(ctypes.Structure):
        _fields_ = [
            (name, ctypes.c_uint64)
            for name in (
                "ReadOperationCount",
                "WriteOperationCount",
                "OtherOperationCount",
                "ReadTransferCount",
                "WriteTransferCount",
                "OtherTransferCount",
            )
        ]

    class _ExtendedLimit(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _BasicLimit),
            ("IoInfo", _IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    _kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    _kernel32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
    _kernel32.SetInformationJobObject.restype = wintypes.BOOL
    _kernel32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    _kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    _kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    _kernel32.TerminateJobObject.restype = wintypes.BOOL
    _kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    _kernel32.CloseHandle.restype = wintypes.BOOL
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

    def _create_kill_on_close_job() -> Any:
        job = _kernel32.CreateJobObjectW(None, None)
        if not job:
            return None
        info = _ExtendedLimit()
        info.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        ok = _kernel32.SetInformationJobObject(
            job,
            _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
            ctypes.byref(info),
            ctypes.sizeof(info),
        )
        if not ok:
            _kernel32.CloseHandle(job)
            return None
        return job

    def _assign(job: Any, process: subprocess.Popen) -> bool:
        return bool(_kernel32.AssignProcessToJobObject(job, int(process._handle)))

    def _terminate(job: Any) -> None:
        _kernel32.TerminateJobObject(job, 1)

    def _close(job: Any) -> None:
        _kernel32.CloseHandle(job)

else:  # pragma: no cover - POSIX uses process groups instead

    def _create_kill_on_close_job() -> Any:
        return None

    def _assign(job: Any, process: subprocess.Popen) -> bool:
        return False

    def _terminate(job: Any) -> None:
        return None

    def _close(job: Any) -> None:
        return None
