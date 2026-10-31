"""Private scratch space for raw scanner output and temporary source copies.

What is in here may contain code-derived text, so it never goes into reports and never
outlives a run: the workspace is removed on exit (also on errors). Leftovers of earlier runs
that were killed before cleanup are only *detected* and reported, never deleted automatically
(user decision, D-042); ``remove_owned_workspace`` is kept for a future, user-approved manual
cleanup.

Deletion is deliberately strict:

- only directories this account owns (``ownership.owned_by_current_user``), and for the
  current run only the very directory created (same identity, not a link);
- Windows extended-length paths, so files beyond MAX_PATH (260) are removed as well;
- links and junctions are removed themselves and never entered;
- a failure is never swallowed: it is recorded as a ``CleanupFailure`` that the audit
  reports as ``CLEANUP_FAILED`` (D-042).
"""

import os
import stat
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType

from auditor.core.config import default_temp_base
from auditor.core.errors import TargetErrorCode, TargetPathError
from auditor.core.ownership import owned_by_current_user
from auditor.core.safe_fs import ensure_directory, identity, is_link_like, verify_own_directory
from auditor.discovery.repository import extended_length_path

_PREFIX = "run-"
# Longer than the longest possible run (scanner timeouts add up to well under an hour), so a
# workspace of a concurrent run is never reported as a leftover.
STALE_AFTER_SECONDS = 2 * 3600


@dataclass(frozen=True)
class CleanupFailure:
    component: str  # who owned the workspace, e.g. "semgrep"
    contents: str  # what may be left behind, e.g. "copies of scanned source files"
    workspace: str  # the directory's *name* only: full paths never reach a report
    reason: str  # short, path-free


@dataclass(frozen=True)
class StaleWorkspaces:
    """Leftovers of earlier runs found (not deleted) when a workspace was opened."""

    component: str
    contents: str
    pattern: str  # e.g. "r-*": names only, never paths
    count: int


class _Unsafe(Exception):
    """The tree changed under us or is not ours: stop deleting."""


def _remove_link(path: str, st: os.stat_result) -> None:
    # A directory symlink or junction is removed with rmdir (only the link goes away).
    if getattr(st, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_DIRECTORY:
        os.rmdir(path)
    else:
        os.unlink(path)


def remove_tree(top: str, expected: tuple[int, int]) -> None:
    """Delete the directory ``top`` bottom-up without ever following a link.

    Every directory is re-identified after it has been listed: if it was swapped for a link
    or another directory in between, nothing below it is touched (``_Unsafe``).
    """
    order: list[str] = []
    pending = [(top, expected)]
    while pending:
        directory, ident = pending.pop()
        with os.scandir(directory) as it:
            entries = list(it)
        st = os.lstat(directory)
        if is_link_like(st) or (st.st_dev, st.st_ino) != ident:
            raise _Unsafe("directory changed during cleanup")
        order.append(directory)
        for entry in entries:
            est = os.lstat(entry.path)
            if is_link_like(est):
                _remove_link(entry.path, est)
            elif stat.S_ISDIR(est.st_mode):
                pending.append((entry.path, (est.st_dev, est.st_ino)))
            else:
                os.unlink(entry.path)
    for directory in reversed(order):
        os.rmdir(directory)


def remove_owned_workspace(path: Path, expected: tuple[int, int] | None = None) -> str | None:
    """Remove a workspace if it is verifiably ours. Returns a path-free failure reason."""
    full = extended_length_path(str(path))
    try:
        st = os.lstat(full)
    except FileNotFoundError:
        return None
    except OSError as exc:
        return f"workspace not accessible ({type(exc).__name__})"
    ident = (st.st_dev, st.st_ino)
    if is_link_like(st) or not stat.S_ISDIR(st.st_mode):
        return "workspace was replaced by a link or file; it was not deleted"
    if expected is not None and ident != expected:
        return "workspace was replaced by another directory; it was not deleted"
    if not owned_by_current_user(full):
        return "workspace is not owned by the current user; it was not deleted"
    try:
        remove_tree(full, ident)
    except _Unsafe as exc:
        return f"{exc}; deletion stopped"
    except OSError as exc:
        return f"some files could not be deleted ({type(exc).__name__})"
    return "workspace still exists after deletion" if os.path.lexists(full) else None


class PrivateWorkspace:
    def __init__(
        self,
        root: Path,
        base: Path | None = None,
        prefix: str = _PREFIX,
        *,
        component: str = "scanner-output",
        contents: str = "raw scanner output (may contain source excerpts)",
        failures: list[CleanupFailure] | None = None,
        stale: list[StaleWorkspaces] | None = None,
    ) -> None:
        self.root = root
        self.base = base if base is not None else default_temp_base()
        self.prefix = prefix
        self.component = component
        self.contents = contents
        self.failures = failures if failures is not None else []
        self.stale = stale if stale is not None else []
        self.path: Path | None = None
        self._identity: tuple[int, int] | None = None
        self.cleanup_failed = False

    def __enter__(self) -> Path:
        ensure_directory(self.base, self.root)
        self._verify_base()
        self._detect_stale()
        self.path = Path(tempfile.mkdtemp(prefix=self.prefix, dir=self.base)).resolve()
        self._identity = identity(self.path)
        verify_own_directory(self.path, self._identity, self.root)
        return self.path

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self.path is not None:
            reason = remove_owned_workspace(self.path, self._identity)
            if reason is not None:
                self._record(self.path.name, reason)

    def _verify_base(self) -> None:
        full = extended_length_path(str(self.base))
        if is_link_like(os.lstat(full)) or not owned_by_current_user(full):
            raise TargetPathError(
                TargetErrorCode.UNSAFE_OUTPUT_DIR,
                "Temporary directory is a link or is not owned by the current user; refused.",
            )

    def _record(self, name: str, reason: str) -> None:
        self.cleanup_failed = True
        self.failures.append(CleanupFailure(self.component, self.contents, name, reason))

    def _detect_stale(self) -> None:
        """Count verified leftovers of earlier runs. Read-only: nothing is deleted."""
        cutoff = time.time() - STALE_AFTER_SECONDS
        with os.scandir(extended_length_path(str(self.base))) as it:
            entries = list(it)
        count = 0
        for entry in entries:
            if not entry.name.startswith(self.prefix):
                continue
            try:
                st = os.lstat(entry.path)
            except OSError:
                continue
            if is_link_like(st) or not stat.S_ISDIR(st.st_mode) or st.st_mtime >= cutoff:
                continue
            if owned_by_current_user(entry.path):  # someone else's folder is not our leftover
                count += 1
        if count:
            self.stale.append(
                StaleWorkspaces(self.component, self.contents, f"{self.prefix}*", count)
            )
