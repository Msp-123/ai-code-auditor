"""Creating the auditor's own directories without ever touching the scan target.

A ``resolve()`` check before creating directories cannot close a check-then-create race (a
path component may be swapped for a link/junction in between). Therefore the deepest
*existing* ancestor is checked first, and every directory created here is verified *after*
creation and removed again if it resolves inside the target or is a link.
"""

import os
import stat
from pathlib import Path

from auditor.core.errors import TargetErrorCode, TargetPathError
from auditor.discovery.repository import is_within

PRIVATE_DIR_MODE = 0o700
PRIVATE_FILE_MODE = 0o600


def inside_target_error() -> TargetPathError:
    return TargetPathError(
        TargetErrorCode.OUTPUT_INSIDE_TARGET,
        "Output location resolves inside the scan target (it may have changed during the "
        "run); nothing was written there.",
    )


def is_link_like(st: os.stat_result) -> bool:
    attributes = getattr(st, "st_file_attributes", 0)
    return stat.S_ISLNK(st.st_mode) or bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def identity(path: Path) -> tuple[int, int]:
    st = os.lstat(path)
    return (st.st_dev, st.st_ino)


def verify_own_directory(path: Path, expected: tuple[int, int], root: Path) -> None:
    """The directory is still the one we created, is not a link and is outside the target."""
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise inside_target_error() from exc
    if is_link_like(st) or (st.st_dev, st.st_ino) != expected or is_within(path.resolve(), root):
        raise inside_target_error()


def _check_ancestor(existing: Path, root: Path) -> None:
    if is_within(existing.resolve(), root):
        raise inside_target_error()
    if os.name != "nt":
        st = os.stat(existing)
        if st.st_mode & stat.S_IWOTH and not st.st_mode & stat.S_ISVTX:
            raise TargetPathError(
                TargetErrorCode.UNSAFE_OUTPUT_DIR,
                "Output directory's parent is writable by any user (no sticky bit); "
                "choose a private --output-dir.",
            )


def ensure_directory(path: Path, root: Path) -> None:
    """Create ``path`` and missing parents without ever leaving anything inside ``root``."""
    missing: list[Path] = []
    current = path
    while not os.path.lexists(current):
        missing.append(current)
        if current.parent == current:
            break
        current = current.parent
    _check_ancestor(current, root)
    for directory in reversed(missing):
        os.mkdir(directory, PRIVATE_DIR_MODE)
        try:
            st = os.lstat(directory)
            safe = not is_link_like(st) and not is_within(directory.resolve(), root)
        except OSError:
            safe = False
        if not safe:
            # We just created it and it is empty: remove it again, then refuse.
            try:
                os.rmdir(directory)
            except OSError:
                pass
            raise inside_target_error()


def create_private_file(path: Path, content: str) -> None:
    """Create a new file (never overwrite, never follow a link) and flush it to disk."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, PRIVATE_FILE_MODE)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
