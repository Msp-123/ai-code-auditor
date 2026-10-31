"""Which inventory files a scanner analyses, and the last-moment TOCTOU checks."""

import os
import stat
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from auditor.core.models import FileEntry, NotAnalyzedReason
from auditor.core.policy import normalize_name
from auditor.core.safe_fs import is_link_like
from auditor.discovery.repository import extended_length_path

_READ_FLAGS = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)


@dataclass(frozen=True)
class ReadResult:
    data: bytes | None
    reason: NotAnalyzedReason | None = None
    detail: str | None = None


def _read_all(descriptor: int, size: int) -> bytes:
    chunks, remaining = [], size + 1  # one extra byte reveals growth
    while remaining > 0 and (chunk := os.read(descriptor, min(remaining, 1 << 20))):
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_regular_file(path: str, limit: int) -> ReadResult:
    """Read a whole regular file without following links, or explain why not.

    Identity (lstat before opening == fstat after opening), size and mtime are checked again
    after reading, so a file swapped for a link or changed while being read is refused rather
    than scanned half-way. The bytes stay in memory; nothing is written anywhere.
    """
    full = extended_length_path(path)
    try:
        before = os.lstat(full)
    except OSError:
        return ReadResult(None, NotAnalyzedReason.IO_ERROR, "could not be opened")
    if is_link_like(before) or not stat.S_ISREG(before.st_mode):
        return ReadResult(None, NotAnalyzedReason.CHANGED_BEFORE_SCAN, "not a regular file")
    if before.st_size > limit:
        return ReadResult(None, NotAnalyzedReason.SIZE_LIMIT, f"larger than {limit} bytes")
    try:
        descriptor = os.open(full, _READ_FLAGS)
    except OSError:
        return ReadResult(None, NotAnalyzedReason.IO_ERROR, "could not be opened")
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            return ReadResult(None, NotAnalyzedReason.CHANGED_BEFORE_SCAN, "replaced")
        data = _read_all(descriptor, opened.st_size)
        after = os.fstat(descriptor)
    except OSError:
        return ReadResult(None, NotAnalyzedReason.IO_ERROR, "read failed")
    finally:
        os.close(descriptor)
    unchanged = (after.st_size, after.st_mtime_ns) == (opened.st_size, opened.st_mtime_ns)
    if not unchanged or len(data) != opened.st_size:
        return ReadResult(None, NotAnalyzedReason.CHANGED_BEFORE_SCAN, "changed while reading")
    return ReadResult(data)


PYTHON_SUFFIXES = (".py", ".pyi")


def select_python_files(files: Sequence[FileEntry]) -> list[FileEntry]:
    """Every .py/.pyi file in the inventory, whatever its category (setup.py, tests…)."""
    return [f for f in files if normalize_name(f.relative_path).endswith(PYTHON_SUFFIXES)]


def precheck_files(
    root: Path, candidates: Sequence[FileEntry]
) -> tuple[list[tuple[FileEntry, str]], list[FileEntry]]:
    """Split candidates into (still a regular, non-link file -> absolute path) and changed.

    Python needs the \\\\?\\ form beyond MAX_PATH for ``lstat``; the plain path is returned.
    """
    passed: list[tuple[FileEntry, str]] = []
    changed: list[FileEntry] = []
    for entry in candidates:
        path = os.path.join(os.fspath(root), *entry.relative_path.split("/"))
        try:
            st = os.lstat(extended_length_path(path))
            regular = not is_link_like(st) and stat.S_ISREG(st.st_mode)
        except OSError:
            regular = False
        if regular:
            passed.append((entry, path))
        else:
            changed.append(entry)
    return passed, changed
