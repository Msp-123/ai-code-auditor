"""Safe, read-only repository discovery.

Guarantees, enforced in code and covered by tests:

- Only directory listings and ``lstat``-style metadata are used. File contents are never
  opened, so nothing in the target (code, README, comments) can influence the scan.
- Links are never followed: symlinks, Windows junctions and any other reparse points are
  detected from metadata that does not traverse them, and reported as excluded.
- ``Path.resolve()`` is used only on the user-chosen root and on our own output location,
  never on entries inside the target, because resolving follows links.
- A directory is re-identified by ``(st_dev, st_ino)`` before and after it is listed, so a
  directory swapped for a link during the scan is detected and reported, not followed.
- Nothing is written to the target.
"""

import os
import stat
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from auditor.core.errors import TargetErrorCode, TargetPathError
from auditor.core.models import (
    EntryKind,
    ExcludedEntry,
    ExclusionReason,
    FileEntry,
    IncompleteReason,
)
from auditor.core.policy import ScanPolicy, normalize_name
from auditor.discovery.classify import classify_file

_IS_WINDOWS = os.name == "nt"
# Characters that can never be part of a single path component returned by scandir.
_FORBIDDEN_NAME_CHARS = ("/", "\\", "\x00") if _IS_WINDOWS else ("/", "\x00")
_WINDOWS_LINK_PREFIXES = ("\\\\?\\UNC\\", "\\\\?\\", "\\??\\")


def extended_length_path(path: str) -> str:
    """On Windows, use the ``\\\\?\\`` form so paths beyond MAX_PATH (260) can be listed."""
    if not _IS_WINDOWS or path.startswith("\\\\?\\"):
        return path
    if path.startswith("\\\\"):
        return "\\\\?\\UNC\\" + path[2:]
    return "\\\\?\\" + path


def plain_path(path: str) -> str:
    """Strip Windows extended-length / NT prefixes for comparisons."""
    for prefix in _WINDOWS_LINK_PREFIXES:
        if path.startswith(prefix):
            return ("\\\\" if prefix.endswith("UNC\\") else "") + path[len(prefix) :]
    return path


# --------------------------------------------------------------------------- validation


def validate_target(target: str | os.PathLike[str]) -> Path:
    """Validate the user-chosen scan root and return its resolved, absolute path."""
    raw = os.fspath(target)
    if not raw or "\x00" in raw:
        raise TargetPathError(TargetErrorCode.INVALID_PATH, "Target path is empty or invalid.")
    path = Path(raw)
    try:
        # The root itself is chosen by the user, so following a link here is intended.
        st = os.stat(path)
    except FileNotFoundError as exc:
        raise TargetPathError(
            TargetErrorCode.NOT_FOUND, f"Target path does not exist: {raw}"
        ) from exc
    except PermissionError as exc:
        raise TargetPathError(
            TargetErrorCode.PERMISSION_DENIED, f"Permission denied: {raw}"
        ) from exc
    except (OSError, ValueError) as exc:
        raise TargetPathError(
            TargetErrorCode.INVALID_PATH, f"Target path is invalid: {raw}"
        ) from exc
    if not stat.S_ISDIR(st.st_mode):
        raise TargetPathError(
            TargetErrorCode.NOT_A_DIRECTORY, f"Target path is not a directory: {raw}"
        )
    try:
        root = path.resolve(strict=True)
        with os.scandir(root):
            pass
    except PermissionError as exc:
        raise TargetPathError(
            TargetErrorCode.PERMISSION_DENIED, f"Permission denied: {raw}"
        ) from exc
    except OSError as exc:
        raise TargetPathError(
            TargetErrorCode.INVALID_PATH, f"Target path is not readable: {raw}"
        ) from exc
    return root


def is_within(path: Path, root: Path) -> bool:
    """True if ``path`` equals ``root`` or lies below it (both must be resolved)."""
    return path == root or root in path.parents


def validate_output_dir(output_dir: str | os.PathLike[str], root: Path) -> Path:
    """Resolve the report output directory and refuse any location inside the target."""
    try:
        resolved = Path(output_dir).resolve()
    except (OSError, ValueError, RuntimeError) as exc:
        raise TargetPathError(
            TargetErrorCode.INVALID_PATH, f"Output directory is invalid: {output_dir}"
        ) from exc
    if is_within(resolved, root):
        raise TargetPathError(
            TargetErrorCode.OUTPUT_INSIDE_TARGET,
            "Output directory is inside the scan target; reports are never written into "
            "the target. Choose another --output-dir.",
        )
    return resolved


def target_is_link(target: str | os.PathLike[str]) -> bool:
    """Whether the user-given root path is itself a symlink or junction."""
    path = os.fspath(target)
    return os.path.islink(path) or bool(getattr(os.path, "isjunction", lambda _p: False)(path))


# ------------------------------------------------------------------------------ discovery


@dataclass
class DiscoveryResult:
    files: list[FileEntry] = field(default_factory=list)
    excluded: list[ExcludedEntry] = field(default_factory=list)
    incomplete_reasons: list[IncompleteReason] = field(default_factory=list)
    vcs_metadata: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    entries_visited: int = 0
    unvisited_directories: int = 0

    def mark_incomplete(self, reason: IncompleteReason) -> None:
        if reason not in self.incomplete_reasons:
            self.incomplete_reasons.append(reason)


@dataclass(frozen=True)
class _PendingDir:
    path: str
    parts: tuple[str, ...]
    identity: tuple[int, int]
    depth: int


class _StopScan(Exception):
    """A global limit was reached; stop walking."""


def inspect(
    root: Path, policy: ScanPolicy, *, clock: Callable[[], float] = time.monotonic
) -> DiscoveryResult:
    """Build a metadata-only inventory of ``root`` (which must come from validate_target)."""
    return _Walker(root, policy, clock).run()


def _identity(st: os.stat_result) -> tuple[int, int]:
    return (st.st_dev, st.st_ino)


def _is_reparse_point(st: os.stat_result) -> bool:
    return bool(getattr(st, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def _link_reason(entry: os.DirEntry[str], st: os.stat_result) -> ExclusionReason | None:
    """Classify links from metadata only; none of these calls traverse the link."""
    if entry.is_symlink():
        return ExclusionReason.SYMLINK
    is_junction = getattr(entry, "is_junction", None)  # Python 3.12+
    if is_junction is not None and is_junction():
        return ExclusionReason.JUNCTION
    if _is_reparse_point(st):
        if getattr(st, "st_reparse_tag", 0) == stat.IO_REPARSE_TAG_MOUNT_POINT:
            return ExclusionReason.JUNCTION
        return ExclusionReason.REPARSE_POINT
    return None


def _to_text(name: str) -> tuple[str, bool]:
    """Make a name JSON-safe: undecodable bytes / lone surrogates become escapes."""
    safe = name.encode("utf-8", "backslashreplace").decode("utf-8")
    return safe, safe != name


class _Walker:
    def __init__(self, root: Path, policy: ScanPolicy, clock: Callable[[], float]) -> None:
        self.root = os.fspath(root)
        self.policy = policy
        self.clock = clock
        self.deadline = clock() + policy.max_duration_seconds
        self.result = DiscoveryResult()
        self._escaped_names = 0

    def run(self) -> DiscoveryResult:
        fs_root = extended_length_path(self.root)
        stack = [_PendingDir(fs_root, (), _identity(os.lstat(fs_root)), 0)]
        while stack:
            if self.clock() > self.deadline:
                self.result.mark_incomplete(IncompleteReason.TIMEOUT)
                break
            pending = stack.pop()
            try:
                subdirs = self._scan_directory(pending)
            except _StopScan:
                break
            # Reverse so that directories are processed in sorted (depth-first) order.
            stack.extend(reversed(subdirs))
        self.result.unvisited_directories += len(stack)
        if self._escaped_names:
            self.result.warnings.append(
                f"{self._escaped_names} name(s) were not valid Unicode and are shown escaped."
            )
        self.result.files.sort(key=lambda f: f.relative_path)
        self.result.excluded.sort(key=lambda e: e.relative_path)
        return self.result

    # -- directories -----------------------------------------------------------------

    def _still_same_directory(self, pending: _PendingDir) -> bool:
        try:
            st = os.lstat(pending.path)
        except OSError:
            return False
        return (
            stat.S_ISDIR(st.st_mode)
            and not _is_reparse_point(st)
            and _identity(st) == pending.identity
        )

    def _scan_directory(self, pending: _PendingDir) -> list[_PendingDir]:
        if not self._still_same_directory(pending):
            return self._changed(pending)
        budget = self.policy.max_entries_visited - self.result.entries_visited
        entries: list[os.DirEntry[str]] = []
        try:
            with os.scandir(pending.path) as iterator:
                for entry in iterator:
                    entries.append(entry)
                    if len(entries) > budget:  # enough to know the limit is exceeded
                        break
        except OSError:
            self._exclude(pending.parts, EntryKind.DIRECTORY, ExclusionReason.UNREADABLE)
            self.result.mark_incomplete(IncompleteReason.UNREADABLE)
            return []
        if not self._still_same_directory(pending):
            return self._changed(pending)

        entries.sort(key=lambda e: e.name)
        subdirs: list[_PendingDir] = []
        try:
            for entry in entries:
                if self.result.entries_visited >= self.policy.max_entries_visited:
                    self.result.mark_incomplete(IncompleteReason.MAX_ENTRIES)
                    raise _StopScan
                if self.clock() > self.deadline:
                    self.result.mark_incomplete(IncompleteReason.TIMEOUT)
                    raise _StopScan
                self.result.entries_visited += 1
                subdir = self._visit(pending, entry)
                if subdir is not None:
                    subdirs.append(subdir)
        except _StopScan:
            # Directories already discovered here will never be visited: count them.
            self.result.unvisited_directories += len(subdirs)
            raise
        return subdirs

    def _changed(self, pending: _PendingDir) -> list[_PendingDir]:
        self._exclude(pending.parts, EntryKind.DIRECTORY, ExclusionReason.CHANGED_DURING_SCAN)
        self.result.mark_incomplete(IncompleteReason.CHANGED_DURING_SCAN)
        return []

    # -- entries ---------------------------------------------------------------------

    def _visit(self, parent: _PendingDir, entry: os.DirEntry[str]) -> _PendingDir | None:
        name = entry.name
        parts = (*parent.parts, name)
        if name in ("", ".", "..") or any(ch in name for ch in _FORBIDDEN_NAME_CHARS):
            self._exclude(parts, EntryKind.OTHER, ExclusionReason.INVALID_NAME)
            return None
        try:
            st = entry.stat(follow_symlinks=False)
        except OSError:
            self._exclude(parts, EntryKind.OTHER, ExclusionReason.UNREADABLE)
            self.result.mark_incomplete(IncompleteReason.UNREADABLE)
            return None

        link_reason = _link_reason(entry, st)
        if link_reason is not None:
            self._exclude(
                parts,
                EntryKind.LINK,
                link_reason,
                points_outside_root=self._link_points_outside(entry.path),
            )
            return None
        if stat.S_ISDIR(st.st_mode):
            return self._visit_directory(entry, parts, parent.depth + 1)
        if stat.S_ISREG(st.st_mode):
            self._visit_file(parts, st)
            return None
        self._exclude(parts, EntryKind.OTHER, ExclusionReason.SPECIAL_FILE)
        return None

    def _visit_directory(
        self, entry: os.DirEntry[str], parts: tuple[str, ...], depth: int
    ) -> _PendingDir | None:
        reason = self.policy.directory_exclusion(entry.name)
        if reason is ExclusionReason.VCS_METADATA:
            if depth == 1:
                self.result.vcs_metadata.append(_to_text(entry.name)[0])
        elif os.path.lexists(os.path.join(entry.path, "pyvenv.cfg")):
            # Any virtual environment, whatever its directory name.
            reason = ExclusionReason.VIRTUALENV
        if reason is not None:
            self._exclude(parts, EntryKind.DIRECTORY, reason)
            return None
        if depth > self.policy.max_depth:
            self._exclude(parts, EntryKind.DIRECTORY, ExclusionReason.MAX_DEPTH)
            self.result.mark_incomplete(IncompleteReason.MAX_DEPTH)
            return None
        try:
            identity = _identity(os.lstat(entry.path))
        except OSError:
            self._exclude(parts, EntryKind.DIRECTORY, ExclusionReason.UNREADABLE)
            self.result.mark_incomplete(IncompleteReason.UNREADABLE)
            return None
        return _PendingDir(entry.path, parts, identity, depth)

    def _visit_file(self, parts: tuple[str, ...], st: os.stat_result) -> None:
        if normalize_name(parts[-1]) == ".git":
            # A ".git" *file* (worktree / submodule pointer) is VCS metadata too.
            if len(parts) == 1:
                self.result.vcs_metadata.append(".git")
            self._exclude(parts, EntryKind.FILE, ExclusionReason.VCS_METADATA)
            return
        if len(self.result.files) >= self.policy.max_files:
            self.result.mark_incomplete(IncompleteReason.MAX_FILES)
            raise _StopScan
        sensitive = self.policy.is_sensitive(parts[-1])
        oversized = st.st_size > self.policy.max_file_size_bytes
        self.result.files.append(
            FileEntry(
                relative_path=self._posix(parts),
                size_bytes=st.st_size,
                category=classify_file(parts),
                is_sensitive=sensitive,
                ai_context_allowed=not sensitive and not oversized,
                # Sensitive files stay eligible: excluding them from AI context must not
                # hide them from secret scanning.
                secret_scan_eligible=True,
                oversized=oversized,
            )
        )

    # -- helpers ---------------------------------------------------------------------

    def _link_points_outside(self, link_path: str) -> bool | None:
        """Lexical, best-effort check of a link's target. The link is never followed."""
        try:
            target = plain_path(os.readlink(link_path))
        except (OSError, ValueError):
            return None
        if not os.path.isabs(target):
            target = os.path.join(os.path.dirname(plain_path(link_path)), target)
        target = os.path.normcase(os.path.normpath(target))
        root = os.path.normcase(self.root)
        try:
            return os.path.commonpath([root, target]) != root
        except ValueError:  # e.g. different drives
            return True

    def _posix(self, parts: tuple[str, ...]) -> str:
        if not parts:
            return "."
        texts = []
        for part in parts:
            text, escaped = _to_text(part)
            self._escaped_names += escaped
            texts.append(text)
        return "/".join(texts)

    def _exclude(
        self,
        parts: tuple[str, ...],
        kind: EntryKind,
        reason: ExclusionReason,
        points_outside_root: bool | None = None,
    ) -> None:
        self.result.excluded.append(
            ExcludedEntry(
                relative_path=self._posix(parts),
                kind=kind,
                reason=reason,
                points_outside_root=points_outside_root,
            )
        )
