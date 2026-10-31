"""Git history access for the secret scan (Stage 4b, D-047): never git on the target.

Measured in step 0 (synthetic lab repositories):

- git run on the target's own ``.git`` executes commands from its config (``textconv``,
  ``include.path``, ``gpg.program``) and lets ``.gitattributes`` (``-diff``, ``binary``) and
  replace refs hide content. Therefore git only ever runs on a **private copy** whose config
  the auditor writes itself; the target's config, hooks, ``info/``, logs and replace refs are
  never copied, and system/global git configuration is disabled.
- ``.git`` is read without following links. Structures that cannot be copied safely are
  refused before git starts: links/junctions, a ``.git`` *file* (gitdir redirect),
  alternates (local, outside the root or UNC), reftable, partial clones (promisor) and
  unknown repository extensions.
- Only plumbing commands run on the copy (``rev-list``, ``diff-tree``, ``cat-file``); no
  content diff, no textconv, no attributes, no pager, no network (no remote is configured).
  Every git exit code is checked: a git failure is an error, never "no findings".

Attribution (user requirement: verified, never guessed): content B at path P is *introduced*
by commit C when C's tree has B at P and none of C's parents has B at P; a root commit
introduces everything it contains. It is derived from ``git diff-tree -r -m --root`` of every
reachable commit against each of its parents, which yields every (blob, path) of every commit
tree. A blob reachable only through a tag (or a tree tag) has no verified path and no commit.
"""

import os
import re
import shutil
import stat
import subprocess
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from auditor.core.safe_fs import is_link_like
from auditor.discovery.repository import extended_length_path
from auditor.scanners.process_tree import ProcessTree

MIN_GIT_VERSION = (2, 32)  # GIT_CONFIG_GLOBAL; GIT_CONFIG_COUNT needs 2.31
MAX_GIT_DIR_BYTES = 1 << 30
_READ_FLAGS = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
_WRITE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
_HEX = re.compile(rb"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_HEAD = re.compile(rb"^(?:ref: refs/[A-Za-z0-9._/-]{1,240}|[0-9a-f]{40}|[0-9a-f]{64})\s*$")
_SECTION = re.compile(r"^\[\s*([A-Za-z0-9.-]+)(?:\s+\"(?:[^\"\\]|\\.)*\")?\s*\]")
_ALLOWED_EXTENSIONS = frozenset({"objectformat"})

# Highest-precedence overrides on top of the auditor's own config (defence in depth: none of
# these is needed by the plumbing commands used, and none can be set by the target).
HARDENING = {
    "core.fsmonitor": "false",
    "core.hooksPath": os.devnull,
    "core.attributesFile": os.devnull,
    "core.pager": "cat",
    "log.showSignature": "false",
    "protocol.allow": "never",
    "color.ui": "false",
    "core.quotePath": "false",
    # measured: git for Windows cannot open a pack file beyond MAX_PATH without it
    "core.longpaths": "true",
}

REFUSAL_TEXT = {
    "NO_GIT_DIR": "no .git directory at the scan root",
    "GIT_DIR_IS_LINK": ".git is a link or junction; not followed",
    "GIT_FILE_REDIRECT": ".git is a file (gitdir redirect, e.g. a linked worktree or "
    "submodule); not supported",
    "LINK_IN_GIT_DIR": "a link or junction inside .git; not followed",
    "ALTERNATES": "the object store uses alternates (objects outside this repository); refused",
    "REFTABLE": "reftable reference storage is not supported",
    "PARTIAL_CLONE": "partial clone (promisor): missing objects would need the network; refused",
    "UNKNOWN_EXTENSION": "unknown repository format or extension; refused",
    "INVALID_HEAD": "HEAD is not a valid reference",
    "INVALID_SHALLOW": "the shallow file is not valid",
    "SIZE_LIMIT": "the .git directory is larger than the copy limit",
    "UNREADABLE": "part of .git could not be read safely",
    "CHANGED": ".git changed while it was being copied",
}
LIMITATION_TEXT = {
    "SHALLOW": "shallow clone: commits beyond the shallow boundary are not in the repository",
    "LINKED_WORKTREES": "linked worktrees exist: their HEADs and per-worktree refs are not "
    "scanned (only refs/ and HEAD of the main repository)",
    "SUBMODULES": "submodule repositories (.git/modules) are not scanned",
}
NOTE_TEXT = {
    "REPLACE_REFS_IGNORED": "replace refs exist; they were ignored (the original objects "
    "were scanned)",
    "GRAFTS_IGNORED": "a grafts file exists; it was ignored",
    "CONFIG_INCLUDES_IGNORED": "the repository config includes other files; the target's "
    "config is never used",
}


class GitRefused(Exception):
    """The target's .git cannot be copied safely; ``code`` is a key of REFUSAL_TEXT."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class GitError(Exception):
    """A git command on the private copy failed; ``kind`` is a fixed word, no tool output."""

    def __init__(self, kind: str, command: str):
        super().__init__(f"{command}: {kind}")
        self.kind, self.command = kind, command


@dataclass(frozen=True)
class GitDirInfo:
    size: int
    object_format: str  # "sha1" | "sha256"
    limitations: tuple[str, ...]
    notes: tuple[str, ...]


# --------------------------------------------------------------------------- trusted git


def find_git(path_env: str | None = None) -> Path | None:
    found = shutil.which("git", path=path_env)
    return Path(found).resolve() if found else None


def hardened_git_env(work: Path, git: Path, git_dir: Path | None = None) -> dict[str, str]:
    """Allowlisted environment: nothing of the user's git setup, nothing of the target's."""
    home = work / "git-home"
    home.mkdir(exist_ok=True)
    empty = home / "empty.gitconfig"
    if not empty.exists():
        empty.write_bytes(b"")
    env = {k: os.environ[k] for k in ("SYSTEMROOT", "WINDIR", "SYSTEMDRIVE") if k in os.environ}
    env.update({
        "PATH": str(git.parent),
        "HOME": str(home), "USERPROFILE": str(home), "XDG_CONFIG_HOME": str(home),
        "TEMP": str(home), "TMP": str(home), "TMPDIR": str(home),
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": str(empty),
        "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "", "SSH_ASKPASS": "",
        "GIT_NO_REPLACE_OBJECTS": "1", "GIT_NO_LAZY_FETCH": "1", "GIT_OPTIONAL_LOCKS": "0",
        "GIT_ATTR_NOSYSTEM": "1", "GIT_ALLOW_PROTOCOL": "", "LC_ALL": "C", "NO_COLOR": "1",
    })  # fmt: skip
    if git_dir is not None:
        env["GIT_DIR"] = str(git_dir)
    env["GIT_CONFIG_COUNT"] = str(len(HARDENING))
    for index, (key, value) in enumerate(HARDENING.items()):
        env[f"GIT_CONFIG_KEY_{index}"], env[f"GIT_CONFIG_VALUE_{index}"] = key, value
    return env


def parse_git_version(text: str) -> tuple[int, int] | None:
    match = re.match(r"^git version (\d+)\.(\d+)", text.strip())
    return (int(match.group(1)), int(match.group(2))) if match else None


# ------------------------------------------------------------- reading .git (no git at all)


def _full(path: Path) -> str:
    return extended_length_path(os.fspath(path))


def _read_small(path: Path, limit: int = 1 << 20) -> bytes:
    """Whole small file, links refused, identity checked; b"" if it does not exist."""
    try:
        before = os.lstat(_full(path))
    except FileNotFoundError:
        return b""
    except OSError as exc:
        raise GitRefused("UNREADABLE") from exc
    if is_link_like(before):
        raise GitRefused("LINK_IN_GIT_DIR")
    if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
        raise GitRefused("UNREADABLE")
    return _copy_or_read(path, None, before)


def _copy_or_read(src: Path, dst: Path | None, before: os.stat_result) -> bytes:
    try:
        descriptor = os.open(_full(src), _READ_FLAGS)
    except OSError as exc:
        raise GitRefused("UNREADABLE") from exc
    out = None
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise GitRefused("CHANGED")
        if dst is not None:
            out = os.open(_full(dst), _WRITE_FLAGS, 0o600)
        chunks, total = [], 0
        while chunk := os.read(descriptor, 1 << 20):
            total += len(chunk)
            if total > opened.st_size:
                raise GitRefused("CHANGED")
            if out is None:
                chunks.append(chunk)
            else:
                os.write(out, chunk)
        after = os.fstat(descriptor)
        if total != opened.st_size or (after.st_size, after.st_mtime_ns) != (
            opened.st_size,
            opened.st_mtime_ns,
        ):
            raise GitRefused("CHANGED")
        return b"".join(chunks)
    finally:
        os.close(descriptor)
        if out is not None:
            os.close(out)


def _walk(top: Path):
    """(path, lstat) of every entry below ``top``; any link or junction is refused."""
    stack = [top]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(_full(current)) as entries:
                items = [(Path(current, e.name), e.stat(follow_symlinks=False)) for e in entries]
        except OSError as exc:
            raise GitRefused("UNREADABLE") from exc
        for path, st in sorted(items):
            if is_link_like(st):
                raise GitRefused("LINK_IN_GIT_DIR")
            if stat.S_ISDIR(st.st_mode):
                stack.append(path)
            yield path, st


def _config_flags(text: str) -> dict:
    """A conservative line scan of the target's config: read for refusals only, never used."""
    section, flags = "", {"extensions": set(), "promisor": False, "version": 0, "include": False}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in "#;":
            continue
        header = _SECTION.match(line)
        if header:
            section = header.group(1).lower()
            flags["include"] |= section in ("include", "includeif")
            line = line[header.end() :].strip()
            if not line:
                continue
        elif line.startswith("["):
            flags["extensions"].add("<unparsed section>")
            continue
        key = line.split("=", 1)[0].strip().lower()
        value = line.split("=", 1)[1].strip().lower() if "=" in line else "true"
        if section == "extensions":
            flags["extensions"].add(key)
        elif section == "core" and key == "repositoryformatversion":
            flags["version"] = int(value) if value.isdigit() else 99
        elif section == "remote" and key in ("promisor", "partialclonefilter"):
            flags["promisor"] = True
    return flags


def inspect_git_dir(root: Path, max_bytes: int = MAX_GIT_DIR_BYTES) -> GitDirInfo:
    """Check the target's .git (read-only, no links, no git) or raise GitRefused."""
    gitdir = root / ".git"
    try:
        st = os.lstat(_full(gitdir))
    except FileNotFoundError as exc:
        raise GitRefused("NO_GIT_DIR") from exc
    except OSError as exc:
        raise GitRefused("UNREADABLE") from exc
    if is_link_like(st):
        raise GitRefused("GIT_DIR_IS_LINK")
    if stat.S_ISREG(st.st_mode):
        raise GitRefused("GIT_FILE_REDIRECT")
    if not stat.S_ISDIR(st.st_mode):
        raise GitRefused("UNREADABLE")
    size = sum(s.st_size for _, s in _walk(gitdir) if stat.S_ISREG(s.st_mode))
    for name in ("objects/info/alternates", "objects/info/http-alternates"):
        if os.path.lexists(_full(gitdir / name)):
            raise GitRefused("ALTERNATES")
    if os.path.lexists(_full(gitdir / "reftable")):
        raise GitRefused("REFTABLE")
    pack = gitdir / "objects" / "pack"
    if pack.is_dir() and any(n.endswith(".promisor") for n in os.listdir(_full(pack))):
        raise GitRefused("PARTIAL_CLONE")
    flags = _config_flags(_read_small(gitdir / "config").decode("utf-8", "replace"))
    if flags["promisor"] or "partialclone" in flags["extensions"]:
        raise GitRefused("PARTIAL_CLONE")
    if flags["extensions"] - _ALLOWED_EXTENSIONS or flags["version"] > 1:
        raise GitRefused("UNKNOWN_EXTENSION")
    if not _HEAD.match(_read_small(gitdir / "HEAD")):
        raise GitRefused("INVALID_HEAD")
    _valid_shallow(_read_small(gitdir / "shallow"))
    limitations, notes = [], []
    if os.path.lexists(_full(gitdir / "shallow")):
        limitations.append("SHALLOW")
    if os.path.lexists(_full(gitdir / "worktrees")):
        limitations.append("LINKED_WORKTREES")
    if os.path.lexists(_full(gitdir / "modules")):
        limitations.append("SUBMODULES")
    if os.path.lexists(_full(gitdir / "refs" / "replace")) or b"refs/replace/" in _read_small(
        gitdir / "packed-refs", 256 << 20
    ):
        notes.append("REPLACE_REFS_IGNORED")
    if os.path.lexists(_full(gitdir / "info" / "grafts")):
        notes.append("GRAFTS_IGNORED")
    if flags["include"]:
        notes.append("CONFIG_INCLUDES_IGNORED")
    if size > max_bytes:
        raise GitRefused("SIZE_LIMIT")
    object_format = "sha256" if "objectformat" in flags["extensions"] else "sha1"
    return GitDirInfo(size, object_format, tuple(limitations), tuple(notes))


def _valid_shallow(data: bytes) -> bytes:
    if not all(_HEX.match(line) for line in data.split()):
        raise GitRefused("INVALID_SHALLOW")
    return data


_SKIP_OBJECTS = {"info/alternates", "info/http-alternates", "info/commit-graph",
                 "info/commit-graphs"}  # fmt: skip


def _copy_tree(src: Path, dst: Path, skip: Callable[[str], bool], budget: list[int]) -> None:
    for path, st in _walk(src):
        relative = path.relative_to(src).as_posix()
        if skip(relative) or any(skip(p.as_posix()) for p in Path(relative).parents):
            continue
        target = dst / path.relative_to(src)
        if stat.S_ISDIR(st.st_mode):
            os.makedirs(_full(target), exist_ok=True)
        elif stat.S_ISREG(st.st_mode):
            # scandir's stat has no file identity on Windows (st_ino == 0): lstat again
            try:
                before = os.lstat(_full(path))
            except OSError as exc:
                raise GitRefused("CHANGED") from exc
            if is_link_like(before) or not stat.S_ISREG(before.st_mode):
                raise GitRefused("CHANGED")
            budget[0] -= before.st_size
            if budget[0] < 0:
                raise GitRefused("SIZE_LIMIT")
            os.makedirs(_full(target.parent), exist_ok=True)
            _copy_or_read(path, target, before)
        else:
            raise GitRefused("UNREADABLE")


def copy_git_history(
    root: Path, dest: Path, info: GitDirInfo, max_bytes: int = MAX_GIT_DIR_BYTES
) -> Path:
    """A private bare repository with the target's objects and refs, and the auditor's config.

    Copied: objects/ (no alternates, no commit-graph), refs/ (no refs/replace), packed-refs
    (no replace refs), HEAD and a validated shallow file. Never copied: config, hooks, info/,
    logs/, worktrees/, modules/. Returns the git directory to use as GIT_DIR.
    """
    gitdir = root / ".git"
    dest.mkdir(mode=0o700)
    budget = [max_bytes]
    _copy_tree(gitdir / "objects", dest / "objects", lambda r: r in _SKIP_OBJECTS, budget)
    os.makedirs(_full(dest / "refs"), exist_ok=True)
    if (gitdir / "refs").is_dir():
        _copy_tree(gitdir / "refs", dest / "refs", lambda r: r == "replace", budget)
    packed = _read_small(gitdir / "packed-refs", 256 << 20)
    if packed:
        (dest / "packed-refs").write_bytes(_without_replace_refs(packed))
    (dest / "HEAD").write_bytes(_read_small(gitdir / "HEAD"))
    shallow = _valid_shallow(_read_small(gitdir / "shallow"))
    if shallow:
        (dest / "shallow").write_bytes(shallow)
    config = "[core]\n\trepositoryformatversion = {}\n\tbare = true\n".format(
        1 if info.object_format == "sha256" else 0
    )
    if info.object_format == "sha256":
        config += "[extensions]\n\tobjectformat = sha256\n"
    (dest / "config").write_text(config, encoding="ascii")
    return dest


def _without_replace_refs(packed: bytes) -> bytes:
    out, skipping = [], False
    for line in packed.splitlines(keepends=True):
        if line.startswith(b"^"):  # peeled value of the previous ref
            if not skipping:
                out.append(line)
            continue
        skipping = b" refs/replace/" in line
        if not skipping:
            out.append(line)
    return b"".join(out)


# ------------------------------------------------------------------- git on the private copy


class GitRunner:
    """Run plumbing commands on the private copy: fixed argv, no shell, stderr discarded
    (only counted), whole process tree killed on timeout, every exit code checked."""

    def __init__(self, git: Path, git_dir: Path, env: Mapping[str, str], timeout: float,
                 deadline: float | None = None):  # fmt: skip
        if not Path(git).is_absolute():  # never let the OS search PATH or the cwd (S603)
            raise ValueError("git must be given as an absolute path")
        self.git, self.git_dir, self.env = Path(git), Path(git_dir), dict(env)
        self.env["GIT_DIR"] = str(git_dir)
        self.timeout = timeout
        self.deadline = deadline if deadline is not None else time.monotonic() + timeout

    def stream(
        self,
        args: Iterable[str],
        on_chunk: Callable[[bytes], None],
        stdin: Iterable[bytes] | None = None,
    ) -> None:
        args = list(args)
        name = args[0] if args else "git"
        tree = ProcessTree()
        try:
            process = subprocess.Popen(  # noqa: S603 - trusted git, fixed argv, shell=False
                [str(self.git), *args],
                shell=False,
                cwd=self.git_dir,
                env=self.env,
                stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                **ProcessTree.popen_kwargs(),
            )
        except OSError as exc:
            raise GitError("could not be started", name) from exc
        tree.attach(process)
        errors: list[BaseException] = []

        def feed() -> None:
            try:
                for block in stdin or ():
                    process.stdin.write(block)
                process.stdin.close()
            except OSError:
                pass

        def drain() -> None:
            while process.stderr.read(65536):
                pass

        helpers = [threading.Thread(target=drain, daemon=True)]
        if stdin is not None:
            helpers.append(threading.Thread(target=feed, daemon=True))
        for helper in helpers:
            helper.start()
        timer = threading.Timer(max(0.1, self.deadline - time.monotonic()), tree.kill)
        timer.start()
        try:
            while chunk := process.stdout.read(1 << 20):
                try:
                    on_chunk(chunk)
                except BaseException as exc:  # stop git, then re-raise the consumer's error
                    errors.append(exc)
                    tree.kill()
                    break
            code = process.wait()
        finally:
            timer.cancel()
            for helper in helpers:
                helper.join(timeout=5)
            tree.close()
        if errors:
            raise errors[0]
        if time.monotonic() >= self.deadline:
            raise GitError("timed out", name)
        if code != 0:
            raise GitError(f"exit code {code}", name)

    def output(self, args: Iterable[str], stdin: bytes | None = None,
               limit: int = 256 << 20) -> bytes:  # fmt: skip
        parts: list[bytes] = []
        size = [0]

        def collect(chunk: bytes) -> None:
            size[0] += len(chunk)
            if size[0] > limit:
                raise GitError("output too large", "git")
            parts.append(chunk)

        self.stream(args, collect, None if stdin is None else [stdin])
        return b"".join(parts)


def split_records(on_record: Callable[[bytes], None]) -> tuple[Callable[[bytes], None],
                                                                 Callable[[], None]]:  # fmt: skip
    """NUL-separated stream -> records (for ``-z`` output)."""
    pending = bytearray()

    def feed(chunk: bytes) -> None:
        pending.extend(chunk)
        *done, rest = bytes(pending).split(b"\0")
        pending[:] = rest
        for record in done:
            on_record(record)

    def finish() -> None:
        if pending:
            on_record(bytes(pending))
            pending.clear()

    return feed, finish


# ----------------------------------------------------------------------- history index


@dataclass
class HistoryIndex:
    commits: int = 0
    commit_ids: list[str] = field(default_factory=list)
    blobs: dict[str, int] = field(default_factory=dict)  # every reachable blob -> size
    paths: dict[str, set[str]] = field(default_factory=dict)  # blob -> verified paths
    introductions: dict[str, set[tuple[str, str]]] = field(default_factory=dict)
    # with ``classify``: blob -> OR of classify(path) over its verified paths (no paths kept)
    path_flags: dict[str, int] = field(default_factory=dict)


def decode_path(raw: bytes) -> str:
    """Exact, reversible text form of a git path (invalid UTF-8 kept as escapes)."""
    return raw.decode("utf-8", "surrogateescape")


class _TreeChanges:
    """Parser state for ``git diff-tree --stdin -r -m --root --always --raw -z``."""

    def __init__(self, index: HistoryIndex, wanted: set[str] | None,
                 classify: Callable[[str], int] | None = None):  # fmt: skip
        self.index, self.wanted, self.classify = index, wanted, classify
        self.commit: bytes | None = None
        self.blocks: list[dict[str, str]] = []
        self.meta: bytes | None = None

    def record(self, token: bytes) -> None:
        if self.meta is not None:
            self._entry(self.meta, token)
            self.meta = None
        elif token.startswith(b":"):
            self.meta = token
        elif _HEX.match(token):
            if token != self.commit:
                self.flush()
                self.commit = token
            self.blocks.append({})
        elif token:
            raise GitError("unexpected output", "diff-tree")

    def _entry(self, meta: bytes, raw_path: bytes) -> None:
        fields = meta[1:].split(b" ")
        if len(fields) != 5 or not self.blocks:
            raise GitError("unexpected output", "diff-tree")
        new_mode, new_blob = fields[1], fields[3].decode("ascii")
        if new_mode[:2] not in (b"10", b"12") or set(new_blob) == {"0"}:
            return  # deletions, gitlinks (submodule commits) and trees carry no blob
        if self.wanted is not None and new_blob not in self.wanted:
            return
        path = decode_path(raw_path)
        if self.classify is not None:  # memory-bounded mode: flags only, no paths or commits
            flags = self.index.path_flags
            flags[new_blob] = flags.get(new_blob, 0) | self.classify(path)
            return
        self.blocks[-1][path] = new_blob
        self.index.paths.setdefault(new_blob, set()).add(path)

    def flush(self) -> None:
        if self.commit is None:
            return
        commit = self.commit.decode("ascii")
        first, *others = self.blocks
        for path, blob in first.items():
            if all(other.get(path) == blob for other in others):
                self.index.introductions.setdefault(blob, set()).add((commit, path))
        self.commit, self.blocks = None, []


def index_history(runner: GitRunner, wanted: set[str] | None = None,
                  with_blobs: bool = True,
                  classify: Callable[[str], int] | None = None) -> HistoryIndex:  # fmt: skip
    """Verified blob -> path / introducing-commit index of everything reachable from --all.

    ``wanted`` restricts paths and introductions to those blobs; ``classify`` instead keeps
    only an OR of ``classify(path)`` per blob (memory-bounded first pass).
    """
    index = HistoryIndex()
    commits = runner.output(["rev-list", "--all"]).split()
    if not all(_HEX.match(c) for c in commits):
        raise GitError("unexpected output", "rev-list")
    index.commits = len(commits)
    index.commit_ids = [c.decode("ascii") for c in commits]
    if with_blobs:
        index.blobs = list_blobs(runner)
    if not commits:
        return index
    parser = _TreeChanges(index, wanted, classify)
    feed, finish = split_records(parser.record)
    runner.stream(
        ["diff-tree", "--stdin", "-r", "-m", "--root", "--always", "--raw", "--no-abbrev",
         "--no-renames", "-z"],
        feed,
        stdin=(c + b"\n" for c in commits),
    )  # fmt: skip
    finish()
    parser.flush()
    return index


def list_blobs(runner: GitRunner) -> dict[str, int]:
    """Every blob reachable from --all -> size (object names only: no paths are read here)."""
    objects = runner.output(["rev-list", "--all", "--objects", "--no-object-names"]).split()
    if not objects:
        return {}
    check = runner.output(
        ["cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"],
        stdin=b"\n".join(objects) + b"\n",
    )
    blobs = {}
    for line in check.splitlines():
        parts = line.split()
        if len(parts) != 3 or not _HEX.match(parts[0]) or not parts[2].isdigit():
            raise GitError("unexpected output", "cat-file")
        if parts[1] == b"blob":
            blobs[parts[0].decode("ascii")] = int(parts[2])
    return blobs


class _BatchReader:
    """Incremental parser of ``git cat-file --batch`` output (one object at a time)."""

    def __init__(self, on_object: Callable[[str, bytes, bytes], None]):
        self.on_object, self.buffer = on_object, bytearray()
        self.header: tuple[str, bytes, int] | None = None

    def feed(self, chunk: bytes) -> None:
        self.buffer.extend(chunk)
        while True:
            if self.header is None:
                end = self.buffer.find(b"\n")
                if end < 0:
                    return
                parts = bytes(self.buffer[:end]).split()
                del self.buffer[: end + 1]
                if len(parts) != 3 or not _HEX.match(parts[0]) or not parts[2].isdigit():
                    raise GitError("missing or unexpected object", "cat-file")
                self.header = (parts[0].decode("ascii"), parts[1], int(parts[2]))
            sha, kind, size = self.header
            if len(self.buffer) < size + 1:
                return
            data = bytes(self.buffer[:size])
            del self.buffer[: size + 1]
            self.header = None
            self.on_object(sha, kind, data)

    def finish(self) -> None:
        if self.header is not None or self.buffer:
            raise GitError("truncated output", "cat-file")


def read_objects(runner: GitRunner, shas: Iterable[str],
                 on_object: Callable[[str, bytes, bytes], None]) -> None:  # fmt: skip
    """Stream the raw content of the given objects (no filters, no textconv) to on_object."""
    reader = _BatchReader(on_object)
    runner.stream(["cat-file", "--batch"], reader.feed,
                  stdin=(s.encode("ascii") + b"\n" for s in shas))  # fmt: skip
    reader.finish()


def parse_commit(data: bytes) -> tuple[int | None, bytes]:
    """(committer timestamp, message) of a raw commit; author/committer names never read."""
    head, _, message = data.partition(b"\n\n")
    timestamp = None
    for line in head.split(b"\n"):
        if line.startswith(b"committer "):
            fields = line.rsplit(b" ", 2)
            timestamp = int(fields[1]) if len(fields) == 3 and fields[1].isdigit() else None
    return timestamp, message
