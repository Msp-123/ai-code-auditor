"""Gitleaks over git history (Stage 4b, D-047): opt-in with ``--scan-git-history``.

Step 0 measured that ``gitleaks git`` is unsuitable: on a merge it misses content that only
the merge introduces, its default path allowlist skips lock files, images, ``node_modules``
and more, it returns exit 0 with no findings when git fails, it never scans commit messages,
and its JSON carries authors, e-mails and the raw commit message (secrets included).

Method instead (user decision K1'):

1. ``git_history`` validates the target's ``.git`` without running git and copies objects and
   refs into a private repository with the auditor's own config (git never runs on the
   target; nothing of its config, hooks or attributes is used).
2. Every reachable blob and every commit message is written into the private workspace as a
   file named by its object id (no extension: no path allowlist can match), followed by the
   4a end marker. ``gitleaks dir`` scans these files with the same fixed options and
   hash-verified configs as Stage 4a. An object counts as scanned only if its marker is
   reported on the expected line in every configuration it was scanned with; otherwise it is
   reported as not analyzed (archives included).
3. Path-conditioned rules use the 4a mechanism, decided from the blob's *verified* paths (from
   the commit trees). A blob without a verified path (reachable through a tag only) is
   scanned with the base rules and reported as a limitation.
4. Attribution of findings comes from the commit trees (``git_history.index_history``): every
   commit that introduces the content at a path is listed; nothing is guessed.
5. Only rule id, line and the local file name (an object id) are read from Gitleaks' report.
"""

import json
import os
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from auditor.core.models import (
    Confidence,
    Evidence,
    Finding,
    FindingCategory,
    FindingIdentifiers,
    LimitedFile,
    NotAnalyzedFile,
    NotAnalyzedReason,
    Severity,
    ToolExecution,
    ToolStatus,
    VerificationStatus,
)
from auditor.core.redaction import sanitize_for_display
from auditor.core.safe_fs import PRIVATE_DIR_MODE, create_private_file
from auditor.discovery.repository import extended_length_path
from auditor.findings.fingerprint import compute_fingerprint
from auditor.scanners.base import ScanContext, ScanOutcome
from auditor.scanners.executables import GITLEAKS_VERSION, resolves_inside
from auditor.scanners.git_history import (
    LIMITATION_TEXT,
    MAX_GIT_DIR_BYTES,
    MIN_GIT_VERSION,
    NOTE_TEXT,
    REFUSAL_TEXT,
    GitDirInfo,
    GitError,
    GitRefused,
    GitRunner,
    HistoryIndex,
    copy_git_history,
    find_git,
    hardened_git_env,
    index_history,
    inspect_git_dir,
    parse_commit,
    parse_git_version,
    read_objects,
)
from auditor.scanners.git_ids import git_blob_id
from auditor.scanners.gitleaks_adapter import (
    _RULE_ID,
    ARGV_TEMPLATE,
    BASE_CONFIG,
    CRITICAL_RULES,
    END_MARKER_RULE,
    GENERIC_RULES,
    PATH_RULES,
    PATHLESS_PREFIX,
    GitleaksAdapter,
    _classify,
    config_for,
    end_marker,
    read_gitleaks_version,
    skipped_format,
    with_end_marker,
)
from auditor.scanners.runner import minimal_env, run_tool, run_tool_stdin
from auditor.scanners.selection import read_regular_file

TOOL = "gitleaks-history"
RULE_PREFIX = "gitleaks."
HISTORY_PATH = "(git history)"
MESSAGE_PATH = "(commit message)"
CHUNK = 1000  # objects per `gitleaks dir` run (bounded report size)
MAX_LISTED = 5  # introductions listed per finding
MAX_REPORTED_GAPS = 200  # not-analyzed objects listed one by one
RECOMMENDATION = (
    "Treat the value as exposed: revoke or rotate it at its issuer. Removing it from the "
    "current files does not remove it from history; rewriting history is a separate decision "
    "(every clone keeps a copy). Load secrets at runtime from a secret manager or the "
    "environment."
)

_HAS_PATH = 1
# One bit per config a path can be scanned with (4a: exactly one matching path rule selects
# its path-less copy, anything else the base config); a blob gets the OR over its paths.
_CONFIG_BITS = {BASE_CONFIG: 1 << 1} | {
    p.config: 1 << (i + 2) for i, p in enumerate(PATH_RULES) if p.config
}
_RULE_OF_CONFIG = {BASE_CONFIG: None} | {p.config: p.rule for p in PATH_RULES if p.config}
_PATH_RULE_NAMES = frozenset(p.rule for p in PATH_RULES if p.config)
_ALLOWED_KEYS = ("RuleID", "StartLine", "File")


@dataclass(frozen=True)
class GitHistoryOptions:
    total_timeout: float = 900.0
    max_git_dir_bytes: int = MAX_GIT_DIR_BYTES
    max_extract_bytes: int = 2 << 30
    max_blob_bytes: int = 10 * 1024 * 1024
    max_output_bytes: int = 64 * 1024 * 1024


def classify_path(path: str) -> int:
    """Bit flags of a verified path: it exists, and the config 4a would scan it with."""
    return _HAS_PATH | _CONFIG_BITS[config_for(path)[0]]


def configs_for(flags: int) -> list[tuple[str, str | None]]:
    """(config, path rule) pairs a blob is scanned with: one per config its paths need."""
    pairs = [(c, _RULE_OF_CONFIG[c]) for c, bit in _CONFIG_BITS.items() if flags & bit]
    return pairs or [(BASE_CONFIG, None)]


@dataclass
class _Item:
    kind: str  # "blob" | "message"
    sha: str
    config: str
    path_rule: str | None
    folder: Path
    marker_line: int
    lines: int
    known_skip: str | None  # format Gitleaks is measured not to scan (SKIPPED_FORMATS)


@dataclass
class _Run:
    findings: list[Finding] = field(default_factory=list)
    not_analyzed: list[NotAnalyzedFile] = field(default_factory=list)
    limited: list[LimitedFile] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    exit_codes: set[int] = field(default_factory=set)
    # (kind, sha, rule, line) -> the configs that reported it (decides the paths it applies to)
    hits: dict[tuple[str, str, str, int], set[str]] = field(default_factory=dict)
    confirmed: set[tuple[str, str]] = field(default_factory=set)  # marker seen at least once
    gaps: dict[tuple[str, str], tuple[NotAnalyzedReason, str]] = field(default_factory=dict)
    path_unknown: set[str] = field(default_factory=set)
    seen_ids: set[str] = field(default_factory=set)

    def warn(self, text: str) -> None:
        if text not in self.warnings:
            self.warnings.append(text)

    def scanned(self, kind: str) -> int:
        return sum(1 for k in self.confirmed if k[0] == kind and k not in self.gaps)


class _Timeout(Exception):
    pass


class GitHistoryAdapter:
    name = TOOL

    def __init__(
        self,
        options: GitHistoryOptions | None = None,
        gitleaks_command: Sequence[str] | None = None,
        tools_base: Path | None = None,
        git: Path | None = None,
    ):
        self.options = options or GitHistoryOptions()
        self.gitleaks = GitleaksAdapter(command=gitleaks_command, tools_base=tools_base)
        self.git = git
        o = self.options
        self.settings = {
            "method": "private copy of objects and refs (git never runs on the target); every "
            "reachable blob and commit message extracted and scanned with `gitleaks dir`",
            "scope_history": "all refs (branches, tags, remote-tracking, stash, notes) and HEAD; "
            "not: reflogs, unreachable objects, submodules, linked worktrees",
            "attribution": "verified from commit trees: every commit that introduces the content "
            "at a path is listed; commit dates are commit metadata (set by the committer)",
            "personal_data": "author and committer names, e-mail addresses and message text are "
            "never read into the report",
            "redaction": "--redact=100; only rule id, line and object id are kept",
            "target_config": "the target's git config, hooks, attributes, replace refs and "
            "grafts are never used; system and global git configuration is disabled",
            "network": "not used (the private copy has no remote)",
            "limits": f"copy {o.max_git_dir_bytes} B, extracted {o.max_extract_bytes} B, per "
            f"object {o.max_blob_bytes} B, {o.total_timeout:g} s",
            "input_check": "end marker per extracted object; counts and markers do not prove a "
            "complete security review",
        }

    # ----------------------------------------------------------------------------- driver

    def scan(self, context: ScanContext) -> ScanOutcome:
        started = time.monotonic()
        deadline = started + self.options.total_timeout
        run = _Run()
        version, counts = None, {}
        try:
            version, counts, status, reason = self._scan(context, run, deadline)
        except GitRefused as refused:
            text = REFUSAL_TEXT[refused.code]
            status = ToolStatus.SKIPPED
            if refused.code == "NO_GIT_DIR":
                reason = f"Not a git repository ({text}): there is no history to scan"
            else:
                reason = f"Git history not scanned: {text}"
                run.not_analyzed.append(NotAnalyzedFile(
                    relative_path=".git", reason=NotAnalyzedReason.UNSAFE_REPOSITORY,
                    detail=text))  # fmt: skip
        except (_Timeout, GitError) as exc:
            timed_out = isinstance(exc, _Timeout) or exc.kind == "timed out"
            status = ToolStatus.TIMED_OUT if timed_out else ToolStatus.ERROR
            reason = (
                "Git history scan did not finish within the time limit; results are incomplete"
                if timed_out
                else f"git failed on the private copy ({exc}); results are incomplete"
            )
        execution = ToolExecution(
            tool=TOOL,
            version=version,
            status=status,
            reason=reason,
            exit_codes=sorted(run.exit_codes),
            duration_seconds=round(time.monotonic() - started, 3),
            files_requested=counts.get("objects", 0),
            files_analyzed=run.scanned("blob") + run.scanned("message"),
            not_analyzed=run.not_analyzed,
            settings={**self.settings, **{k: str(v) for k, v in counts.items()}},
            command_summary="gitleaks dir on extracted history objects (private copy)",
            stderr_excerpt=None,
            warnings=run.warnings,
            coverage_limitations=run.limited,
        )
        return ScanOutcome(execution, run.findings, [])

    def _scan(self, context: ScanContext, run: _Run, deadline: float):
        refusal = self.gitleaks._refusal(context.root)
        if refusal is not None:
            return None, {}, *refusal
        configs = self.gitleaks._verified_configs()
        if configs is None:
            return None, {}, ToolStatus.ERROR, "Gitleaks configuration integrity check failed"
        git = self.git or find_git()
        if git is None:
            reason = "git was not found (needed only for --scan-git-history)"
            return None, {}, ToolStatus.NOT_INSTALLED, reason
        if resolves_inside(git, context.root):
            return None, {}, ToolStatus.ERROR, "git resolves inside the scan target; refused"
        work = context.workspace
        info = inspect_git_dir(context.root, self.options.max_git_dir_bytes)
        env = hardened_git_env(work, git)
        git_version = self._git_version(git, work, env)
        if git_version is None or git_version < MIN_GIT_VERSION:
            shown = ".".join(map(str, git_version)) if git_version else "unknown"
            required = ".".join(map(str, MIN_GIT_VERSION))
            return None, {}, ToolStatus.ERROR, f"git {shown} is older than the required {required}"
        argv, cwd, gl_env = self._prepare_gitleaks(work, configs)
        version = read_gitleaks_version(self.gitleaks.command, cwd, gl_env)
        if version != GITLEAKS_VERSION:
            run.warn(f"Gitleaks {version or 'unknown'} differs from the pinned {GITLEAKS_VERSION}; "
                     "rules and output format may differ.")  # fmt: skip
        copy = copy_git_history(context.root, work / "copy", info, self.options.max_git_dir_bytes)
        self._check(deadline)
        runner = GitRunner(git, copy, env, self.options.total_timeout, deadline)
        index = index_history(runner, classify=classify_path)
        self._check(deadline)
        for code in info.limitations:
            run.limited.append(LimitedFile(relative_path=".git", reason=f"GIT_{code}",
                                           detail=LIMITATION_TEXT[code]))  # fmt: skip
        for code in info.notes:
            run.warn(NOTE_TEXT[code][0].upper() + NOTE_TEXT[code][1:] + ".")
        scan_dir = work / "scan"
        scan_dir.mkdir(mode=PRIVATE_DIR_MODE)
        items, dates = self._extract(runner, index, scan_dir, run, deadline)
        self._scan_items(items, argv, cwd, gl_env, run, deadline)
        self._reconcile(index, run)
        self._report(runner, info, dates, context, run)
        blobs, messages = run.scanned("blob"), run.scanned("message")
        counts = {
            "commits": index.commits,
            "blobs_reachable": len(index.blobs),
            "blobs_scanned": blobs,
            "commit_messages_scanned": messages,
            "objects": len(index.blobs) + index.commits,
            "git": ".".join(map(str, git_version)),
            "copy_bytes": info.size,
        }
        reason = (f"Completed; {blobs} of {len(index.blobs)} blobs and {messages} of "
                  f"{index.commits} commit messages scanned")  # fmt: skip
        return version, counts, ToolStatus.SUCCESS, reason

    # ---------------------------------------------------------------------------- helpers

    @staticmethod
    def _check(deadline: float) -> None:
        if time.monotonic() >= deadline:
            raise _Timeout

    @staticmethod
    def _git_version(git: Path, work: Path, env: dict) -> tuple[int, int] | None:
        result = run_tool([str(git), "--version"], cwd=work, timeout=30, env=env,
                          stdout_limit=256)  # fmt: skip
        return parse_git_version(result.stdout) if result.exit_code == 0 else None

    def _prepare_gitleaks(self, work: Path, configs: dict[str, bytes]):
        """Private cwd/HOME/TEMP, the verified configs and one `gitleaks dir` argv per config."""
        cwd, home, tmp = work / "gl-cwd", work / "gl-home", work / "gl-tmp"
        config_dir = work / "gl-config"
        for directory in (cwd, home, tmp, config_dir):
            directory.mkdir(mode=PRIVATE_DIR_MODE)
        ignore = work / "empty.gitleaksignore"
        create_private_file(ignore, "")
        argv = {}
        for name, data in configs.items():
            create_private_file(config_dir / name, data.decode("utf-8"))
            rest = [a.format(config=config_dir / name, ignore=ignore) for a in ARGV_TEMPLATE[1:]]
            argv[name] = [*self.gitleaks.command, "dir", *rest]
        env = minimal_env(tmp, extra={"HOME": str(home), "USERPROFILE": str(home)})
        return argv, cwd, env

    def _plan(self, index: HistoryIndex, run: _Run) -> dict[str, list[tuple[str, str | None]]]:
        """Which blobs are extracted, and with which configs; the rest is reported."""
        budget, plans = self.options.max_extract_bytes, {}
        for sha in sorted(index.blobs):
            size, flags = index.blobs[sha], index.path_flags.get(sha, 0)
            configs = configs_for(flags)
            if size > self.options.max_blob_bytes:
                limit = f"larger than {self.options.max_blob_bytes} bytes"
                run.gaps[("blob", sha)] = (NotAnalyzedReason.SIZE_LIMIT, limit)
                continue
            cost = (size + 64) * len(configs)
            if cost > budget:
                limit = "total extraction limit reached"
                run.gaps[("blob", sha)] = (NotAnalyzedReason.SIZE_LIMIT, limit)
                continue
            budget -= cost
            if not flags & _HAS_PATH:
                run.path_unknown.add(sha)
            plans[sha] = configs
        return plans

    def _extract(self, runner, index, scan_dir: Path, run: _Run, deadline: float):
        """Write each planned blob and commit message (+ end marker) into a chunk folder."""
        plans = self._plan(index, run)
        items: list[_Item] = []
        counters: dict[str, int] = {}

        def place(kind: str, sha: str, data: bytes, config: str, rule: str | None) -> None:
            key = "messages" if kind == "message" else config.removesuffix(".toml")
            number = counters.get(key, 0)
            counters[key] = number + 1
            folder = scan_dir / f"{key}-{number // CHUNK}"
            if number % CHUNK == 0:
                folder.mkdir(mode=PRIVATE_DIR_MODE)
            payload, marker_line = with_end_marker(data, end_marker())
            with open(extended_length_path(str(folder / sha)), "xb") as handle:
                handle.write(payload)
            lines = data.count(b"\n") + 1
            items.append(_Item(kind, sha, config, rule, folder, marker_line, lines,
                               skipped_format(data)))  # fmt: skip

        def on_blob(sha: str, kind: bytes, data: bytes) -> None:
            if kind != b"blob" or sha not in plans:
                raise GitError("unexpected object", "cat-file")
            for config, rule in plans[sha]:
                place("blob", sha, data, config, rule)

        read_objects(runner, sorted(plans), on_blob)
        self._check(deadline)
        dates: dict[str, int | None] = {}

        def on_commit(sha: str, kind: bytes, data: bytes) -> None:
            if kind != b"commit":
                raise GitError("unexpected object", "cat-file")
            timestamp, message = parse_commit(data)
            dates[sha] = timestamp
            if len(message) > self.options.max_blob_bytes:
                limit = f"larger than {self.options.max_blob_bytes} bytes"
                run.gaps[("message", sha)] = (NotAnalyzedReason.SIZE_LIMIT, limit)
                return
            place("message", sha, message, BASE_CONFIG, None)

        read_objects(runner, index.commit_ids, on_commit)
        self._check(deadline)
        return items, dates

    def _scan_items(self, items: list[_Item], argv, cwd, env, run: _Run, deadline) -> None:
        folders: dict[Path, list[_Item]] = {}
        for item in items:
            folders.setdefault(item.folder, []).append(item)
        for folder, chunk in folders.items():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _Timeout
            command = argv[chunk[0].config]
            result = run_tool_stdin(
                [*command[:2], str(folder), *command[2:]],
                data=b"",
                cwd=cwd,
                env=env,
                timeout=remaining,
                stdout_limit=self.options.max_output_bytes,
            )
            if result.exit_code is not None:
                run.exit_codes.add(result.exit_code)
            if result.timed_out:
                raise _Timeout
            self._collect(chunk, result, run)

    @staticmethod
    def _collect(chunk: list[_Item], result, run: _Run) -> None:
        failure, _ = _classify(result)
        reported: dict[str, list[tuple[object, object]]] = {}
        if failure is None:
            try:
                for rule, line, name in _parse(result.stdout):
                    reported.setdefault(name, []).append((rule, line))
            except (ValueError, TypeError, UnicodeDecodeError):
                failure = (NotAnalyzedReason.TOOL_ERROR, "invalid JSON")
        for item in chunk:
            key = (item.kind, item.sha)
            hits = reported.get(item.sha, [])
            if failure is None and (END_MARKER_RULE, item.marker_line) not in hits:
                failure_here = (
                    (NotAnalyzedReason.SKIPPED_BY_TOOL,
                     f"{item.known_skip}: not scanned by Gitleaks (binary format)")
                    if item.known_skip
                    else (NotAnalyzedReason.TOOL_ERROR,
                          "Gitleaks did not confirm reading the whole object (end marker)")
                )  # fmt: skip
            else:
                failure_here = failure
            if failure_here is not None:
                run.gaps[key] = failure_here
                continue
            hits.remove((END_MARKER_RULE, item.marker_line))
            run.confirmed.add(key)
            for rule, line in hits:
                _record(item, rule, line, run)

    @staticmethod
    def _reconcile(index: HistoryIndex, run: _Run) -> None:
        """Every listed blob and commit must end up scanned or reported: nothing silent."""
        listed = [("blob", sha) for sha in index.blobs]
        listed += [("message", sha) for sha in index.commit_ids]
        for key in listed:
            if key not in run.confirmed and key not in run.gaps:
                run.gaps[key] = (
                    NotAnalyzedReason.TOOL_ERROR,
                    "listed but not extracted or not confirmed (reconciliation)",
                )

    def _report(self, runner, info: GitDirInfo, dates, context, run: _Run) -> None:
        wanted = {sha for (kind, sha, _, _) in run.hits if kind == "blob"}
        wanted |= {sha for (kind, sha) in run.gaps if kind == "blob"} | run.path_unknown
        index = index_history(runner, wanted=wanted, with_blobs=False) if wanted else None
        inventory = {f.relative_path: f for f in context.files}
        for (kind, sha, rule, line), configs in sorted(run.hits.items()):
            if (kind, sha) in run.gaps:
                continue  # incompletely scanned object: reported as not analyzed below
            if kind == "message":
                self._message_finding(sha, rule, line, dates, run)
                continue
            # only the paths whose own config reported the result (a path rule never applies
            # to another path of the same content)
            paths = {p for p in (index.paths.get(sha, ()) if index else ())
                     if config_for(p)[0] in configs}  # fmt: skip
            intro = {(c, p) for c, p in (index.introductions.get(sha, ()) if index else ())
                     if p in paths}  # fmt: skip
            still = _still_in_tree(sha, paths, inventory, context.root, info.object_format)
            tag = "path-rule-applied-by-auditor" if rule in _PATH_RULE_NAMES else None
            ids = FindingIdentifiers(git_object=sha, object_format=info.object_format,
                                     history_paths=sorted(paths)[:50])  # fmt: skip
            self._blob_finding(sha, rule, line, tag, intro, dates, still, run, ids)
        for sha in sorted(run.path_unknown - {s for _, s in run.gaps}):
            run.limited.append(LimitedFile(
                relative_path=f"{HISTORY_PATH} [object {sha[:12]}]", reason="GIT_PATH_UNKNOWN",
                detail="path unknown (reachable through a tag only): path-conditioned rules "
                "were not applied"))  # fmt: skip
        gaps = sorted(run.gaps.items())
        for (kind, sha), (reason, detail) in gaps[:MAX_REPORTED_GAPS]:
            paths = index.paths.get(sha, set()) if index and kind == "blob" else set()
            where = _display(min(paths)) if paths else (
                MESSAGE_PATH if kind == "message" else HISTORY_PATH)  # fmt: skip
            run.not_analyzed.append(
                NotAnalyzedFile(
                    relative_path=f"{where} [object {sha[:12]}]", reason=reason, detail=detail
                )
            )
        if len(gaps) > MAX_REPORTED_GAPS:
            run.not_analyzed.append(NotAnalyzedFile(
                relative_path=HISTORY_PATH, reason=NotAnalyzedReason.SIZE_LIMIT,
                detail=f"{len(gaps) - MAX_REPORTED_GAPS} more objects not analyzed (not listed "
                "individually)"))  # fmt: skip

    def _blob_finding(self, sha, rule, line, tag, intro, dates, still, run: _Run,
                      ids=None) -> None:  # fmt: skip
        ordered = sorted(intro, key=lambda cp: (dates.get(cp[0]) or 0, cp[1], cp[0]))
        tags = ["secret", "git-history", *([tag] if tag else [])]
        if still:
            tags.append("still-in-working-tree")
        if not ordered:
            tags.append("attribution-unavailable")
            where, evidence = HISTORY_PATH, [Evidence(kind="git-object", reference=sha[:12])]
            attribution = ("This content is reachable only through a tag: no commit or path is "
                           "attributed, none is guessed.")  # fmt: skip
        else:
            commits, paths = {c for c, _ in ordered}, {p for _, p in ordered}
            if len(commits) > 1 or len(paths) > 1:
                tags.append("multiple-introductions")
            where = _display(ordered[0][1])
            evidence = [
                Evidence(kind="git-introduction",
                         reference=f"{c[:12]} {_date(dates.get(c))} {_display(p)}:{line}",
                         redacted=True)
                for c, p in ordered[:MAX_LISTED]
            ]  # fmt: skip
            more = len(ordered) - MAX_LISTED
            attribution = (f"Introduced by {len(commits)} commit(s) at {len(paths)} path(s), "
                           "verified from the commit trees"
                           + (f"; {more} more introductions not listed" if more > 0 else "")
                           + ".")  # fmt: skip
        description = (f"Gitleaks rule '{rule}' matched line {line} of a file version stored in "
                       f"git history (object {sha[:12]}). {attribution} Commit dates are commit "
                       "metadata. The value is never stored or shown.")  # fmt: skip
        if still:
            description += f" The working tree still holds this exact content at {_display(still)}."
        _add(run, sha, rule, line, where, description, evidence, tags, ids)

    @staticmethod
    def _message_finding(sha, rule, line, dates, run: _Run) -> None:
        evidence = [Evidence(kind="git-commit-message",
                             reference=f"{sha[:12]} {_date(dates.get(sha))} message:{line}",
                             redacted=True)]  # fmt: skip
        description = (
            f"Gitleaks rule '{rule}' matched line {line} of the message of commit "
            f"{sha[:12]}. The message text and the value are never stored or shown. "
            "A commit message cannot be changed without rewriting history."
        )
        tags = ["secret", "git-history", "commit-message"]
        _add(run, sha, rule, line, MESSAGE_PATH, description, evidence, tags)


def _record(item: _Item, rule, line, run: _Run) -> None:
    if not isinstance(rule, str) or not _RULE_ID.match(rule):
        run.warn("A result with an unexpected rule id was dropped.")
        return
    if not isinstance(line, int) or isinstance(line, bool) or not 1 <= line <= item.lines:
        run.warn("A result with an invalid line number was dropped.")
        return
    if rule.startswith(PATHLESS_PREFIX):
        rule = rule.removeprefix(PATHLESS_PREFIX)
        if rule != item.path_rule:  # defensive: copies only where a verified path matches
            run.warn("A path-rule result for a non-matching object was dropped.")
            return
    # the same object scanned with two configs: one finding, attributed per config
    run.hits.setdefault((item.kind, item.sha, rule, line), set()).add(item.config)


def _add(run: _Run, sha, rule, line, where, description, evidence, tags, ids=None) -> None:
    rule_id = RULE_PREFIX + rule
    fingerprint = compute_fingerprint(tool=TOOL, rule_id=rule_id, relative_path=f"git:{sha}",
                                      start=(line, None), end=(line, None),
                                      message="git history")  # fmt: skip
    finding_id, suffix = f"{TOOL}-{fingerprint[:16]}", 2
    while finding_id in run.seen_ids:
        finding_id, suffix = f"{TOOL}-{fingerprint[:16]}-{suffix}", suffix + 1
    run.seen_ids.add(finding_id)
    severity = (Severity.CRITICAL if rule in CRITICAL_RULES
                else Severity.MEDIUM if rule in GENERIC_RULES else Severity.HIGH)  # fmt: skip
    run.findings.append(
        Finding(
            finding_id=finding_id,
            fingerprint=fingerprint,
            source_tool=TOOL,
            rule_id=rule_id,
            title=f"Potential secret in git history ({rule})",
            description=description,
            category=FindingCategory.SECURITY,
            severity=severity,
            confidence=GENERIC_RULES.get(rule, Confidence.HIGH),
            verification_status=VerificationStatus.NEEDS_REVIEW,
            relative_path=where,
            start_line=line,
            evidence=evidence,
            recommendation=RECOMMENDATION,
            tags=tags,
            identifiers=ids or FindingIdentifiers(),
        )
    )


def _still_in_tree(sha, paths, inventory, root: Path, object_format: str) -> str | None:
    """A verified path whose working-tree file is exactly this blob (same git object id)."""
    for path in sorted(paths):
        if path not in inventory:  # only inventory paths (validated by discovery) are opened
            continue
        read = read_regular_file(os.path.join(root, *path.split("/")), 50 * 1024 * 1024)
        if read.data is not None and git_blob_id(read.data, object_format) == sha:
            return path
    return None


def _parse(stdout: bytes) -> list[tuple[object, object, str]]:
    """[(RuleID, StartLine, file name)]; every other key is dropped while parsing."""
    text = stdout.decode("utf-8").strip()
    if not text:
        raise ValueError("no report")
    data = json.loads(text, object_hook=lambda o: {k: o[k] for k in _ALLOWED_KEYS if k in o})
    if not isinstance(data, list) or not all(isinstance(item, dict) for item in data):
        raise TypeError("unexpected report format")
    return [(i.get("RuleID"), i.get("StartLine"), Path(str(i.get("File", ""))).name) for i in data]


def _display(path: str) -> str:
    return sanitize_for_display(path)


def _date(timestamp: int | None) -> str:
    if timestamp is None:
        return "date-unknown"
    return datetime.fromtimestamp(timestamp, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
