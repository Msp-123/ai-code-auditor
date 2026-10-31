"""Semgrep security adapter (Semgrep CE 1.182.1 in a dedicated tool environment).

Behaviour verified against the real engine (Stage 3, step 0) and covered by tests:

- Only the auditor's own, manifest-verified ruleset is used; the verified bytes are copied
  into the private workspace and passed with ``--config``. Target ``.semgrep.yml`` /
  ``.semgrep/`` are never loaded; ``--no-rewrite-rule-ids`` keeps our rule ids intact.
- Files are passed explicitly (absolute paths after ``--``). Verified: explicit targets are
  scanned despite a target ``.semgrepignore`` / ``.gitignore`` or Semgrep's default ignores
  (``tests/``…). As a guard against future behaviour changes, every passed file must appear in
  ``paths.scanned`` or it is reported as not analyzed (``SKIPPED_BY_TOOL``).
- ``--disable-nosem``: ``# nosemgrep`` cannot hide findings. ``--no-git-ignore``: git is not
  called. ``--metrics=off`` / ``--disable-version-check``: application-level offline mode
  (not an OS-level network block).
- HOME/USERPROFILE (where Semgrep writes ``.semgrep/settings.yml``, logs, ``semgrep-mcp``)
  and TEMP point into a short private scratch dir (``%TEMP%\\aca\\r-*``, removed after the
  run), so the real user profile is never written.
- ``semgrep-core`` cannot use long paths: on Windows every mirror target and the working
  directory are passed in ``\\\\?\\`` form, and a scratch dir longer than MAX_TEMP_PATH is
  reported as an ERROR.
- Semgrep only ever reads a private byte-for-byte copy of the files (``m/`` in the scratch
  dir, also its working directory): with any other working directory it walked the whole
  enclosing git repository, outside the target (D-040).
- Source lines (``extra.lines``), metavariable content and fixes are never modelled.
- Semgrep silently recovers from syntax errors; that coverage gap is reconciled by the audit
  service using Ruff's parse results (D-038), not here.
"""

import dataclasses
import os
import re
import stat
import tempfile
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, ValidationError

from auditor.core.errors import TargetPathError
from auditor.core.models import (
    Confidence,
    Evidence,
    FileEntry,
    Finding,
    FindingCategory,
    NotAnalyzedFile,
    NotAnalyzedReason,
    Severity,
    ToolExecution,
    ToolStatus,
    VerificationStatus,
)
from auditor.core.safe_fs import PRIVATE_DIR_MODE, PRIVATE_FILE_MODE, is_link_like
from auditor.discovery.repository import extended_length_path, plain_path
from auditor.findings.fingerprint import compute_fingerprint
from auditor.scanners.base import FlowObservation, ScanContext, ScanOutcome
from auditor.scanners.executables import resolves_inside, semgrep_executable
from auditor.scanners.runner import ProcessResult, minimal_env, run_tool
from auditor.scanners.selection import precheck_files, select_python_files
from auditor.scanners.semgrep_rules import RULES_DIR, RulesetError, load_ruleset, materialize
from auditor.scanners.workspace import PrivateWorkspace

TOOL = "semgrep"
TESTED_VERSION = "1.182.1"
RULE_PREFIX = "auditor."
# H5: results of these rules are data-flow observations (ScanOutcome.observations), never
# findings; they do not count anywhere and the quality gate never sees them.
EVIDENCE_RULE_PREFIX = "auditor.python.flow-evidence."
_EVIDENCE_KINDS = {"param-to-sql-text": "sql_sink", "request-to-call-arg": "request_call"}
# semgrep-core 1.182.1 fails when TEMP/HOME is long (measured on Windows: <=75 chars works,
# >=80 fails). Semgrep therefore gets its own short scratch dir in the user's TEMP
# (%TEMP%\aca\r-xxxxxxxx), and anything longer than this limit is reported as an ERROR.
MAX_TEMP_PATH = 70


def short_temp_base() -> Path:
    """Per-user OS temp dir (private on Windows; mkdtemp dirs are 0700 on POSIX)."""
    return Path(tempfile.gettempdir()) / "aca"


_VERSION = re.compile(r"^\s*(\d+\.\d+\.\d+)\s*$", re.MULTILINE)
_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "ERROR": Severity.HIGH,
    "HIGH": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "INFO": Severity.LOW,
    "LOW": Severity.LOW,
}
_TEXT_LIMIT = 500


@dataclass(frozen=True)
class SemgrepOptions:
    batch_timeout: float = 300.0
    total_timeout: float = 900.0
    rule_timeout_seconds: int = 30  # per rule and file (Semgrep --timeout)
    max_target_bytes: int = 5 * 1024 * 1024
    max_output_bytes: int = 50 * 1024 * 1024
    max_command_chars: int = 30_000
    rules_dir: Path = RULES_DIR
    temp_base: Path | None = None  # None: short_temp_base()


def semgrep_env(workspace: Path) -> dict[str, str]:
    """Minimal environment with every Semgrep home/config/cache location inside ``workspace``."""
    home = workspace / "home"
    home.mkdir(exist_ok=True)
    return minimal_env(
        workspace,
        extra={
            "HOME": str(home),
            "USERPROFILE": str(home),
            "XDG_CONFIG_HOME": str(home / ".config"),
            "XDG_CACHE_HOME": str(home / ".cache"),
            "SEMGREP_SETTINGS_FILE": str(home / "settings.yml"),
            "SEMGREP_LOG_FILE": str(home / "semgrep.log"),
            "SEMGREP_VERSION_CACHE_PATH": str(home / "version_cache"),
            "SEMGREP_ENABLE_VERSION_CHECK": "0",
            "SEMGREP_SEND_METRICS": "off",
            "OTEL_SDK_DISABLED": "true",
            "PYTHONUTF8": "1",
            "PYTHONIOENCODING": "utf-8",
        },
    )


def read_semgrep_version(command: Sequence[str], workspace: Path) -> str | None:
    result = run_tool(
        [*command, "--version"],
        cwd=workspace,
        timeout=120,
        env=semgrep_env(workspace),
        stdout_limit=4096,
    )
    match = _VERSION.search(result.stdout) if result.exit_code == 0 else None
    return match.group(1) if match else None


# --------------------------------------------------------------- Semgrep JSON contract


class _Pos(BaseModel):
    line: int
    col: int


class _Extra(BaseModel):
    model_config = ConfigDict(extra="ignore")  # lines, metavars, fix, ... are never modelled
    message: str
    severity: str | None = None
    metadata: dict[str, Any] = {}


class _Result(BaseModel):
    model_config = ConfigDict(extra="ignore")
    check_id: str
    path: str
    start: _Pos
    end: _Pos
    extra: _Extra


class _Skipped(BaseModel):
    model_config = ConfigDict(extra="ignore")
    path: str
    reason: str | None = None


class _Paths(BaseModel):
    model_config = ConfigDict(extra="ignore")
    scanned: list[str] = []
    skipped: list[_Skipped] = []


class _Error(BaseModel):
    model_config = ConfigDict(extra="ignore")
    level: str | None = None
    type: Any = None
    message: str | None = None
    path: str | None = None


class _Output(BaseModel):
    model_config = ConfigDict(extra="ignore")
    results: list[_Result]
    errors: list[_Error] = []
    paths: _Paths = _Paths()


class _BatchError(Exception):
    pass


def _key(path: str) -> str:
    return os.path.normcase(os.path.normpath(plain_path(path)))


def _text(value: Any) -> str | None:
    return str(value)[:_TEXT_LIMIT] if isinstance(value, str) and value.strip() else None


def _strings(value: Any) -> list[str]:
    items = value if isinstance(value, list) else [value]
    return [str(v)[:_TEXT_LIMIT] for v in items if isinstance(v, str) and v.strip()]


@dataclass
class _Run:
    findings: list[Finding] = field(default_factory=list)
    not_analyzed: dict[str, NotAnalyzedFile] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    exit_codes: list[int] = field(default_factory=list)
    stderr: list[str] = field(default_factory=list)
    timed_out: bool = False
    seen_ids: set[str] = field(default_factory=set)
    observations: list[FlowObservation] = field(default_factory=list)  # H5 evidence, no findings

    def skip(self, entry: FileEntry, reason: NotAnalyzedReason, detail: str | None = None):
        self.not_analyzed.setdefault(
            entry.relative_path,
            NotAnalyzedFile(relative_path=entry.relative_path, reason=reason, detail=detail),
        )

    def warn(self, message: str) -> None:
        if message not in self.warnings:
            self.warnings.append(message)


class SemgrepAdapter:
    name = TOOL

    def __init__(
        self,
        options: SemgrepOptions | None = None,
        command: Sequence[str] | None = None,
        tools_base: Path | None = None,
    ):
        self.options = options or SemgrepOptions()
        if command is None:
            executable = semgrep_executable(tools_base)
            command = [str(executable)] if executable else None
        self.command = list(command) if command else None
        self.settings = {
            "ruleset": "auditor's own versioned rules (package data, manifest-verified)",
            "nosem": "ignored (--disable-nosem)",
            "config_files": "target Semgrep configs never loaded (--config <auditor ruleset>)",
            "gitignore": "not consulted (--no-git-ignore)",
            "network": "metrics off, version check off, local rules only "
            "(application-level; not an OS network block)",
        }

    # -- public ----------------------------------------------------------------------

    def scan(self, context: ScanContext) -> ScanOutcome:
        outcome = self._scan_impl(context)
        applicable = [f.relative_path for f in select_python_files(context.files)]
        return dataclasses.replace(outcome, applicable=applicable)

    def _scan_impl(self, context: ScanContext) -> ScanOutcome:
        started = time.monotonic()
        candidates = select_python_files(context.files)

        def stop(status: ToolStatus, reason: str, version: str | None = None) -> ScanOutcome:
            return ScanOutcome(
                ToolExecution(
                    tool=TOOL,
                    version=version,
                    status=status,
                    reason=reason,
                    duration_seconds=round(time.monotonic() - started, 3),
                    files_requested=len(candidates),
                    settings=self.settings,
                ),
                [],
            )

        if self.command is None:
            return stop(
                ToolStatus.NOT_INSTALLED,
                "Semgrep not found in the auditor's tool environment (<tools>/semgrep)",
            )
        if resolves_inside(Path(self.command[0]), context.root):
            return stop(
                ToolStatus.ERROR,
                "Semgrep executable resolves inside the scan target; refused (untrusted)",
            )
        if not candidates:
            return stop(ToolStatus.SKIPPED, "No Python files in the inventory")
        try:
            ruleset = load_ruleset(self.options.rules_dir)
        except RulesetError as exc:
            return stop(ToolStatus.ERROR, f"Ruleset integrity check failed: {exc}")
        self.settings = {
            **self.settings,
            "ruleset_version": ruleset.version,
            "ruleset_sha256": ruleset.digest,
            "rule_files": str(len(ruleset.files)),
        }
        scratch_space = PrivateWorkspace(
            context.root,
            self.options.temp_base or short_temp_base(),
            prefix="r-",
            component=TOOL,
            contents="copies of scanned source files",
            failures=context.cleanup_failures,
            stale=context.stale_workspaces,
        )
        try:
            with scratch_space as scratch:
                if len(str(scratch)) > MAX_TEMP_PATH:
                    return stop(
                        ToolStatus.ERROR,
                        f"Temporary directory path is too long for Semgrep "
                        f"({len(str(scratch))} > {MAX_TEMP_PATH} characters; semgrep-core "
                        "fails with long TEMP paths on Windows)",
                    )
                return self._scan(context, scratch, ruleset, candidates, started, stop)
        except TargetPathError as exc:
            return stop(ToolStatus.ERROR, f"Semgrep temporary directory refused: {exc}")

    def _scan(self, context, scratch: Path, ruleset, candidates, started, stop) -> ScanOutcome:
        rules_dir = materialize(ruleset, scratch)
        version = read_semgrep_version(self.command, scratch)
        if version is None:
            return stop(ToolStatus.ERROR, "Could not run 'semgrep --version'")

        run = _Run()
        if version != TESTED_VERSION:
            run.warn(
                f"Semgrep {version} differs from the tested version {TESTED_VERSION}; output "
                "format and coverage behaviour may differ."
            )
        passed, changed = precheck_files(context.root, candidates)
        for entry in changed:
            run.skip(entry, NotAnalyzedReason.CHANGED_BEFORE_SCAN)
        mirror = scratch / "m"
        mirror.mkdir(mode=PRIVATE_DIR_MODE)
        # D-040: Semgrep compares targets and cwd lexically. A \\?\ target under a plain cwd
        # counts as "outside" and re-triggers the tree walk (measured: 70 s vs 2 s), so on
        # Windows the cwd and every target use the same extended form.
        targets = [
            (entry, extended_length_path(copy)) for entry, copy in self._mirror(passed, mirror, run)
        ]
        deadline = started + self.options.total_timeout
        for index, batch in enumerate(self._batches(targets)):
            remaining = deadline - time.monotonic()
            if remaining <= 0 or run.timed_out:
                for entry, _ in batch:
                    run.skip(entry, NotAnalyzedReason.TIMED_OUT)
                run.timed_out = True
                continue
            self._run_batch(
                scratch,
                mirror,
                rules_dir,
                index,
                batch,
                min(remaining, self.options.batch_timeout),
                run,
            )

        if run.errors:
            status, reason = ToolStatus.ERROR, "; ".join(dict.fromkeys(run.errors))
        elif run.timed_out:
            status, reason = ToolStatus.TIMED_OUT, "Semgrep did not finish within the time limit"
        else:
            status = ToolStatus.SUCCESS
            analyzed = len(candidates) - len(run.not_analyzed)
            reason = f"Completed; {analyzed} of {len(candidates)} Python files analyzed"
        return ScanOutcome(
            ToolExecution(
                tool=TOOL,
                version=version,
                status=status,
                reason=reason,
                exit_codes=run.exit_codes,
                duration_seconds=round(time.monotonic() - started, 3),
                files_requested=len(candidates),
                files_analyzed=len(candidates) - len(run.not_analyzed),
                not_analyzed=sorted(run.not_analyzed.values(), key=lambda n: n.relative_path),
                settings=self.settings,
                command_summary=(
                    "semgrep scan --config <verified ruleset> --json --metrics=off "
                    "--disable-version-check --disable-nosem --no-git-ignore "
                    f"--no-rewrite-rule-ids --timeout {self.options.rule_timeout_seconds} "
                    f"-- <{len(targets)} files>"
                ),
                stderr_excerpt="\n".join(run.stderr)[:4000] or None,
                warnings=run.warnings,
            ),
            run.findings,
            observations=run.observations,
        )

    # -- steps -----------------------------------------------------------------------

    def _mirror(
        self, passed: list[tuple[FileEntry, str]], mirror: Path, run: _Run
    ) -> list[tuple[FileEntry, str]]:
        """Copy each file's bytes into the private mirror; Semgrep only ever sees the copy.

        Why (D-040): with any working directory other than the scanned folder, Semgrep walks
        the whole enclosing git repository (here: the entire user profile, ~70 s). Running in
        a private mirror keeps Semgrep away from the target and from everything around it.
        The source is identified by lstat before opening and fstat after opening; a file that
        changed in between (e.g. swapped for a link) is not copied.
        """
        copies: list[tuple[FileEntry, str]] = []
        read_flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        for entry, source in passed:
            src = extended_length_path(source)
            try:
                before = os.lstat(src)
                if before.st_size > self.options.max_target_bytes:
                    run.skip(
                        entry,
                        NotAnalyzedReason.SKIPPED_BY_TOOL,
                        f"larger than --max-target-bytes ({self.options.max_target_bytes})",
                    )
                    continue
                descriptor = os.open(src, read_flags)
                try:
                    after = os.fstat(descriptor)
                    same = (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino)
                    if not same or is_link_like(before) or not stat.S_ISREG(after.st_mode):
                        run.skip(entry, NotAnalyzedReason.CHANGED_BEFORE_SCAN)
                        continue
                    with os.fdopen(descriptor, "rb", closefd=False) as handle:
                        data = handle.read(self.options.max_target_bytes + 1)
                finally:
                    os.close(descriptor)
            except OSError:
                run.skip(entry, NotAnalyzedReason.CHANGED_BEFORE_SCAN)
                continue
            copy = os.path.join(str(mirror), *entry.relative_path.split("/"))
            os.makedirs(extended_length_path(os.path.dirname(copy)), mode=0o700, exist_ok=True)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
            out = os.open(extended_length_path(copy), flags, PRIVATE_FILE_MODE)
            with os.fdopen(out, "wb") as handle:
                handle.write(data)
            copies.append((entry, copy))
        return copies

    def _batches(self, targets: list[tuple[FileEntry, str]]):
        batch: list[tuple[FileEntry, str]] = []
        size = 0
        for item in targets:
            length = len(item[1]) + 3
            if batch and size + length > self.options.max_command_chars:
                yield batch
                batch, size = [], 0
            batch.append(item)
            size += length
        if batch:
            yield batch

    def _argv(self, rules_dir: Path, output: Path, paths: list[str]) -> list[str]:
        return [
            *self.command,
            "scan",
            "--config",
            str(rules_dir),
            "--json",
            "--output",
            str(output),
            "--metrics=off",
            "--disable-version-check",
            "--disable-nosem",
            "--no-git-ignore",
            "--no-rewrite-rule-ids",
            "--timeout",
            str(self.options.rule_timeout_seconds),
            "--max-target-bytes",
            str(self.options.max_target_bytes),
            "--",
            *paths,
        ]

    def _run_batch(self, workspace, mirror, rules_dir, index, batch, timeout, run: _Run) -> None:
        output = workspace / f"semgrep-{index}.json"
        result = run_tool(
            self._argv(rules_dir, output, [path for _, path in batch]),
            # D-040: any other cwd makes Semgrep walk the enclosing git repository.
            cwd=Path(extended_length_path(str(mirror))),
            timeout=timeout,
            env=semgrep_env(workspace),
        )
        try:
            data = self._read_output(result, output)
        except _BatchError as exc:
            reason = (
                NotAnalyzedReason.TIMED_OUT if result.timed_out else NotAnalyzedReason.BATCH_FAILED
            )
            for entry, _ in batch:
                run.skip(entry, reason)
            if result.timed_out:
                run.timed_out = True
            else:
                run.errors.append(str(exc))
            if result.stderr.strip():
                run.stderr.append(result.stderr.strip()[-4000:])
            return
        finally:
            try:
                os.remove(output)  # raw output is deleted as soon as it was parsed
            except OSError:
                pass
        run.exit_codes.append(result.exit_code)
        by_path = {_key(path): entry for entry, path in batch}
        self._errors(data.errors, by_path, run)
        self._coverage(data.paths, batch, by_path, run)
        for item in data.results:
            self._map(item, by_path, run)

    def _read_output(self, result: ProcessResult, output: Path) -> _Output:
        if result.launch_error:
            raise _BatchError(f"could not start semgrep ({result.launch_error})")
        if result.timed_out:
            raise _BatchError("timed out")
        if result.exit_code != 0:
            raise _BatchError(f"semgrep failed with exit code {result.exit_code}")
        if not output.is_file():
            raise _BatchError("semgrep produced no output file")
        if output.stat().st_size > self.options.max_output_bytes:
            raise _BatchError("semgrep output too large")
        try:
            text = output.read_bytes().decode("utf-8")
        except UnicodeDecodeError as exc:
            raise _BatchError("semgrep output is not valid UTF-8") from exc
        try:
            return _Output.model_validate_json(text)
        except ValidationError as exc:
            kind = "invalid JSON" if "json_invalid" in str(exc) else "unexpected output format"
            raise _BatchError(f"semgrep output has {kind}") from exc

    def _errors(self, errors: list[_Error], by_path: dict[str, FileEntry], run: _Run) -> None:
        for error in errors:
            kind = str(error.type)
            entry = by_path.get(_key(error.path)) if error.path else None
            if entry is not None:
                if "timeout" in kind.lower():
                    reason = NotAnalyzedReason.TIMED_OUT
                elif any(w in kind.lower() for w in ("syntax", "parse", "lexical")):
                    reason = NotAnalyzedReason.PARSE_ERROR
                else:
                    reason = NotAnalyzedReason.TOOL_ERROR
                run.skip(entry, reason, _text(error.message) or kind[:_TEXT_LIMIT])
            elif (error.level or "error").lower() == "error":
                run.errors.append(f"semgrep reported an error: {kind[:200]}")
            else:
                run.warn(f"Semgrep warning: {kind[:200]}")

    def _coverage(self, paths: _Paths, batch, by_path, run: _Run) -> None:
        scanned = {_key(p) for p in paths.scanned}
        skipped = {_key(s.path): s.reason for s in paths.skipped}
        for entry, path in batch:
            key = _key(path)
            if key in scanned:
                continue
            reason = skipped.get(key)
            detail = f"Semgrep skipped the file ({reason})" if reason else "not in paths.scanned"
            run.skip(entry, NotAnalyzedReason.SKIPPED_BY_TOOL, detail)

    def _map(self, item: _Result, by_path: dict[str, FileEntry], run: _Run) -> None:
        if not item.check_id.startswith(RULE_PREFIX):
            run.warn("Dropped a Semgrep result from an unknown rule (not the auditor ruleset).")
            return
        entry = by_path.get(_key(item.path))
        if entry is None:
            run.warn("Dropped a Semgrep result for an unexpected path (not a file we passed).")
            return
        if item.check_id.startswith(EVIDENCE_RULE_PREFIX):
            suffix = item.check_id.removeprefix(EVIDENCE_RULE_PREFIX)
            kind = _EVIDENCE_KINDS.get(suffix)
            if kind and item.start.line and item.start.col:  # location only, never the text
                run.observations.append(
                    FlowObservation(
                        kind, entry.relative_path, item.start.line, item.start.col, suffix
                    )
                )
            return
        meta = item.extra.metadata
        severity = _SEVERITY.get(str(meta.get("auditor_severity", "")).upper()) or _SEVERITY.get(
            (item.extra.severity or "").upper(), Severity.INFO
        )
        confidence_text = str(meta.get("confidence", "")).upper()
        confidence = (
            Confidence(confidence_text)
            if confidence_text in Confidence.__members__
            else Confidence.LOW
        )
        start = (item.start.line or None, item.start.col or None)
        end = (item.end.line or None, item.end.col or None)
        fingerprint = compute_fingerprint(
            tool=TOOL,
            rule_id=item.check_id,
            relative_path=entry.relative_path,
            start=start,
            end=end,
            message=item.extra.message,
        )
        finding_id = f"{TOOL}-{fingerprint[:16]}"
        suffix = 2
        while finding_id in run.seen_ids:
            finding_id = f"{TOOL}-{fingerprint[:16]}-{suffix}"
            suffix += 1
        run.seen_ids.add(finding_id)
        run.findings.append(
            Finding(
                finding_id=finding_id,
                fingerprint=fingerprint,
                source_tool=TOOL,
                rule_id=item.check_id,
                title=item.check_id.rsplit(".", 1)[-1],
                description=item.extra.message.strip()[:_TEXT_LIMIT],
                category=FindingCategory.SECURITY,
                severity=severity,
                original_severity=item.extra.severity,
                confidence=confidence,
                verification_status=VerificationStatus.NEEDS_REVIEW,
                relative_path=entry.relative_path,
                start_line=start[0],
                start_column=start[1],
                end_line=end[0],
                end_column=end[1],
                evidence=[
                    Evidence(
                        kind="scanner_location",
                        reference=f"{entry.relative_path}:{start[0]}",
                    )
                ],
                recommendation=_text(meta.get("auditor_recommendation")),
                references=[
                    r for r in _strings(meta.get("references")) if r.startswith("https://")
                ],
                tags=_strings(meta.get("cwe")) + _strings(meta.get("owasp")),
            )
        )
