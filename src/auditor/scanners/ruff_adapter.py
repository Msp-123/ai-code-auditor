"""Ruff code-quality adapter.

Security properties (each covered by tests):

- Only the ``ruff`` executable of the auditor's *own* Python environment is used — never a
  PATH lookup, never an executable from the target.
- ``--isolated`` ignores every configuration file in the target (``pyproject.toml``,
  ``ruff.toml``…), so a target cannot ``extend`` files outside the root, disable rules,
  exclude files or relocate the cache. ``--no-cache`` keeps Ruff from writing
  ``.ruff_cache`` into the target. ``--ignore-noqa`` stops ``# noqa`` from hiding findings.
- Files are passed explicitly from the discovery inventory, after ``--`` and as absolute
  paths, so names like ``-h.py`` cannot become options and the scope is exactly discovery's.
- Raw JSON output lives in the private workspace only; fix edits (code text) are never kept.
"""

import dataclasses
import os
import re
import sysconfig
import time
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import BaseModel, ConfigDict, TypeAdapter, ValidationError

from auditor.core.models import (
    Confidence,
    Evidence,
    FileCategory,
    FileEntry,
    Finding,
    FindingCategory,
    NotAnalyzedFile,
    NotAnalyzedReason,
    Severity,
    SuppressedFindings,
    ToolExecution,
    ToolStatus,
    VerificationStatus,
)
from auditor.discovery.repository import plain_path
from auditor.findings.fingerprint import compute_fingerprint
from auditor.scanners.base import ScanContext, ScanOutcome
from auditor.scanners.executables import trust_note
from auditor.scanners.runner import ProcessResult, minimal_env, run_tool
from auditor.scanners.selection import PYTHON_SUFFIXES, precheck_files, select_python_files

__all__ = ["PYTHON_SUFFIXES", "RuffAdapter", "RuffOptions", "select_python_files"]

TOOL = "ruff"
RULES = ("E4", "E7", "E9", "F", "B", "S", "C901")
SUPPORTED_PYTHON = tuple(f"3.{minor}" for minor in range(7, 16))
DEFAULT_TARGET_PYTHON = "3.12"
# Rules not reported for test files (FileCategory.TEST): pytest relies on plain `assert`.
# S101 stays active for all other code; every suppression is counted in the report.
TEST_FILE_SUPPRESSIONS = {"S101": "assert in test files (pytest uses assert by design)"}
TRUSTED_DOC_PREFIX = "https://docs.astral.sh/ruff/"
_VERSION = re.compile(r"\bruff (\d+\.\d+\.\d+)\b")
_VERSION_GATED = re.compile(r"\(syntax was (?:added|removed) in Python \d+\.\d+\)|^Cannot use ")
_HIGH_RISK_SECURITY = frozenset({"S102", "S301", "S307", "S506", "S602", "S604", "S605"})
_CORRECTNESS_PYFLAKES = frozenset({"F811", "F821", "F822", "F823"})


@dataclass(frozen=True)
class RuffOptions:
    target_python: str | None = None  # None: DEFAULT_TARGET_PYTHON is assumed and reported
    batch_timeout: float = 120.0
    total_timeout: float = 600.0
    max_output_bytes: int = 50 * 1024 * 1024
    max_command_chars: int = 30_000  # Windows CreateProcess limit is 32,767


@dataclass(frozen=True)
class RuleInfo:
    severity: Severity
    category: FindingCategory
    confidence: Confidence


def to_ruff_target(version: str) -> str:
    if version not in SUPPORTED_PYTHON:
        raise ValueError(
            f"Unsupported target Python {version!r}; choose one of {', '.join(SUPPORTED_PYTHON)}"
        )
    return "py3" + version.split(".")[1]


def classify_rule(code: str) -> RuleInfo:
    """Severity / category mapping (Ruff itself reports every diagnostic as "error")."""
    if code == "invalid-syntax" or re.fullmatch(r"E9\d\d", code):
        return RuleInfo(Severity.HIGH, FindingCategory.CORRECTNESS, Confidence.HIGH)
    if re.fullmatch(r"S\d{3}", code):
        if code == "S101":
            return RuleInfo(Severity.LOW, FindingCategory.SECURITY, Confidence.MEDIUM)
        severity = Severity.HIGH if code in _HIGH_RISK_SECURITY else Severity.MEDIUM
        return RuleInfo(severity, FindingCategory.SECURITY, Confidence.MEDIUM)
    if re.fullmatch(r"F\d{3}", code):
        if code in _CORRECTNESS_PYFLAKES:
            return RuleInfo(Severity.MEDIUM, FindingCategory.CORRECTNESS, Confidence.HIGH)
        return RuleInfo(Severity.LOW, FindingCategory.MAINTAINABILITY, Confidence.HIGH)
    if re.fullmatch(r"B\d{3}", code):
        return RuleInfo(Severity.MEDIUM, FindingCategory.CORRECTNESS, Confidence.MEDIUM)
    if re.fullmatch(r"E[47]\d\d", code):
        return RuleInfo(Severity.LOW, FindingCategory.STYLE, Confidence.HIGH)
    if code == "C901":
        return RuleInfo(Severity.LOW, FindingCategory.MAINTAINABILITY, Confidence.MEDIUM)
    return RuleInfo(Severity.INFO, FindingCategory.OTHER, Confidence.LOW)


def read_version(command: Sequence[str], workspace: Path) -> str | None:
    result = run_tool(
        [*command, "--version"],
        cwd=workspace,
        timeout=30,
        env=minimal_env(workspace),
        stdout_limit=4096,
    )
    match = _VERSION.search(result.stdout) if result.exit_code == 0 else None
    return match.group(1) if match else None


def executable_trust_note(executable: Path, root: Path) -> str | None:
    """Trust-assumption note when the auditor's own environment lies inside the target."""
    return trust_note(executable, root)


def find_ruff_executable() -> Path | None:
    """The ruff binary installed next to the running interpreter — nothing else."""
    scripts = sysconfig.get_path("scripts")
    if not scripts:
        return None
    candidate = Path(scripts) / ("ruff.exe" if os.name == "nt" else "ruff")
    return candidate if candidate.is_file() else None


# ------------------------------------------------------------------- Ruff JSON contract


class _Loc(BaseModel):
    row: int
    column: int


class _Fix(BaseModel):
    message: str | None = None  # edits (code text) are intentionally not modelled


class _Diagnostic(BaseModel):
    model_config = ConfigDict(extra="ignore")
    code: str | None
    name: str | None = None
    message: str
    filename: str
    location: _Loc | None = None
    end_location: _Loc | None = None
    fix: _Fix | None = None
    url: str | None = None
    severity: str | None = None


_DIAGNOSTICS = TypeAdapter(list[_Diagnostic])


class _BatchError(Exception):
    pass


def _positive(value: int | None) -> int | None:
    return value if value and value > 0 else None


@dataclass
class _Run:
    """Mutable state of one adapter run."""

    root: Path
    findings: list[Finding] = field(default_factory=list)
    not_analyzed: dict[str, NotAnalyzedFile] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    exit_codes: list[int] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    timed_out: bool = False
    stderr: list[str] = field(default_factory=list)
    seen_ids: set[str] = field(default_factory=set)
    suppressed: Counter[str] = field(default_factory=Counter)

    def skip(self, entry: FileEntry, reason: NotAnalyzedReason, detail: str | None = None):
        self.not_analyzed.setdefault(
            entry.relative_path,
            NotAnalyzedFile(relative_path=entry.relative_path, reason=reason, detail=detail),
        )


class RuffAdapter:
    name = TOOL

    def __init__(self, options: RuffOptions | None = None, command: Sequence[str] | None = None):
        self.options = options or RuffOptions()
        if command is None:
            executable = find_ruff_executable()
            command = [str(executable)] if executable else None
        self.command = list(command) if command else None
        target = self.options.target_python or DEFAULT_TARGET_PYTHON
        self.ruff_target = to_ruff_target(target)
        self.settings = {
            "target_python": target,
            "target_python_source": "--target-python"
            if self.options.target_python
            else "default (assumed)",
            "rules": ",".join(RULES),
            "ignore_noqa": "true",
            "config_files": "ignored (--isolated)",
            "cache": "disabled (--no-cache)",
        }

    # -- public ----------------------------------------------------------------------

    def scan(self, context: ScanContext) -> ScanOutcome:
        outcome = self._scan_impl(context)
        applicable = [f.relative_path for f in select_python_files(context.files)]
        return dataclasses.replace(outcome, applicable=applicable)

    def _scan_impl(self, context: ScanContext) -> ScanOutcome:
        started = time.monotonic()
        candidates = select_python_files(context.files)
        if self.command is None:
            return self._outcome(
                ToolStatus.NOT_INSTALLED,
                "Ruff executable not found in the auditor's environment",
                started,
                requested=len(candidates),
            )
        if not candidates:
            return self._outcome(
                ToolStatus.SKIPPED, "No Python files in the inventory", started, requested=0
            )

        version = read_version(self.command, context.workspace)
        if version is None:
            return self._outcome(
                ToolStatus.ERROR, "Could not run 'ruff --version'", started, len(candidates)
            )

        run = _Run(root=context.root)
        trust_note = executable_trust_note(Path(self.command[0]), context.root)
        if trust_note:
            run.warnings.append(trust_note)
        passed = self._precheck(context.root, candidates, run)
        deadline = started + self.options.total_timeout
        for index, batch in enumerate(self._batches(passed)):
            remaining = deadline - time.monotonic()
            if remaining <= 0 or run.timed_out:
                for entry, _ in batch:
                    run.skip(entry, NotAnalyzedReason.TIMED_OUT)
                run.timed_out = True
                continue
            self._run_batch(
                context.workspace, index, batch, min(remaining, self.options.batch_timeout), run
            )

        if run.errors:
            status, reason = ToolStatus.ERROR, "; ".join(dict.fromkeys(run.errors))
        elif run.timed_out:
            status, reason = ToolStatus.TIMED_OUT, "Ruff did not finish within the time limit"
        else:
            status = ToolStatus.SUCCESS
            analyzed = len(candidates) - len(run.not_analyzed)
            reason = f"Completed; {analyzed} of {len(candidates)} Python files analyzed"
        # On ERROR / TIMED_OUT, findings from batches that did succeed are kept; the status
        # (and the not_analyzed list) tells readers that coverage is incomplete.
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
                command_summary=self._summary(len(passed)),
                stderr_excerpt="\n".join(run.stderr)[:4000] or None,
                warnings=run.warnings,
                suppressed=[
                    SuppressedFindings(
                        rule_id=rule, reason=TEST_FILE_SUPPRESSIONS[rule], count=count
                    )
                    for rule, count in sorted(run.suppressed.items())
                ],
            ),
            run.findings,
        )

    # -- steps -----------------------------------------------------------------------

    def _outcome(
        self, status: ToolStatus, reason: str, started: float, requested: int
    ) -> ScanOutcome:
        return ScanOutcome(
            ToolExecution(
                tool=TOOL,
                version=None,
                status=status,
                reason=reason,
                duration_seconds=round(time.monotonic() - started, 3),
                files_requested=requested,
                settings=self.settings,
            ),
            [],
        )

    def _precheck(
        self, root: Path, candidates: list[FileEntry], run: _Run
    ) -> list[tuple[FileEntry, str]]:
        """Re-check right before running: still a regular file, not a link (TOCTOU guard).

        Ruff accepts plain paths beyond MAX_PATH itself, so plain paths are passed.
        """
        passed, changed = precheck_files(root, candidates)
        for entry in changed:
            run.skip(entry, NotAnalyzedReason.CHANGED_BEFORE_SCAN)
        return passed

    def _batches(self, passed: list[tuple[FileEntry, str]]):
        batch: list[tuple[FileEntry, str]] = []
        size = 0
        for item in passed:
            length = len(item[1]) + 3
            if batch and size + length > self.options.max_command_chars:
                yield batch
                batch, size = [], 0
            batch.append(item)
            size += length
        if batch:
            yield batch

    def _argv(self, output_file: Path, paths: list[str]) -> list[str]:
        return [
            *self.command,
            "check",
            "--isolated",
            "--no-cache",
            "--ignore-noqa",
            "--output-format",
            "json",
            "--output-file",
            str(output_file),
            "--select",
            ",".join(RULES),
            "--target-version",
            self.ruff_target,
            "--",
            *paths,
        ]

    def _summary(self, file_count: int) -> str:
        return (
            f"ruff check --isolated --no-cache --ignore-noqa --output-format json "
            f"--select {','.join(RULES)} --target-version {self.ruff_target} "
            f"-- <{file_count} files>"
        )

    def _run_batch(self, workspace, index, batch, timeout, run: _Run) -> None:
        output = workspace / f"ruff-{index}.json"
        result = run_tool(
            self._argv(output, [path for _, path in batch]),
            cwd=workspace,
            timeout=timeout,
            env=minimal_env(workspace),
        )
        try:
            diagnostics = self._read_output(result, output)
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
                run.stderr.append(result.stderr.strip())
            return
        finally:
            try:
                os.remove(output)  # raw output is deleted as soon as it was parsed
            except OSError:
                pass
        run.exit_codes.append(result.exit_code)
        by_path = {os.path.normcase(os.path.normpath(path)): entry for entry, path in batch}
        for diagnostic in diagnostics:
            self._map(diagnostic, by_path, run)

    def _read_output(self, result: ProcessResult, output: Path) -> list[_Diagnostic]:
        if result.launch_error:
            raise _BatchError(f"could not start ruff ({result.launch_error})")
        if result.timed_out:
            raise _BatchError("timed out")
        if result.exit_code not in (0, 1):
            raise _BatchError(f"ruff failed with exit code {result.exit_code}")
        if not output.is_file():
            raise _BatchError("ruff produced no output file")
        if output.stat().st_size > self.options.max_output_bytes:
            raise _BatchError("ruff output too large")
        try:
            text = output.read_bytes().decode("utf-8")
        except UnicodeDecodeError as exc:
            raise _BatchError("ruff output is not valid UTF-8") from exc
        try:
            return _DIAGNOSTICS.validate_json(text)
        except ValidationError as exc:
            kind = "invalid JSON" if "json_invalid" in str(exc) else "unexpected output format"
            raise _BatchError(f"ruff output has {kind}") from exc

    def _map(self, d: _Diagnostic, by_path: dict[str, FileEntry], run: _Run) -> None:
        entry = by_path.get(os.path.normcase(os.path.normpath(plain_path(d.filename))))
        if entry is None:
            run.warnings.append(
                "Dropped a Ruff diagnostic for an unexpected path (not a file we passed)."
            )
            return
        code = d.code or "invalid-syntax"
        if code == "E902" or d.name == "io-error":
            run.skip(entry, NotAnalyzedReason.IO_ERROR, d.message)
            return
        if code in TEST_FILE_SUPPRESSIONS and entry.category is FileCategory.TEST:
            run.suppressed[code] += 1
            return

        info = classify_rule(code)
        if code == "invalid-syntax":
            if _VERSION_GATED.search(d.message):
                info = RuleInfo(Severity.MEDIUM, FindingCategory.COMPATIBILITY, Confidence.HIGH)
            else:
                # Ruff runs no other rule on a file it cannot parse: it was not analyzed.
                run.skip(entry, NotAnalyzedReason.PARSE_ERROR, "file could not be parsed")

        start = (
            (_positive(d.location.row), _positive(d.location.column))
            if d.location
            else (None, None)
        )
        end = (
            (_positive(d.end_location.row), _positive(d.end_location.column))
            if d.end_location
            else (None, None)
        )
        fingerprint = compute_fingerprint(
            tool=TOOL,
            rule_id=code,
            relative_path=entry.relative_path,
            start=start,
            end=end,
            message=d.message,
        )
        finding_id = f"{TOOL}-{fingerprint[:16]}"
        suffix = 2
        while finding_id in run.seen_ids:
            finding_id = f"{TOOL}-{fingerprint[:16]}-{suffix}"
            suffix += 1
        run.seen_ids.add(finding_id)
        location = entry.relative_path + (f":{start[0]}" if start[0] else "")
        run.findings.append(
            Finding(
                finding_id=finding_id,
                fingerprint=fingerprint,
                source_tool=TOOL,
                rule_id=code,
                title=d.name or code,
                description=d.message,
                category=info.category,
                severity=info.severity,
                original_severity=d.severity,
                confidence=info.confidence,
                verification_status=VerificationStatus.NEEDS_REVIEW,
                relative_path=entry.relative_path,
                start_line=start[0],
                start_column=start[1],
                end_line=end[0],
                end_column=end[1],
                evidence=[Evidence(kind="scanner_location", reference=location)],
                recommendation=d.fix.message if d.fix else None,
                fix_available=d.fix is not None,
                references=[d.url] if d.url and d.url.startswith(TRUSTED_DOC_PREFIX) else [],
            )
        )
