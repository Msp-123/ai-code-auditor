"""Application service: orchestrates validation, discovery, scanners and report output."""

import dataclasses
import os
import secrets
import time
from collections.abc import Callable, Collection, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from auditor.application.report_builder import build_audit_report
from auditor.core.audit_report import AuditReport, Permissions
from auditor.core.config import default_reports_base
from auditor.core.models import (
    SEVERITY_RANK,
    CoverageStatus,
    FileCoverage,
    FindingsReport,
    IncompleteReason,
    LimitedFile,
    LimitsSummary,
    NotAnalyzedReason,
    OperationalError,
    OperationalErrorCode,
    RepositoryInventory,
    ScannerCoverage,
    ScanStatus,
    ToolCoverage,
    ToolExecution,
    ToolStatus,
    VerificationStatus,
)
from auditor.core.policy import ScanPolicy
from auditor.discovery.repository import (
    DiscoveryResult,
    inspect,
    target_is_link,
    validate_output_dir,
    validate_target,
)
from auditor.findings.flow_verification import apply_flow_evidence
from auditor.findings.gate import GatePolicy
from auditor.reports.writer import ReportPaths, count_incomplete_dirs, write_reports
from auditor.scanners.base import ScanContext, ScannerAdapter, ScanOutcome
from auditor.scanners.git_history_adapter import GitHistoryAdapter, GitHistoryOptions
from auditor.scanners.gitleaks_adapter import GitleaksAdapter, GitleaksOptions
from auditor.scanners.pip_audit_adapter import PipAuditAdapter, PipAuditOptions
from auditor.scanners.ruff_adapter import RuffAdapter, RuffOptions
from auditor.scanners.semgrep_adapter import SemgrepAdapter, SemgrepOptions
from auditor.scanners.workspace import (
    STALE_AFTER_SECONDS,
    CleanupFailure,
    PrivateWorkspace,
    StaleWorkspaces,
)

# Scanners of later stages: reported honestly as not run.
PLANNED_SCANNERS = (
    ("ruff", 2),
    ("semgrep", 3),
    ("gitleaks", 4),
    ("pip-audit", 5),
)

_STATUS_REASON = {
    ToolStatus.NOT_INSTALLED: IncompleteReason.SCANNER_NOT_INSTALLED,
    ToolStatus.ERROR: IncompleteReason.SCANNER_ERROR,
    ToolStatus.TIMED_OUT: IncompleteReason.SCANNER_TIMED_OUT,
}
_RAN = (ToolStatus.SUCCESS, ToolStatus.ERROR, ToolStatus.TIMED_OUT)
IMPLEMENTED_SCANNERS = ("ruff", "semgrep", "gitleaks", "pip-audit")
SYNTAX_LIMITATION = "SYNTAX_ERROR_RECOVERY"


@dataclass(frozen=True)
class DiscoveryRun:
    inventory: RepositoryInventory
    reports: ReportPaths
    audit: AuditReport  # the canonical report (report.json)


@dataclass(frozen=True)
class AuditRun:
    inventory: RepositoryInventory
    findings: FindingsReport
    reports: ReportPaths
    audit: AuditReport  # the canonical report (report.json)


def _incomplete_reports_warning(base_dir: Path) -> list[OperationalError]:
    """G3: staging directories of earlier failed report writes are reported, never deleted."""
    count = count_incomplete_dirs(base_dir)
    if not count:
        return []
    noun = "directory" if count == 1 else "directories"
    return [
        OperationalError(
            code=OperationalErrorCode.INCOMPLETE_REPORTS_FOUND,
            component="reports",
            workspace=".<run_id>.incomplete",
            message=f"{count} incomplete report {noun} of earlier runs found in the report "
            "directory. They are not valid reports (no integrity record) and are never "
            "deleted automatically; remove them by hand after checking.",
        )
    ]


def new_run_id(now: datetime) -> str:
    return f"{now.strftime('%Y%m%dT%H%M%SZ')}-{secrets.token_hex(3)}"


def _build_inventory(
    target: str | os.PathLike[str],
    root: Path,
    policy: ScanPolicy,
    result: DiscoveryResult,
    started: datetime,
    finished: datetime,
    scanners: list[ToolCoverage],
    extra_warnings: Sequence[str] = (),
) -> RepositoryInventory:
    warnings = list(result.warnings) + list(extra_warnings)
    if target_is_link(target):
        warnings.insert(
            0, "The target path is a link or junction; its resolved location was scanned."
        )
    return RepositoryInventory(
        run_id=new_run_id(started),
        started_at=started,
        finished_at=finished,
        root_name=root.name or root.anchor,
        status=ScanStatus.PARTIAL if result.incomplete_reasons else ScanStatus.COMPLETE,
        incomplete_reasons=result.incomplete_reasons,
        vcs_metadata=result.vcs_metadata,
        entries_visited=result.entries_visited,
        unvisited_directories=result.unvisited_directories,
        limits=LimitsSummary(
            max_files=policy.max_files,
            max_entries_visited=policy.max_entries_visited,
            max_depth=policy.max_depth,
            max_file_size_bytes=policy.max_file_size_bytes,
            max_duration_seconds=policy.max_duration_seconds,
        ),
        files=result.files,
        excluded=result.excluded,
        scanners=scanners,
        warnings=warnings,
    )


def _coverage(executions: Sequence[ToolExecution], discovery_only: bool) -> list[ToolCoverage]:
    by_tool = {e.tool: e for e in executions}
    coverage = []
    for tool, stage in PLANNED_SCANNERS:
        if tool in by_tool:
            e = by_tool[tool]
            coverage.append(ToolCoverage(tool=tool, status=e.status, reason=e.reason))
        elif discovery_only and tool in IMPLEMENTED_SCANNERS:
            coverage.append(
                ToolCoverage(
                    tool=tool, status=ToolStatus.SKIPPED, reason="Not run (discovery only)"
                )
            )
        else:
            coverage.append(
                ToolCoverage(
                    tool=tool,
                    status=ToolStatus.SKIPPED,
                    reason=f"Not implemented yet (Stage {stage})",
                )
            )
    return coverage


def run_discovery(
    target: str | os.PathLike[str],
    output_dir: str | os.PathLike[str] | None = None,
    policy: ScanPolicy | None = None,
    *,
    clock: Callable[[], float] = time.monotonic,
) -> DiscoveryRun:
    """Validate inputs, inventory the target read-only and write reports outside it."""
    policy = policy or ScanPolicy()
    root = validate_target(target)
    base_dir = validate_output_dir(
        default_reports_base() if output_dir is None else output_dir, root
    )
    started = datetime.now(UTC)
    result = inspect(root, policy, clock=clock)
    inventory = _build_inventory(
        target, root, policy, result, started, datetime.now(UTC), _coverage([], True)
    )
    audit = build_audit_report(
        mode="discovery",
        inventory=inventory,
        permissions=Permissions(network=False, git_history=False, disabled_scanners=[]),
        status=inventory.status,
        incomplete_reasons=inventory.incomplete_reasons,
        operational_warnings=_incomplete_reports_warning(base_dir),
    )
    return DiscoveryRun(inventory, write_reports(audit, base_dir, root), audit)


def _safe_scan(adapter: ScannerAdapter, context: ScanContext) -> ScanOutcome:
    """An adapter bug must surface as ERROR, never as a silently clean result.

    Scanner output is evidence to review: a finding an adapter marks CONFIRMED is downgraded
    to NEEDS_REVIEW (confirmation is reserved for a separate, independent verification step).
    """
    try:
        outcome = adapter.scan(context)
    except Exception as exc:
        return ScanOutcome(
            ToolExecution(
                tool=adapter.name,
                version=None,
                status=ToolStatus.ERROR,
                reason=f"Internal adapter error ({type(exc).__name__})",
            ),
            [],
        )
    confirmed = [
        f for f in outcome.findings if f.verification_status is VerificationStatus.CONFIRMED
    ]
    if not confirmed:
        return outcome
    findings = [
        f.model_copy(update={"verification_status": VerificationStatus.NEEDS_REVIEW})
        if f.verification_status is VerificationStatus.CONFIRMED
        else f
        for f in outcome.findings
    ]
    warning = (
        f"{len(confirmed)} finding(s) marked CONFIRMED by the scanner were downgraded to "
        "NEEDS_REVIEW: scanner output is never accepted as confirmed."
    )
    execution = outcome.execution.model_copy(
        update={"warnings": [*outcome.execution.warnings, warning]}
    )
    return dataclasses.replace(outcome, execution=execution, findings=findings)


def _note_flow_verification(executions: list[ToolExecution], verified: int) -> list[ToolExecution]:
    """Record on the Semgrep execution how many SQL locations the data-flow proof upgraded."""
    note = (
        f"{verified} SQL location(s) verified request -> call -> parameter -> SQL text and "
        "raised to HIGH; the two flow-evidence rules are observations, never findings"
    )
    return [
        e.model_copy(update={"settings": {**e.settings, "data_flow_verification": note}})
        if e.tool == "semgrep"
        else e
        for e in executions
    ]


def _disabled(name: str) -> ScanOutcome:
    return ScanOutcome(
        ToolExecution(
            tool=name,
            version=None,
            status=ToolStatus.SKIPPED,
            reason=f"Disabled by user (--disable-scanner {name}): this run has no {name} coverage",
            settings={"disabled_by_user": "true"},
        ),
        [],
    )


def _reconcile_parse_coverage(outcomes: list[ScanOutcome]) -> list[ScanOutcome]:
    """Ç1 / D-038: Semgrep silently uses error-tolerant parsing on unparsable files.

    Files Ruff could not parse but Semgrep reports as scanned are marked
    SCANNED_WITH_LIMITATIONS for Semgrep. Semgrep's findings are kept. This is a coverage
    *warning*, not a guarantee that Semgrep analysed every other file completely.
    """
    by_tool = {o.execution.tool: i for i, o in enumerate(outcomes)}
    if "semgrep" not in by_tool:
        return outcomes
    semgrep = outcomes[by_tool["semgrep"]]
    sg = semgrep.execution
    if sg.status not in _RAN or sg.files_analyzed == 0:
        return outcomes
    ruff = outcomes[by_tool["ruff"]].execution if "ruff" in by_tool else None
    parse_errors = (
        {n.relative_path for n in ruff.not_analyzed if n.reason is NotAnalyzedReason.PARSE_ERROR}
        if ruff is not None
        else set()
    )
    not_scanned = {n.relative_path for n in sg.not_analyzed}
    applicable = set(semgrep.applicable or [])
    limited = [
        LimitedFile(
            relative_path=path,
            reason=SYNTAX_LIMITATION,
            detail="Ruff could not parse this file; Semgrep used error-tolerant parsing, so "
            "parts of the file may not have been analyzed.",
        )
        for path in sorted(parse_errors - not_scanned)
        if not applicable or path in applicable
    ]
    warnings = list(sg.warnings)
    if ruff is None or ruff.status is not ToolStatus.SUCCESS:
        state = "not run" if ruff is None else ruff.status.value
        warnings.append(
            f"Syntax status of the scanned files could not be independently verified (Ruff: "
            f"{state}). Semgrep silently uses error-tolerant parsing on unparsable files, so "
            "its coverage of such files is unknown."
        )
    updated = sg.model_copy(update={"coverage_limitations": limited, "warnings": warnings})
    result = list(outcomes)
    result[by_tool["semgrep"]] = dataclasses.replace(semgrep, execution=updated)
    return result


def _file_coverage(files, outcomes: list[ScanOutcome]) -> list[FileCoverage]:
    rows = []
    for entry in files:
        path = entry.relative_path
        states: dict[str, ScannerCoverage] = {}
        for outcome in outcomes:
            e = outcome.execution
            not_analyzed = {n.relative_path: n.reason.value for n in e.not_analyzed}
            limited = {item.relative_path: item.reason for item in e.coverage_limitations}
            if outcome.applicable is not None and path not in outcome.applicable:
                state = ScannerCoverage(status=CoverageStatus.NOT_APPLICABLE)
            elif e.status not in _RAN:
                state = ScannerCoverage(status=CoverageStatus.NOT_RUN, reason=e.status.value)
            elif path in not_analyzed:
                state = ScannerCoverage(
                    status=CoverageStatus.NOT_ANALYZED, reason=not_analyzed[path]
                )
            elif e.files_analyzed == 0:  # the tool failed before analysing anything
                state = ScannerCoverage(status=CoverageStatus.NOT_RUN, reason=e.status.value)
            elif path in limited:
                state = ScannerCoverage(
                    status=CoverageStatus.SCANNED_WITH_LIMITATIONS, reason=limited[path]
                )
            else:
                state = ScannerCoverage(status=CoverageStatus.SCANNED)
            states[e.tool] = state
        rows.append(FileCoverage(relative_path=path, scanners=states))
    return rows


def _cleanup_error(failure: CleanupFailure) -> OperationalError:
    return OperationalError(
        code=OperationalErrorCode.CLEANUP_FAILED,
        component=failure.component,
        workspace=failure.workspace,
        message=(
            f"Temporary {failure.contents} could not be fully removed ({failure.reason}). "
            "They may contain SENSITIVE DATA such as source code or secrets. They are left in "
            f"the auditor's private temporary directory (folder {failure.workspace!r}), "
            "readable only by this account and administrators. It is NOT deleted "
            "automatically by later runs; review and delete the folder manually."
        ),
    )


def _stale_warning(found: StaleWorkspaces) -> OperationalError:
    hours = STALE_AFTER_SECONDS // 3600
    return OperationalError(
        code=OperationalErrorCode.STALE_WORKSPACES_FOUND,
        component=found.component,
        workspace=found.pattern,
        message=(
            f"{found.count} temporary folder(s) ({found.pattern}) older than {hours} hours were "
            f"left by earlier, interrupted runs. They may hold {found.contents} and so "
            "SENSITIVE DATA such as source code or secrets. They were NOT deleted "
            "automatically; review and delete them manually."
        ),
    )


def run_audit(
    target: str | os.PathLike[str],
    output_dir: str | os.PathLike[str] | None = None,
    policy: ScanPolicy | None = None,
    ruff_options: RuffOptions | None = None,
    semgrep_options: SemgrepOptions | None = None,
    gitleaks_options: GitleaksOptions | None = None,
    pip_audit_options: PipAuditOptions | None = None,
    git_history_options: GitHistoryOptions | None = None,
    *,
    gate: GatePolicy | None = None,
    disabled: Collection[str] = (),
    scanners: Sequence[ScannerAdapter] | None = None,
    temp_base: Path | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> AuditRun:
    """Discovery followed by the enabled scanners (Ruff, Semgrep, Gitleaks, pip-audit), each
    independent. The git history scan runs only when ``git_history_options`` is given
    (``--scan-git-history``)."""
    policy = policy or ScanPolicy()
    adapters = (
        list(scanners)
        if scanners is not None
        else [
            RuffAdapter(ruff_options),
            SemgrepAdapter(semgrep_options),
            GitleaksAdapter(gitleaks_options),
            PipAuditAdapter(pip_audit_options),
        ]
        + ([GitHistoryAdapter(git_history_options)] if git_history_options is not None else [])
    )
    root = validate_target(target)
    base_dir = validate_output_dir(
        default_reports_base() if output_dir is None else output_dir, root
    )

    started = datetime.now(UTC)
    result = inspect(root, policy, clock=clock)
    outcomes: list[ScanOutcome] = []
    failures: list[CleanupFailure] = []
    stale: list[StaleWorkspaces] = []
    with PrivateWorkspace(root, temp_base, failures=failures, stale=stale) as work_dir:
        for adapter in adapters:
            if adapter.name in disabled:
                outcomes.append(_disabled(adapter.name))
                continue
            own_dir = work_dir / adapter.name  # independent scratch per scanner
            own_dir.mkdir()
            context = ScanContext(root, result.files, own_dir, failures, stale)
            outcomes.append(_safe_scan(adapter, context))
    outcomes = _reconcile_parse_coverage(outcomes)
    executions = [o.execution for o in outcomes]
    findings = [f for o in outcomes for f in o.findings]
    # H5: join the Semgrep evidence observations with a static AST check of the target and
    # raise verified cross-function SQL findings to HIGH (same findings, proof attached).
    findings, verified = apply_flow_evidence(
        root, findings, [ob for o in outcomes for ob in o.observations]
    )
    executions = _note_flow_verification(executions, verified)
    operational_errors = [_cleanup_error(f) for f in failures]
    operational_warnings = [_stale_warning(s) for s in stale]
    operational_warnings += _incomplete_reports_warning(base_dir)
    extra_warnings = [
        f"{e.code.value}: temporary data of {e.component} could not be removed "
        "(see the findings report)."
        for e in operational_errors
    ] + [f"{w.code.value}: {w.message}" for w in operational_warnings]

    inventory = _build_inventory(
        target,
        root,
        policy,
        result,
        started,
        datetime.now(UTC),
        _coverage(executions, False),
        extra_warnings,
    )
    reasons = list(inventory.incomplete_reasons)
    for execution in executions:
        found = [_STATUS_REASON.get(execution.status)]
        if execution.status not in _STATUS_REASON and execution.not_analyzed:
            found.append(IncompleteReason.FILES_NOT_ANALYZED)
        if execution.coverage_limitations:
            found.append(IncompleteReason.FILES_ANALYZED_WITH_LIMITATIONS)
        for reason in found:
            if reason is not None and reason not in reasons:
                reasons.append(reason)
    if operational_errors:
        reasons.append(IncompleteReason.CLEANUP_FAILED)
    findings.sort(key=lambda f: (SEVERITY_RANK[f.severity], f.relative_path, f.start_line or 0))
    report = FindingsReport(
        run_id=inventory.run_id,
        status=ScanStatus.PARTIAL if reasons else ScanStatus.COMPLETE,
        incomplete_reasons=reasons,
        tool_executions=executions,
        findings=findings,
        file_coverage=_file_coverage(result.files, outcomes),
        operational_errors=operational_errors,
        operational_warnings=operational_warnings,
    )
    names = {a.name for a in adapters}
    audit = build_audit_report(
        mode="audit",
        inventory=inventory,
        permissions=Permissions(
            network=bool(pip_audit_options and pip_audit_options.allow_network),
            git_history=git_history_options is not None,
            disabled_scanners=sorted(set(disabled) & names),
        ),
        status=report.status,
        incomplete_reasons=report.incomplete_reasons,
        executions=report.tool_executions,
        findings=report.findings,
        file_coverage=report.file_coverage,
        operational_errors=report.operational_errors,
        operational_warnings=report.operational_warnings,
        gate_policy=gate,
    )
    return AuditRun(inventory, report, write_reports(audit, base_dir, root), audit)
