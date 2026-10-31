"""Builds the canonical AuditReport (Stage 6, D-048) from what discovery and the scanners did.

Redaction is applied here, once, so report.json, the legacy JSON files, report.md and the
terminal summary are all derived from the same redacted data.
"""

import platform
from collections import Counter
from collections.abc import Sequence

from auditor import __version__
from auditor.core.audit_report import (
    AuditReport,
    Coverage,
    Gap,
    GateResult,
    Limitation,
    Outcome,
    Permissions,
    RunInfo,
)
from auditor.core.models import (
    FileContext,
    FileCoverage,
    Finding,
    FindingsReport,
    IncompleteReason,
    OperationalError,
    RepositoryInventory,
    ScanStatus,
    Severity,
    ToolExecution,
)
from auditor.core.redaction import redact_findings, redact_inventory
from auditor.discovery.classify import classify_context
from auditor.findings.correlation import relate
from auditor.findings.coverage_areas import AREAS, coverage_areas
from auditor.findings.gate import GatePolicy, evaluate_gate
from auditor.reports.limitations import BY_TOOL

_AREA_OF_TOOL = {tool: area for area, tool in AREAS.items() if tool}


def _with_context(finding: Finding) -> Finding:
    """H6: the same path-based context for every tool's finding, plus the test-path tag."""
    if finding.path_redacted:
        context, basis = FileContext.UNKNOWN, "path redacted"
    else:
        context, basis = classify_context(finding.relative_path)
    tags = list(finding.tags)
    if context is FileContext.TEST and "test-path" not in tags:
        tags.append("test-path")
    return finding.model_copy(update={"context": context, "context_basis": basis, "tags": tags})


def _outcome(findings: Sequence[Finding], groups: int) -> Outcome:
    def count(values) -> dict[str, int]:
        return dict(sorted(Counter(values).items()))

    by_severity = Counter(f.severity for f in findings)
    by_source: dict[str, Counter] = {}
    for finding in findings:
        by_source.setdefault(finding.source_tool, Counter())[finding.severity.value] += 1
    return Outcome(
        total=len(findings),
        by_severity={s.value: by_severity[s] for s in Severity if by_severity[s]},
        by_source={tool: dict(sorted(c.items())) for tool, c in sorted(by_source.items())},
        by_confidence=count(f.confidence.value for f in findings),
        by_verification=count(f.verification_status.value for f in findings),
        by_context=count(f.context.value for f in findings),
        unrated=by_severity[Severity.UNRATED],
        related_groups=groups,
        findings_in_groups=sum(1 for f in findings if f.group_ids),
    )


def _gaps(executions: Sequence[ToolExecution]) -> list[Gap]:
    gaps = []
    for e in executions:
        area = _AREA_OF_TOOL.get(e.tool, e.tool)
        gaps += [Gap(area=area, tool=e.tool, kind="not_analyzed", item=n.relative_path,
                     reason=n.reason.value, detail=n.detail) for n in e.not_analyzed]  # fmt: skip
        gaps += [Gap(area=area, tool=e.tool, kind="limited", item=item.relative_path,
                     reason=item.reason, detail=item.detail)
                 for item in e.coverage_limitations]  # fmt: skip
    return gaps


def _limitations(executions: Sequence[ToolExecution]) -> list[Limitation]:
    ran = [e.tool for e in executions if e.settings.get("disabled_by_user") != "true"]
    return [Limitation(tool=tool, text=text) for tool in ran for text in BY_TOOL.get(tool, ())]


def build_audit_report(
    *,
    mode: str,
    inventory: RepositoryInventory,
    permissions: Permissions,
    status: ScanStatus,
    incomplete_reasons: Sequence[IncompleteReason],
    executions: Sequence[ToolExecution] = (),
    findings: Sequence[Finding] = (),
    file_coverage: Sequence[FileCoverage] = (),
    operational_errors: Sequence[OperationalError] = (),
    operational_warnings: Sequence[OperationalError] = (),
    gate_policy: GatePolicy | None = None,
) -> AuditReport:
    redacted = redact_findings(
        FindingsReport(
            run_id=inventory.run_id,
            status=status,
            incomplete_reasons=list(incomplete_reasons),
            tool_executions=list(executions),
            findings=list(findings),
            file_coverage=list(file_coverage),
            operational_errors=list(operational_errors),
            operational_warnings=list(operational_warnings),
        )
    )
    related, groups = relate([_with_context(f) for f in redacted.findings])
    gate = (evaluate_gate(related, gate_policy or GatePolicy()) if mode == "audit"
            else GateResult.not_evaluated())  # fmt: skip
    inv = redact_inventory(inventory)
    return AuditReport(
        mode=mode,
        run=RunInfo(
            run_id=inv.run_id,
            started_at=inv.started_at,
            finished_at=inv.finished_at,
            duration_seconds=round((inv.finished_at - inv.started_at).total_seconds(), 3),
            auditor_version=__version__,
            platform=platform.system() or "unknown",
            python=platform.python_version(),
        ),
        target_name=inv.root_name,
        permissions=permissions,
        coverage=Coverage(
            status=status,
            incomplete_reasons=list(incomplete_reasons),
            areas=coverage_areas(
                inv.status,
                redacted.tool_executions,
                permissions,
                discovery_only=mode == "discovery",
            ),  # fmt: skip
        ),
        outcome=_outcome(related, len(groups)),
        gate=gate,
        tools=redacted.tool_executions,
        findings=related,
        groups=groups,
        gaps=_gaps(redacted.tool_executions),
        file_coverage=redacted.file_coverage,
        discovery=inv,
        limitations=_limitations(redacted.tool_executions),
        warnings=list(inv.warnings),
        operational_errors=redacted.operational_errors,
        operational_warnings=redacted.operational_warnings,
    )
