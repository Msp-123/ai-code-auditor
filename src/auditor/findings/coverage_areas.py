"""One coverage state per area (Stage 6, D-048), derived from the scanners' own reports.

The overall COMPLETE/PARTIAL decision stays where it was (the audit service); areas are a
consistent, more precise view of it. NOT_APPLICABLE (nothing to check), NOT_REQUESTED (opt-in
check not asked for), NOT_PERMITTED (permission missing) and DISABLED (switched off by the
user) are kept apart.
"""

from collections.abc import Sequence

from auditor.core.audit_report import AreaStatus, CoverageArea, Permissions
from auditor.core.models import NotAnalyzedReason, ScanStatus, ToolExecution, ToolStatus

# area -> scanner (None: discovery itself)
AREAS = {
    "discovery": None,
    "code_quality": "ruff",
    "static_security": "semgrep",
    "secrets_working_tree": "gitleaks",
    "secrets_history": "gitleaks-history",
    "dependencies": "pip-audit",
}
_FAILED = (ToolStatus.NOT_INSTALLED, ToolStatus.ERROR, ToolStatus.TIMED_OUT)


def _area_state(execution: ToolExecution) -> tuple[AreaStatus, str]:
    if execution.settings.get("disabled_by_user") == "true":
        return (
            AreaStatus.DISABLED,
            "disabled by the user (--disable-scanner): not part of this audit",
        )
    if execution.status in _FAILED:
        return AreaStatus.FAILED, f"{execution.status.value}: {execution.reason}"
    if any(n.reason is NotAnalyzedReason.NETWORK_NOT_ALLOWED for n in execution.not_analyzed):
        return AreaStatus.NOT_PERMITTED, "network permission not granted (--allow-network)"
    if execution.not_analyzed or execution.coverage_limitations:
        return AreaStatus.PARTIAL, (
            f"{len(execution.not_analyzed)} not analyzed, "
            f"{len(execution.coverage_limitations)} scanned with limitations"
        )
    if execution.status is ToolStatus.SKIPPED:
        return AreaStatus.NOT_APPLICABLE, execution.reason
    return AreaStatus.COMPLETE, execution.reason


def coverage_areas(
    discovery_status: ScanStatus,
    executions: Sequence[ToolExecution],
    permissions: Permissions,
    *,
    discovery_only: bool,
) -> list[CoverageArea]:
    by_tool = {e.tool: e for e in executions}
    areas = []
    for area, tool in AREAS.items():
        if tool is None:
            status = (AreaStatus.COMPLETE if discovery_status is ScanStatus.COMPLETE
                      else AreaStatus.PARTIAL)  # fmt: skip
            reason = "inventory complete" if status is AreaStatus.COMPLETE else (
                "a discovery limit was hit or entries were unreadable")  # fmt: skip
        elif discovery_only:
            status, reason = AreaStatus.NOT_RUN, "discovery only: no scanner ran"
        elif tool in by_tool:
            status, reason = _area_state(by_tool[tool])
        elif tool == "gitleaks-history" and permissions.git_history:
            status, reason = AreaStatus.FAILED, "git history was requested but did not run"
        elif tool == "gitleaks-history":
            status = AreaStatus.NOT_REQUESTED
            reason = "git history was not scanned (opt-in: --scan-git-history)"
        else:
            status, reason = AreaStatus.NOT_REQUESTED, f"{tool} was not part of this run"
        areas.append(CoverageArea(area=area, tool=tool, status=status, reason=reason))
    return areas
