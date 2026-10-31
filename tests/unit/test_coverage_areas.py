"""Stage 6 step 2: one coverage state per area, derived from what each scanner reported.

NOT_APPLICABLE, NOT_REQUESTED, NOT_PERMITTED and DISABLED are distinct on purpose.
"""

import pytest

from auditor.core.audit_report import AreaStatus, Permissions
from auditor.core.models import (
    LimitedFile,
    NotAnalyzedFile,
    NotAnalyzedReason,
    ScanStatus,
    ToolExecution,
    ToolStatus,
)
from auditor.findings.coverage_areas import AREAS, coverage_areas

PERMS = Permissions(network=False, git_history=False, disabled_scanners=[])


def execution(tool, status=ToolStatus.SUCCESS, reason="r", **extra):
    return ToolExecution(tool=tool, version="1", status=status, reason=reason, **extra)


def area(areas, name):
    return next(a for a in areas if a.area == name)


def test_every_area_is_always_reported_in_a_fixed_order():
    areas = coverage_areas(ScanStatus.COMPLETE, [], PERMS, discovery_only=False)

    assert [a.area for a in areas] == list(AREAS)
    assert [a.area for a in areas] == ["discovery", "code_quality", "static_security",
                                       "secrets_working_tree", "secrets_history",
                                       "dependencies"]  # fmt: skip


@pytest.mark.parametrize(
    ("tool_execution", "expected"),
    [
        (execution("ruff"), AreaStatus.COMPLETE),
        (execution("ruff", not_analyzed=[NotAnalyzedFile(
            relative_path="a.py", reason=NotAnalyzedReason.PARSE_ERROR)]), AreaStatus.PARTIAL),
        (execution("ruff", coverage_limitations=[LimitedFile(
            relative_path="a.py", reason="X")]), AreaStatus.PARTIAL),
        (execution("ruff", ToolStatus.ERROR), AreaStatus.FAILED),
        (execution("ruff", ToolStatus.TIMED_OUT), AreaStatus.FAILED),
        (execution("ruff", ToolStatus.NOT_INSTALLED), AreaStatus.FAILED),
        (execution("ruff", ToolStatus.SKIPPED, "No Python files"), AreaStatus.NOT_APPLICABLE),
        (execution("ruff", ToolStatus.SKIPPED, settings={"disabled_by_user": "true"}),
         AreaStatus.DISABLED),
    ],
)  # fmt: skip
def test_scanner_states_map_to_area_states(tool_execution, expected):
    areas = coverage_areas(ScanStatus.COMPLETE, [tool_execution], PERMS, discovery_only=False)

    assert area(areas, "code_quality").status is expected


def test_dependencies_without_network_permission_are_not_permitted():
    gap = NotAnalyzedFile(relative_path="r.txt", reason=NotAnalyzedReason.NETWORK_NOT_ALLOWED)
    pip = execution("pip-audit", ToolStatus.SKIPPED, not_analyzed=[gap])

    deps = area(coverage_areas(ScanStatus.PARTIAL, [pip], PERMS, discovery_only=False),
                "dependencies")  # fmt: skip

    assert deps.status is AreaStatus.NOT_PERMITTED and "--allow-network" in deps.reason


def test_dependencies_without_manifests_are_not_applicable():
    pip = execution("pip-audit", ToolStatus.SKIPPED, "No dependency manifests in the inventory")

    deps = area(coverage_areas(ScanStatus.COMPLETE, [pip], PERMS, discovery_only=False),
                "dependencies")  # fmt: skip

    assert deps.status is AreaStatus.NOT_APPLICABLE


def test_git_history_not_requested_is_its_own_state():
    history = area(coverage_areas(ScanStatus.COMPLETE, [], PERMS, discovery_only=False),
                   "secrets_history")  # fmt: skip

    assert history.status is AreaStatus.NOT_REQUESTED and "--scan-git-history" in history.reason


def test_git_history_refused_is_partial_and_no_repository_is_not_applicable():
    refused = execution("gitleaks-history", ToolStatus.SKIPPED, not_analyzed=[NotAnalyzedFile(
        relative_path=".git", reason=NotAnalyzedReason.UNSAFE_REPOSITORY)])  # fmt: skip
    none = execution("gitleaks-history", ToolStatus.SKIPPED, "Not a git repository")
    perms = Permissions(network=False, git_history=True, disabled_scanners=[])

    for tool_execution, expected in ((refused, AreaStatus.PARTIAL),
                                     (none, AreaStatus.NOT_APPLICABLE)):  # fmt: skip
        areas = coverage_areas(ScanStatus.COMPLETE, [tool_execution], perms, discovery_only=False)
        assert area(areas, "secrets_history").status is expected


def test_discovery_area_follows_the_inventory_and_discovery_only_runs_no_scanner():
    areas = coverage_areas(ScanStatus.PARTIAL, [], PERMS, discovery_only=True)

    assert area(areas, "discovery").status is AreaStatus.PARTIAL
    assert {a.status for a in areas if a.area != "discovery"} == {AreaStatus.NOT_RUN}
