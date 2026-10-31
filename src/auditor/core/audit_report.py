"""The canonical v1 audit report (Stage 6): the single source of report.json, report.md, the
legacy JSON files and the terminal summary.

Two independent axes are kept apart on purpose:

- ``coverage``: what was checked (COMPLETE / PARTIAL, plus one state per area). COMPLETE says
  only that every requested check covered its whole scope; it never says the project is safe.
- ``outcome`` and ``gate``: what was found, and whether a user-chosen severity threshold was
  reached. Finding relations (``groups``) never remove or merge findings.
"""

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import Field, model_validator

from auditor.core.models import (
    FileCoverage,
    Finding,
    IncompleteReason,
    OperationalError,
    RepositoryInventory,
    ScanStatus,
    ToolExecution,
    _Frozen,
)

REPORT_SCHEMA_ID = "ai-code-auditor/report"
REPORT_SCHEMA_VERSION = "1.1.0"
# Additive 1.x changes only: a report written by any of these versions still loads (missing
# fields take their defaults). 1.1.0 added Finding.context / context_basis and
# Outcome.by_context (H6).
SUPPORTED_SCHEMA_VERSIONS = ("1.0.0", "1.1.0")


class AreaStatus(StrEnum):
    COMPLETE = "COMPLETE"  # the area's scanner covered everything it was asked to
    PARTIAL = "PARTIAL"  # it ran, but some files/objects were not (fully) analyzed
    FAILED = "FAILED"  # not installed, error or timeout: the area is not covered
    DISABLED = "DISABLED"  # switched off by the user (--disable-scanner)
    NOT_APPLICABLE = "NOT_APPLICABLE"  # nothing to check (no Python files, no manifests, ...)
    NOT_REQUESTED = "NOT_REQUESTED"  # an opt-in check that was not requested (git history)
    NOT_PERMITTED = "NOT_PERMITTED"  # needs a permission that was not granted (network)
    NOT_RUN = "NOT_RUN"  # discovery-only run: no scanner ran at all


INCOMPLETE_AREA_STATES = frozenset(
    {AreaStatus.PARTIAL, AreaStatus.FAILED, AreaStatus.NOT_PERMITTED}
)


class CoverageArea(_Frozen):
    area: str
    tool: str | None
    status: AreaStatus
    reason: str


class Coverage(_Frozen):
    status: ScanStatus
    incomplete_reasons: list[IncompleteReason]
    areas: list[CoverageArea]
    meaning: str = (
        "COMPLETE means every requested check covered its whole scope. It does not mean that "
        "nothing was found, that every possible check was made, or that the project is safe."
    )


class RunInfo(_Frozen):
    run_id: str
    started_at: datetime
    finished_at: datetime
    duration_seconds: float
    auditor_version: str
    platform: str
    python: str


class Permissions(_Frozen):
    network: bool
    git_history: bool
    disabled_scanners: list[str]


class GateStatus(StrEnum):
    NOT_EVALUATED = "NOT_EVALUATED"
    PASSED = "PASSED"
    FAILED = "FAILED"


class GateResult(_Frozen):
    status: GateStatus
    fail_on: str  # "none" | severity
    unrated_as: str  # severity | "ignore"
    counted: int = 0
    counted_by_effective_severity: dict[str, int] = Field(default_factory=dict)
    counted_finding_ids: list[str] = Field(default_factory=list)  # at most 100
    note: str = (
        "The gate uses an effective severity (UNRATED mapped by --unrated-as); findings keep "
        "their real severity. Related findings are all counted."
    )

    @classmethod
    def not_evaluated(cls) -> "GateResult":
        return cls(status=GateStatus.NOT_EVALUATED, fail_on="none", unrated_as="high")


class Outcome(_Frozen):
    total: int
    by_severity: dict[str, int]
    by_source: dict[str, dict[str, int]]
    by_confidence: dict[str, int]
    by_verification: dict[str, int]
    by_context: dict[str, int] = {}  # H6 (schema 1.1.0); path-based, not a security proof
    unrated: int
    related_groups: int
    findings_in_groups: int
    statement: str = (
        "Scanner findings are leads to review (NEEDS_REVIEW), not confirmed vulnerabilities. "
        "No findings does not mean the project is safe."
    )

    @classmethod
    def empty(cls) -> "Outcome":
        return cls(total=0, by_severity={}, by_source={}, by_confidence={}, by_verification={},
                   unrated=0, related_groups=0, findings_in_groups=0)  # fmt: skip


class RelationType(StrEnum):
    SAME_LOCATION = "same_location"
    SAME_CONTENT_IN_HISTORY = "same_content_in_history"
    SAME_VULNERABILITY = "same_vulnerability"


class FindingGroup(_Frozen):
    group_id: str
    relation: RelationType
    basis: dict[str, str | int | list[str]]
    finding_ids: list[str]
    statement: str


class Gap(_Frozen):
    area: str
    tool: str
    kind: Literal["not_analyzed", "limited"]
    item: str
    reason: str
    detail: str | None = None


class Limitation(_Frozen):
    tool: str
    text: str


class Privacy(_Frozen):
    contains: list[str] = Field(default_factory=lambda: [
        "relative paths inside the target", "rule ids, lines and fixed descriptions",
        "package names and versions", "git commit and object ids, commit dates",
        "tool versions and settings",
    ])  # fmt: skip
    never_contains: list[str] = Field(default_factory=lambda: [
        "secret values or any part of them", "file contents or code excerpts",
        "commit messages, author or committer names and e-mail addresses",
        "absolute paths of the user's machine", "credentials of indexes or proxies",
    ])  # fmt: skip
    ai_context_allowed: bool = False
    note: str = (
        "Contains metadata about the target that can be sensitive (paths, commit ids). It is "
        "not prepared for AI context; a later stage must build such context separately."
    )


class AuditReport(_Frozen):
    report_schema: Literal["ai-code-auditor/report"] = REPORT_SCHEMA_ID
    schema_version: Literal["1.0.0", "1.1.0"] = REPORT_SCHEMA_VERSION
    mode: Literal["audit", "discovery"]
    run: RunInfo
    target_name: str
    permissions: Permissions
    coverage: Coverage
    outcome: Outcome
    gate: GateResult
    tools: list[ToolExecution] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    groups: list[FindingGroup] = Field(default_factory=list)
    gaps: list[Gap] = Field(default_factory=list)
    file_coverage: list[FileCoverage] = Field(default_factory=list)
    discovery: RepositoryInventory
    limitations: list[Limitation] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    operational_errors: list[OperationalError] = Field(default_factory=list)
    operational_warnings: list[OperationalError] = Field(default_factory=list)
    privacy: Privacy = Field(default_factory=Privacy)

    @model_validator(mode="after")
    def _coverage_is_consistent(self) -> "AuditReport":
        status = self.coverage.status
        if (status is ScanStatus.PARTIAL) != bool(self.coverage.incomplete_reasons):
            raise ValueError("coverage must be PARTIAL exactly when there are incomplete reasons")
        incomplete = [a.area for a in self.coverage.areas if a.status in INCOMPLETE_AREA_STATES]
        if status is ScanStatus.COMPLETE and incomplete:
            raise ValueError(f"COMPLETE is impossible with incomplete areas: {incomplete}")
        return self


def report_json_schema() -> dict:
    """JSON Schema of report.json (serialization view; generated from the model)."""
    schema = AuditReport.model_json_schema(mode="serialization")
    schema["$id"] = "https://ai-code-auditor.invalid/schemas/report-v1.schema.json"
    schema["title"] = "AI Code Auditor report v1"
    return schema


if __name__ == "__main__":  # regenerate: python -m auditor.core.audit_report > schemas/...
    import json
    import sys

    sys.stdout.write(json.dumps(report_json_schema(), indent=2, sort_keys=True) + "\n")
