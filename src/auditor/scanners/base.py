"""The small contract every scanner adapter implements (master plan §4.4).

Deliberately not a plugin framework: four scanners need one Protocol and two value types.
An adapter never raises for tool failures; it reports them in ``ToolExecution.status``.
"""

from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from auditor.core.models import FileEntry, Finding, ToolExecution
from auditor.scanners.workspace import CleanupFailure, StaleWorkspaces


@dataclass(frozen=True)
class ScanContext:
    root: Path  # resolved scan root (from validate_target)
    files: Sequence[FileEntry]  # discovery inventory: the only files a scanner may look at
    workspace: Path  # private, auto-cleaned scratch directory outside the target
    # Adapters that open their own PrivateWorkspace record cleanup failures here, so they are
    # reported even when the adapter raises afterwards (D-042).
    cleanup_failures: list[CleanupFailure] = field(default_factory=list)
    # Leftovers of earlier runs they found (reported, never deleted automatically).
    stale_workspaces: list[StaleWorkspaces] = field(default_factory=list)


@dataclass(frozen=True)
class FlowObservation:
    """An intra-procedural data-flow observation from an evidence rule (H5). Never reported
    as a finding; only joined by ``auditor.findings.flow_verification``. Locations only."""

    kind: str  # "sql_sink" (a parameter reaches SQL text) or "request_call" (request -> arg)
    relative_path: str
    line: int
    column: int  # 1-based, as Semgrep reports it
    kind_rule: str = ""  # rule id suffix, e.g. "param-to-sql-text"


@dataclass(frozen=True)
class ScanOutcome:
    execution: ToolExecution
    findings: list[Finding]
    # Inventory paths this scanner is responsible for (e.g. the .py/.pyi files); the audit
    # service uses it to build the per-file coverage matrix. None: not reported.
    applicable: list[str] | None = None
    # H5 evidence observations (not findings): the audit service verifies them after all
    # scanners ran and may raise the severity of existing SQL findings with the proof attached.
    observations: list[FlowObservation] = field(default_factory=list)


class ScannerAdapter(Protocol):
    name: str

    def scan(self, context: ScanContext) -> ScanOutcome: ...
