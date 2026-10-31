"""Typed, serialisable data models shared across layers."""

from collections import Counter
from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, PositiveInt, computed_field, model_validator

SCHEMA_VERSION = "1"


class ToolStatus(StrEnum):
    NOT_INSTALLED = "NOT_INSTALLED"
    READY = "READY"
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    SKIPPED = "SKIPPED"
    ERROR = "ERROR"
    TIMED_OUT = "TIMED_OUT"


class ScanStatus(StrEnum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"


class IncompleteReason(StrEnum):
    """Why an inventory or an audit does not cover the whole target."""

    # Discovery
    MAX_FILES = "MAX_FILES"
    MAX_ENTRIES = "MAX_ENTRIES"
    MAX_DEPTH = "MAX_DEPTH"
    TIMEOUT = "TIMEOUT"
    UNREADABLE = "UNREADABLE"
    CHANGED_DURING_SCAN = "CHANGED_DURING_SCAN"
    # Scanners
    SCANNER_NOT_INSTALLED = "SCANNER_NOT_INSTALLED"
    SCANNER_ERROR = "SCANNER_ERROR"
    SCANNER_TIMED_OUT = "SCANNER_TIMED_OUT"
    FILES_NOT_ANALYZED = "FILES_NOT_ANALYZED"
    FILES_ANALYZED_WITH_LIMITATIONS = "FILES_ANALYZED_WITH_LIMITATIONS"
    # The auditor's own operation (findings stay valid, but the run did not end cleanly)
    CLEANUP_FAILED = "CLEANUP_FAILED"


class ExclusionReason(StrEnum):
    """Why an entry is not part of the inventory."""

    VCS_METADATA = "VCS_METADATA"
    VIRTUALENV = "VIRTUALENV"
    EXCLUDED_DIR = "EXCLUDED_DIR"
    SYMLINK = "SYMLINK"
    JUNCTION = "JUNCTION"
    REPARSE_POINT = "REPARSE_POINT"
    SPECIAL_FILE = "SPECIAL_FILE"
    INVALID_NAME = "INVALID_NAME"
    UNREADABLE = "UNREADABLE"
    MAX_DEPTH = "MAX_DEPTH"
    CHANGED_DURING_SCAN = "CHANGED_DURING_SCAN"


class FileCategory(StrEnum):
    PYTHON_SOURCE = "python_source"
    TEST = "test"
    DEPENDENCY_MANIFEST = "dependency_manifest"
    CONFIG = "config"
    DOC = "doc"
    OTHER = "other"


class FileContext(StrEnum):
    """Where a finding's file sits, from its path only (H6). Never a security proof."""

    PRODUCTION = "production"
    TEST = "test"
    DOCS = "docs"
    EXAMPLES = "examples"
    CONFIG = "config"
    UNKNOWN = "unknown"


class EntryKind(StrEnum):
    FILE = "file"
    DIRECTORY = "directory"
    LINK = "link"
    OTHER = "other"


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True)


class FileEntry(_Frozen):
    relative_path: str
    size_bytes: int
    category: FileCategory
    is_sensitive: bool
    ai_context_allowed: bool
    secret_scan_eligible: bool
    oversized: bool
    path_redacted: bool = False


class ExcludedEntry(_Frozen):
    relative_path: str
    kind: EntryKind
    reason: ExclusionReason
    # Only for links: lexical, best-effort classification. Links are never followed.
    points_outside_root: bool | None = None
    path_redacted: bool = False


class ToolCoverage(_Frozen):
    tool: str
    status: ToolStatus
    reason: str


class LimitsSummary(_Frozen):
    max_files: int
    max_entries_visited: int
    max_depth: int
    max_file_size_bytes: int
    max_duration_seconds: float


class RepositoryInventory(_Frozen):
    schema_version: str = SCHEMA_VERSION
    run_id: str
    started_at: datetime
    finished_at: datetime
    root_name: str
    status: ScanStatus
    incomplete_reasons: list[IncompleteReason]
    vcs_metadata: list[str]
    entries_visited: int
    unvisited_directories: int
    limits: LimitsSummary
    files: list[FileEntry]
    excluded: list[ExcludedEntry]
    scanners: list[ToolCoverage]
    warnings: list[str]

    @model_validator(mode="after")
    def _status_matches_reasons(self) -> "RepositoryInventory":
        # An incomplete inventory must never be reported as COMPLETE, and vice versa.
        if (self.status is ScanStatus.PARTIAL) != bool(self.incomplete_reasons):
            raise ValueError("status must be PARTIAL exactly when incomplete_reasons is non-empty")
        return self

    @computed_field
    @property
    def files_by_category(self) -> dict[str, int]:
        return dict(sorted(Counter(f.category.value for f in self.files).items()))

    @computed_field
    @property
    def excluded_by_reason(self) -> dict[str, int]:
        return dict(sorted(Counter(e.reason.value for e in self.excluded).items()))

    @computed_field
    @property
    def sensitive_file_count(self) -> int:
        return sum(f.is_sensitive for f in self.files)

    @computed_field
    @property
    def oversized_file_count(self) -> int:
        return sum(f.oversized for f in self.files)


# ------------------------------------------------------------------- findings (all tools)


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    # The tool gives no severity (pip-audit). Kept as such in the canonical model; the quality
    # gate maps it with --unrated-as, the legacy findings.json keeps a MEDIUM placeholder.
    UNRATED = "UNRATED"


# Sort order (CRITICAL first). UNRATED right after HIGH, so it is never buried at the end.
SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.UNRATED: 2,
    Severity.MEDIUM: 3,
    Severity.LOW: 4,
    Severity.INFO: 5,
}
# Gate thresholds compare real severities only (UNRATED is mapped first).
GATE_ORDER = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)


class Confidence(StrEnum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class VerificationStatus(StrEnum):
    CONFIRMED = "CONFIRMED"
    PROBABLE = "PROBABLE"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    DISPROVEN = "DISPROVEN"


class FindingCategory(StrEnum):
    SECURITY = "security"
    CORRECTNESS = "correctness"
    COMPATIBILITY = "compatibility"
    MAINTAINABILITY = "maintainability"
    STYLE = "style"
    OTHER = "other"


class Evidence(_Frozen):
    kind: str
    reference: str
    redacted: bool = False


class Finding(_Frozen):
    """One normalised finding from any scanner (master plan §8.2)."""

    finding_id: str
    fingerprint: str
    source_tool: str
    rule_id: str
    title: str
    description: str
    category: FindingCategory
    severity: Severity
    original_severity: str | None = None
    confidence: Confidence
    verification_status: VerificationStatus
    relative_path: str
    start_line: PositiveInt | None = None
    start_column: PositiveInt | None = None
    end_line: PositiveInt | None = None
    end_column: PositiveInt | None = None
    evidence: list[Evidence] = Field(default_factory=list)
    recommendation: str | None = None
    fix_available: bool = False
    references: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    first_seen_run_id: str | None = None
    path_redacted: bool = False
    # Stage 6: structured, non-secret identifiers used to relate findings (R2, R3).
    identifiers: "FindingIdentifiers" = Field(default_factory=lambda: FindingIdentifiers())
    group_ids: list[str] = Field(default_factory=list)
    # H6: path-based context (production / test / docs / examples / config / unknown) and the
    # directory name or file pattern it was derived from. Set once by the report builder.
    context: FileContext = FileContext.UNKNOWN
    context_basis: str | None = None
    # Git blob ids of the analysed working-tree bytes ({"sha1": ..., "sha256": ...}), used only
    # inside the process to verify R2. Never serialised: for a tiny file the id of its content
    # could help guess a low-entropy secret.
    content_ids: dict[str, str] = Field(default_factory=dict, exclude=True)
    # CONFIRMED is allowed by the model for a future, independent verification step. Scanner
    # adapters must never produce it; the audit service enforces that (run_audit/_safe_scan).


class FindingIdentifiers(_Frozen):
    """Identifiers a finding can be related by; never secret values."""

    package: str | None = None  # pip-audit: PEP 503 name
    version: str | None = None
    vulnerability_ids: list[str] = Field(default_factory=list)  # id + validated aliases
    git_object: str | None = None  # history: blob id (already part of the repository)
    object_format: str | None = None  # "sha1" | "sha256"
    history_paths: list[str] = Field(default_factory=list)  # verified paths of that object


Finding.model_rebuild()


class NotAnalyzedReason(StrEnum):
    PARSE_ERROR = "PARSE_ERROR"
    IO_ERROR = "IO_ERROR"
    CHANGED_BEFORE_SCAN = "CHANGED_BEFORE_SCAN"
    BATCH_FAILED = "BATCH_FAILED"
    TIMED_OUT = "TIMED_OUT"
    TOOL_ERROR = "TOOL_ERROR"
    SKIPPED_BY_TOOL = "SKIPPED_BY_TOOL"
    SIZE_LIMIT = "SIZE_LIMIT"
    NETWORK_NOT_ALLOWED = "NETWORK_NOT_ALLOWED"
    UNSUPPORTED_MANIFEST = "UNSUPPORTED_MANIFEST"
    UNSAFE_REPOSITORY = "UNSAFE_REPOSITORY"


class NotAnalyzedFile(_Frozen):
    relative_path: str
    reason: NotAnalyzedReason
    detail: str | None = None
    path_redacted: bool = False


class LimitedFile(_Frozen):
    """A file the scanner did scan, but whose analysis may be incomplete."""

    relative_path: str
    reason: str
    detail: str | None = None
    path_redacted: bool = False


class CoverageStatus(StrEnum):
    SCANNED = "SCANNED"
    SCANNED_WITH_LIMITATIONS = "SCANNED_WITH_LIMITATIONS"
    NOT_ANALYZED = "NOT_ANALYZED"
    NOT_RUN = "NOT_RUN"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class ScannerCoverage(_Frozen):
    status: CoverageStatus
    reason: str | None = None


class FileCoverage(_Frozen):
    """Per inventory file: what every scanner did with it (no silent skipping)."""

    relative_path: str
    scanners: dict[str, ScannerCoverage]
    path_redacted: bool = False


class SuppressedFindings(_Frozen):
    """Findings dropped by an explicit auditor policy — always counted, never silently lost."""

    rule_id: str
    reason: str
    count: int


class ToolExecution(_Frozen):
    """What a scanner actually did — kept separate from what it found."""

    tool: str
    version: str | None
    status: ToolStatus
    reason: str
    exit_codes: list[int] = Field(default_factory=list)
    duration_seconds: float = 0.0
    files_requested: int = 0
    files_analyzed: int = 0
    not_analyzed: list[NotAnalyzedFile] = Field(default_factory=list)
    settings: dict[str, str] = Field(default_factory=dict)
    command_summary: str = ""
    stderr_excerpt: str | None = None
    warnings: list[str] = Field(default_factory=list)
    suppressed: list[SuppressedFindings] = Field(default_factory=list)
    coverage_limitations: list[LimitedFile] = Field(default_factory=list)


class OperationalErrorCode(StrEnum):
    CLEANUP_FAILED = "CLEANUP_FAILED"  # error: this run's temporary data was not removed
    STALE_WORKSPACES_FOUND = "STALE_WORKSPACES_FOUND"  # warning: leftovers of earlier runs
    # warning: staging directories of earlier report writes (G3; never deleted)
    INCOMPLETE_REPORTS_FOUND = "INCOMPLETE_REPORTS_FOUND"


class OperationalError(_Frozen):
    """A security-relevant problem of the auditor itself, not a finding about the target."""

    code: OperationalErrorCode
    component: str  # e.g. "semgrep", "scanner-output"
    workspace: str  # name (or name pattern) of temporary directories; never a full path
    message: str


class FindingsReport(_Frozen):
    schema_version: str = SCHEMA_VERSION
    run_id: str
    status: ScanStatus
    incomplete_reasons: list[IncompleteReason]
    tool_executions: list[ToolExecution]
    findings: list[Finding]
    file_coverage: list[FileCoverage] = Field(default_factory=list)
    operational_errors: list[OperationalError] = Field(default_factory=list)
    # Do not make the run PARTIAL (they concern earlier runs), but are always shown.
    operational_warnings: list[OperationalError] = Field(default_factory=list)

    @model_validator(mode="after")
    def _status_matches_reasons(self) -> "FindingsReport":
        if (self.status is ScanStatus.PARTIAL) != bool(self.incomplete_reasons):
            raise ValueError("status must be PARTIAL exactly when incomplete_reasons is non-empty")
        return self

    @computed_field
    @property
    def findings_by_severity(self) -> dict[str, int]:
        counts = Counter(f.severity for f in self.findings)
        return {s.value: counts[s] for s in Severity if counts[s]}

    @computed_field
    @property
    def coverage_summary(self) -> dict[str, dict[str, int]]:
        summary: dict[str, Counter] = {}
        for row in self.file_coverage:
            for tool, state in row.scanners.items():
                summary.setdefault(tool, Counter())[state.status.value] += 1
        return {tool: dict(sorted(counts.items())) for tool, counts in sorted(summary.items())}
