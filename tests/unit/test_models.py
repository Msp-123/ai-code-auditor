from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from auditor.core.models import (
    EntryKind,
    ExcludedEntry,
    ExclusionReason,
    FileCategory,
    FileEntry,
    IncompleteReason,
    LimitsSummary,
    RepositoryInventory,
    ScanStatus,
    ToolCoverage,
    ToolStatus,
)

NOW = datetime(2026, 10, 28, 16, 0, tzinfo=UTC)
LIMITS = LimitsSummary(
    max_files=10,
    max_entries_visited=100,
    max_depth=5,
    max_file_size_bytes=1024,
    max_duration_seconds=1.0,
)


def make_inventory(**overrides) -> RepositoryInventory:
    data = {
        "run_id": "20261028T160000Z-abc123",
        "started_at": NOW,
        "finished_at": NOW,
        "root_name": "sample",
        "status": ScanStatus.COMPLETE,
        "incomplete_reasons": [],
        "vcs_metadata": [".git"],
        "entries_visited": 3,
        "unvisited_directories": 0,
        "limits": LIMITS,
        "files": [
            FileEntry(
                relative_path="src/main.py",
                size_bytes=10,
                category=FileCategory.PYTHON_SOURCE,
                is_sensitive=False,
                ai_context_allowed=True,
                secret_scan_eligible=True,
                oversized=False,
            ),
            FileEntry(
                relative_path=".env",
                size_bytes=5,
                category=FileCategory.OTHER,
                is_sensitive=True,
                ai_context_allowed=False,
                secret_scan_eligible=True,
                oversized=False,
            ),
        ],
        "excluded": [
            ExcludedEntry(
                relative_path=".git", kind=EntryKind.DIRECTORY, reason=ExclusionReason.VCS_METADATA
            )
        ],
        "scanners": [ToolCoverage(tool="ruff", status=ToolStatus.SKIPPED, reason="Stage 2")],
        "warnings": [],
    }
    data.update(overrides)
    return RepositoryInventory(**data)


def test_inventory_json_round_trip():
    inventory = make_inventory()

    restored = RepositoryInventory.model_validate_json(inventory.model_dump_json())

    assert restored == inventory


def test_computed_counts_are_serialised():
    dumped = make_inventory().model_dump(mode="json")

    assert dumped["files_by_category"] == {"other": 1, "python_source": 1}
    assert dumped["excluded_by_reason"] == {"VCS_METADATA": 1}
    assert dumped["sensitive_file_count"] == 1
    assert dumped["schema_version"] == "1"


def test_complete_status_with_incomplete_reasons_is_rejected():
    with pytest.raises(ValidationError, match="PARTIAL"):
        make_inventory(incomplete_reasons=[IncompleteReason.MAX_FILES])


def test_partial_status_without_reasons_is_rejected():
    with pytest.raises(ValidationError, match="PARTIAL"):
        make_inventory(status=ScanStatus.PARTIAL)


def test_missing_required_field_is_rejected():
    data = make_inventory().model_dump(mode="json")
    del data["root_name"]

    with pytest.raises(ValidationError, match="root_name"):
        RepositoryInventory.model_validate(data)


def test_models_are_immutable():
    inventory = make_inventory()

    with pytest.raises(ValidationError):
        inventory.root_name = "other"
