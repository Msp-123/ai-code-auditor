"""Load a stored report for ``auditor report`` (Stage 6, D-048): read-only, no scanner, no git,
no network.

A stored report is untrusted data: the run id must match the strict pattern (no path syntax,
drive letters, UNC or device names can pass), no link or junction is followed, files are read
with identity and size checks, every file listed in SHA256SUMS.json must match, and report.json
must validate against the v1 model. Runs without an integrity record (earlier versions,
incomplete writes) are refused. The integrity record is not a signature (see writer).
"""

import hashlib
import json
import os
import stat
from pathlib import Path

from pydantic import ValidationError

from auditor.core.audit_report import SUPPORTED_SCHEMA_VERSIONS, AuditReport
from auditor.core.safe_fs import is_link_like
from auditor.discovery.repository import extended_length_path
from auditor.reports.writer import (
    FINDINGS_FILE,
    INTEGRITY_FILE,
    INVENTORY_FILE,
    MARKDOWN_FILE,
    REPORT_FILE,
    RUN_ID,
)
from auditor.scanners.selection import read_regular_file

MAX_REPORT_BYTES = 64 * 1024 * 1024
MAX_INTEGRITY_BYTES = 64 * 1024
_ALLOWED_FILES = frozenset({REPORT_FILE, INVENTORY_FILE, FINDINGS_FILE, MARKDOWN_FILE})
_HEX64 = frozenset("0123456789abcdef")


class ReportLoadError(Exception):
    """A fixed, content-free explanation of why a stored report cannot be shown."""


def _directory(path: Path, what: str) -> None:
    try:
        st = os.lstat(extended_length_path(os.fspath(path)))
    except OSError:
        raise ReportLoadError(f"{what} does not exist") from None
    if is_link_like(st):
        raise ReportLoadError(f"{what} is a link or junction; not followed")
    if not stat.S_ISDIR(st.st_mode):
        raise ReportLoadError(f"{what} is not a directory")


def _read(path: Path, limit: int, what: str) -> bytes:
    result = read_regular_file(os.fspath(path), limit)
    if result.data is None:
        raise ReportLoadError(f"{what} cannot be read safely ({result.reason.value.lower()})")
    return result.data


def _integrity(run_dir: Path) -> dict[str, str]:
    if not os.path.lexists(extended_length_path(os.fspath(run_dir / INTEGRITY_FILE))):
        raise ReportLoadError(
            "no integrity record (SHA256SUMS.json): written by an earlier version or incomplete; "
            "refused"
        )
    try:
        record = json.loads(
            _read(run_dir / INTEGRITY_FILE, MAX_INTEGRITY_BYTES, "integrity record")
        )
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ReportLoadError("the integrity record is not valid JSON") from None
    files = record.get("files") if isinstance(record, dict) else None
    if (not isinstance(files, dict) or record.get("algorithm") != "sha256"
            or record.get("report_schema_version") not in SUPPORTED_SCHEMA_VERSIONS):  # fmt: skip
        raise ReportLoadError("the integrity record has an unsupported format or version")
    for name, digest in files.items():
        if name not in _ALLOWED_FILES or not isinstance(digest, str) or len(digest) != 64 or (
                set(digest) - _HEX64):  # fmt: skip
            raise ReportLoadError("the integrity record lists an unexpected entry")
    if REPORT_FILE not in files:
        raise ReportLoadError("the integrity record does not cover report.json")
    return files


def load_report(run_id: str, base_dir: Path) -> AuditReport:
    if not isinstance(run_id, str) or not RUN_ID.fullmatch(run_id):
        raise ReportLoadError("invalid run id (expected e.g. 20261030T120000Z-1a2b3c)")
    _directory(base_dir, "the report directory")
    run_dir = base_dir / run_id
    _directory(run_dir, "the run directory")
    files = _integrity(run_dir)
    contents = {}
    for name, digest in files.items():
        data = _read(run_dir / name, MAX_REPORT_BYTES, name)
        if hashlib.sha256(data).hexdigest() != digest:
            raise ReportLoadError(f"{name} does not match the integrity record (changed?)")
        contents[name] = data
    try:
        return AuditReport.model_validate_json(contents[REPORT_FILE])
    except ValidationError:
        raise ReportLoadError("report.json does not match the v1 report schema") from None
