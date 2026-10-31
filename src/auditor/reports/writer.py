"""Atomic, target-safe report output with an integrity record (G1, G2; D-022, D-048).

Every file is first written as ``<name>.partial`` into a hidden staging directory
``.<run_id>.incomplete``. Only when all of them were written does the auditor write
SHA256SUMS.json, rename the files to their final names, re-read and check every file against
the record, and then rename the staging directory to ``<run_id>``. A failure at any point
leaves the staging directory, with ``.partial`` names and without an integrity record, so no
file of it looks like part of a finished report (G2). Nothing is deleted automatically:
leftovers are reported on the next run (G3).

The integrity record detects accidental or casual changes. It is not a signature: whoever can
write to the report directory can change a report and its record together.

Target safety (G1): missing directories are created via ``safe_fs.ensure_directory``, and the
staging directory's identity ``(st_dev, st_ino)`` is pinned and re-verified before every file
write, before the final rename and after it. Residual risk (D-022): no directory-handle-relative
file creation on Windows, so a very short window between a check and the following
``open``/``rename`` remains.
"""

import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

from auditor.core.audit_report import REPORT_SCHEMA_VERSION, AuditReport
from auditor.core.errors import ReportWriteError, TargetPathError
from auditor.core.models import FindingsReport
from auditor.core.safe_fs import (
    PRIVATE_DIR_MODE,
    create_private_file,
    ensure_directory,
    identity,
    verify_own_directory,
)
from auditor.reports.findings_report import render_findings_json
from auditor.reports.json_report import render_json
from auditor.reports.markdown_report import render_markdown

REPORT_FILE = "report.json"
INVENTORY_FILE = "inventory.json"
FINDINGS_FILE = "findings.json"
MARKDOWN_FILE = "report.md"
INTEGRITY_FILE = "SHA256SUMS.json"
PARTIAL = ".partial"
RUN_ID = re.compile(r"^\d{8}T\d{6}Z-[0-9a-f]{6}$")
INCOMPLETE_DIR = re.compile(r"^\.\d{8}T\d{6}Z-[0-9a-f]{6}\.incomplete$")
INTEGRITY_NOTE = (
    "Integrity record of this report directory (SHA-256 of each file). It detects accidental "
    "or casual changes; it is not a signature and gives no guarantee against someone who can "
    "write to the report directory."
)


@dataclass(frozen=True)
class ReportPaths:
    directory: Path
    inventory_json: Path
    markdown: Path
    findings_json: Path | None = None
    report_json: Path | None = None
    integrity: Path | None = None


class _IntegrityMismatch(Exception):
    pass


def render_report_json(audit: AuditReport) -> str:
    return audit.model_dump_json(indent=2) + "\n"


def legacy_findings_report(audit: AuditReport) -> FindingsReport:
    return FindingsReport(
        run_id=audit.run.run_id,
        status=audit.coverage.status,
        incomplete_reasons=audit.coverage.incomplete_reasons,
        tool_executions=audit.tools,
        findings=audit.findings,
        file_coverage=audit.file_coverage,
        operational_errors=audit.operational_errors,
        operational_warnings=audit.operational_warnings,
    )


def render_integrity(digests: dict[str, str]) -> str:
    record = {
        "algorithm": "sha256",
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "files": dict(sorted(digests.items())),
        "note": INTEGRITY_NOTE,
    }
    return json.dumps(record, indent=2) + "\n"


def count_incomplete_dirs(base_dir: Path) -> int:
    """Leftover staging directories of earlier runs (G3: reported, never deleted)."""
    try:
        return sum(1 for name in os.listdir(base_dir) if INCOMPLETE_DIR.match(name))
    except OSError:
        return 0


def _sha256_of(path: Path) -> str:
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def _finalise_names(staging: Path, names: list[str]) -> None:
    for name in names:
        os.replace(staging / f"{name}{PARTIAL}", staging / name)


def _check_integrity(staging: Path, digests: dict[str, str]) -> None:
    present = {p.name for p in staging.iterdir()}
    if present != {*digests, INTEGRITY_FILE}:
        raise _IntegrityMismatch("unexpected files")
    for name, digest in digests.items():
        if _sha256_of(staging / name) != digest:
            raise _IntegrityMismatch(name)


def write_reports(audit: AuditReport, base_dir: Path, root: Path) -> ReportPaths:
    """Write report.json, inventory.json, findings.json (audits), report.md and
    SHA256SUMS.json, and publish them atomically as ``<base_dir>/<run_id>``."""
    run_id = audit.run.run_id
    if not RUN_ID.match(run_id):
        raise ReportWriteError("Reports could not be written: invalid run id.")
    final_dir = base_dir / run_id
    staging_dir = base_dir / f".{run_id}.incomplete"
    documents = [(REPORT_FILE, lambda: render_report_json(audit)),
                 (INVENTORY_FILE, lambda: render_json(audit.discovery))]  # fmt: skip
    if audit.mode == "audit":
        documents.append(
            (FINDINGS_FILE, lambda: render_findings_json(legacy_findings_report(audit)))
        )
    documents.append((MARKDOWN_FILE, lambda: render_markdown(audit)))
    try:
        ensure_directory(base_dir, root)
        os.mkdir(staging_dir, PRIVATE_DIR_MODE)
        pinned = identity(staging_dir)
        verify_own_directory(staging_dir, pinned, root)

        digests: dict[str, str] = {}
        for name, render in documents:
            content = render()
            verify_own_directory(staging_dir, pinned, root)
            create_private_file(staging_dir / f"{name}{PARTIAL}", content)
            digests[name] = _sha256_of(staging_dir / f"{name}{PARTIAL}")

        verify_own_directory(staging_dir, pinned, root)
        create_private_file(staging_dir / f"{INTEGRITY_FILE}{PARTIAL}", render_integrity(digests))
        _finalise_names(staging_dir, [*digests, INTEGRITY_FILE])
        _check_integrity(staging_dir, digests)

        verify_own_directory(staging_dir, pinned, root)
        if os.path.lexists(final_dir):  # never replace an existing directory (any platform)
            raise FileExistsError("run directory exists")
        os.replace(staging_dir, final_dir)
        verify_own_directory(final_dir, pinned, root)
    except TargetPathError:
        raise
    except Exception as exc:
        kind = "integrity check failed" if isinstance(exc, _IntegrityMismatch) else (
            type(exc).__name__)  # fmt: skip
        location = staging_dir if staging_dir.exists() else base_dir
        raise ReportWriteError(
            f"Reports could not be written completely ({kind}). No complete report exists; "
            f"incomplete output (if any, never a valid report) is at: {location}"
        ) from exc
    return ReportPaths(
        directory=final_dir,
        inventory_json=final_dir / INVENTORY_FILE,
        markdown=final_dir / MARKDOWN_FILE,
        findings_json=final_dir / FINDINGS_FILE if audit.mode == "audit" else None,
        report_json=final_dir / REPORT_FILE,
        integrity=final_dir / INTEGRITY_FILE,
    )
