"""Report privacy: secret-looking path segments and unsafe display characters.

File *names* can themselves carry secrets (e.g. a token pasted into a file name) or carry
characters that spoof terminal/Markdown output (bidi overrides, ANSI escapes, newlines).
"""

import hashlib
import math
import re
import unicodedata
from collections import Counter

from auditor.core.models import (
    ExcludedEntry,
    FileEntry,
    Finding,
    FindingsReport,
    RepositoryInventory,
    ToolExecution,
)

_KNOWN_TOKEN = re.compile(
    r"(?:AKIA|ASIA)[0-9A-Z]{16}"
    r"|gh[pousr]_[A-Za-z0-9]{30,}"
    r"|github_pat_[A-Za-z0-9_]{20,}"
    r"|glpat-[A-Za-z0-9_-]{20,}"
    r"|sk-[A-Za-z0-9_-]{20,}"
    r"|xox[abprs]-[A-Za-z0-9-]{10,}"
    r"|AIza[0-9A-Za-z_-]{35}"
    r"|eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}"
)
_HEX_RUN = re.compile(r"[0-9A-Fa-f]{32,}")
_TOKEN_RUN = re.compile(r"[A-Za-z0-9+/=_-]{32,}")
_ENTROPY_THRESHOLD = 4.5  # random base64 is ~5 bits/char, English identifiers ~4


def _entropy(text: str) -> float:
    counts = Counter(text)
    return -sum(n / len(text) * math.log2(n / len(text)) for n in counts.values())


def looks_like_secret(segment: str) -> bool:
    """Heuristic: known credential formats, or long high-entropy tokens."""
    if _KNOWN_TOKEN.search(segment):
        return True
    for match in _HEX_RUN.finditer(segment):
        run = match.group()
        if any(c.isdigit() for c in run) and any(c.isalpha() for c in run):
            return True
    for match in _TOKEN_RUN.finditer(segment):
        run = match.group()
        mixed = (
            any(c.isdigit() for c in run)
            and any(c.isupper() for c in run)
            and any(c.islower() for c in run)
        )
        if mixed and _entropy(run) >= _ENTROPY_THRESHOLD:
            return True
    return False


def redact_path(relative_path: str) -> tuple[str, bool]:
    """Replace secret-looking segments with a stable, non-reversible marker."""
    redacted = False
    segments = []
    for segment in relative_path.split("/"):
        if looks_like_secret(segment):
            segments.append(_marker(segment))
            redacted = True
        else:
            segments.append(segment)
    return "/".join(segments), redacted


_TEXT_TOKEN = re.compile(r"[^\s\"'`]+")


def _marker(secret: str) -> str:
    digest = hashlib.sha256(secret.encode("utf-8", "backslashreplace")).hexdigest()
    return f"<redacted:{digest[:8]}>"


def redact_text(text: str) -> str:
    """Redact secret-looking tokens inside free text (e.g. scanner messages).

    Heuristic only: short or low-entropy secrets are NOT detected (see tests documenting the
    limitation). Callers must therefore never persist raw code text in the first place.
    """
    return _TEXT_TOKEN.sub(
        lambda m: _marker(m.group()) if looks_like_secret(m.group()) else m.group(), text
    )


def sanitize_for_display(text: str) -> str:
    """Escape control, format (bidi / zero-width) and separator characters."""
    text = text.encode("utf-8", "backslashreplace").decode("utf-8")
    out = []
    for ch in text:
        if unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp"):
            code = ord(ch)
            out.append(f"\\u{code:04x}" if code <= 0xFFFF else f"\\U{code:08x}")
        else:
            out.append(ch)
    return "".join(out)


def redact_findings(report: FindingsReport) -> FindingsReport:
    """Copy of a findings report that is safe to persist or display."""

    def finding(f: Finding) -> Finding:
        path, redacted = redact_path(f.relative_path)
        return f.model_copy(
            update={
                "relative_path": path,
                "path_redacted": redacted or f.path_redacted,
                "description": redact_text(f.description),
                "recommendation": redact_text(f.recommendation) if f.recommendation else None,
                "evidence": [
                    e.model_copy(update={"reference": redact_path(e.reference)[0]})
                    for e in f.evidence
                ],
                # the same redaction as relative_path, so R2 path comparisons stay exact
                "identifiers": f.identifiers.model_copy(
                    update={
                        "history_paths": [redact_path(p)[0] for p in f.identifiers.history_paths]
                    }
                ),
            }
        )

    def execution(e: ToolExecution) -> ToolExecution:
        not_analyzed = []
        for item in e.not_analyzed:
            path, redacted = redact_path(item.relative_path)
            detail = redact_text(item.detail) if item.detail else None
            not_analyzed.append(
                item.model_copy(
                    update={
                        "relative_path": path,
                        "path_redacted": redacted or item.path_redacted,
                        "detail": detail,
                    }
                )
            )
        stderr = redact_text(e.stderr_excerpt) if e.stderr_excerpt else None
        limited = []
        for item in e.coverage_limitations:
            path, redacted = redact_path(item.relative_path)
            limited.append(
                item.model_copy(
                    update={"relative_path": path, "path_redacted": redacted or item.path_redacted}
                )
            )
        return e.model_copy(
            update={
                "not_analyzed": not_analyzed,
                "stderr_excerpt": stderr,
                "coverage_limitations": limited,
            }
        )

    def coverage(row):
        path, redacted = redact_path(row.relative_path)
        return row.model_copy(
            update={"relative_path": path, "path_redacted": redacted or row.path_redacted}
        )

    return report.model_copy(
        update={
            "findings": [finding(f) for f in report.findings],
            "tool_executions": [execution(e) for e in report.tool_executions],
            "file_coverage": [coverage(row) for row in report.file_coverage],
        }
    )


def redact_inventory(inventory: RepositoryInventory) -> RepositoryInventory:
    """Copy of the inventory that is safe to persist or display."""

    def file_entry(entry: FileEntry) -> FileEntry:
        path, redacted = redact_path(entry.relative_path)
        return entry.model_copy(
            update={"relative_path": path, "path_redacted": redacted or entry.path_redacted}
        )

    def excluded_entry(entry: ExcludedEntry) -> ExcludedEntry:
        path, redacted = redact_path(entry.relative_path)
        return entry.model_copy(
            update={"relative_path": path, "path_redacted": redacted or entry.path_redacted}
        )

    return inventory.model_copy(
        update={
            "root_name": redact_path(inventory.root_name)[0],
            "files": [file_entry(f) for f in inventory.files],
            "excluded": [excluded_entry(e) for e in inventory.excluded],
        }
    )
