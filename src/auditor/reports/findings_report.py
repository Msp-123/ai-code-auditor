"""Legacy machine-readable findings report (findings.json, kept for one release, D-048).

findings.json keeps the Stage 2-5 format exactly: pip-audit findings appear with the MEDIUM
placeholder (``original_severity`` stays "UNRATED"), and the Stage 6 fields ``identifiers`` and
``group_ids`` are not included. The canonical data, with ``severity: UNRATED``, is report.json.
"""

import json
from collections import Counter

from auditor.core.models import Finding, FindingsReport, Severity
from auditor.core.redaction import redact_findings

# Canonical-only fields: the legacy findings.json keeps its Stage 2-5 shape for one release.
_STAGE6_FIELDS = {"identifiers", "group_ids", "context", "context_basis"}


def legacy_finding(finding: Finding) -> dict:
    data = finding.model_dump(mode="json", exclude=_STAGE6_FIELDS)
    if finding.severity is Severity.UNRATED:
        data["severity"] = Severity.MEDIUM.value
    return data


def render_findings_json(report: FindingsReport) -> str:
    redacted = redact_findings(report)
    data = redacted.model_dump(mode="json")
    data["findings"] = [legacy_finding(f) for f in redacted.findings]
    counts = Counter(f["severity"] for f in data["findings"])
    data["findings_by_severity"] = {s.value: counts[s.value] for s in Severity if counts[s.value]}
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"
