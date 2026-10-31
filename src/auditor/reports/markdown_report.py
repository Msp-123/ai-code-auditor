"""Human-readable report (report.md), rendered only from the canonical AuditReport.

Untrusted text (paths, tool reasons, warnings, details, advisory text) never reaches the
document unescaped: paths and identifiers are escaped inline code (``md_code``), prose goes
through ``md_text`` and table cells through ``md_cell``. Control, bidi and zero-width
characters are shown as escapes; Markdown syntax, HTML and link syntax are neutralised.
"""

import re
from collections import Counter

from auditor.core.audit_report import AreaStatus, AuditReport, GateStatus
from auditor.core.models import (
    SEVERITY_RANK,
    CoverageStatus,
    ExclusionReason,
    Finding,
    IncompleteReason,
    NotAnalyzedReason,
    ScanStatus,
    Severity,
    ToolExecution,
    ToolStatus,
)
from auditor.core.redaction import redact_inventory, sanitize_for_display
from auditor.reports.terminal_summary import context_counts

MAX_LISTED = 200

_EXCLUSION_TEXT = {
    ExclusionReason.VCS_METADATA: "version-control metadata (not part of discovery)",
    ExclusionReason.VIRTUALENV: "virtual environment (contains pyvenv.cfg)",
    ExclusionReason.EXCLUDED_DIR: "excluded by default directory policy",
    ExclusionReason.SYMLINK: "symlink, not followed",
    ExclusionReason.JUNCTION: "Windows junction, not followed",
    ExclusionReason.REPARSE_POINT: "Windows reparse point, not followed",
    ExclusionReason.SPECIAL_FILE: "special file (device, FIFO, socket)",
    ExclusionReason.INVALID_NAME: "invalid entry name",
    ExclusionReason.UNREADABLE: "could not be read",
    ExclusionReason.MAX_DEPTH: "deeper than max_depth",
    ExclusionReason.CHANGED_DURING_SCAN: "changed while being scanned",
}

_INCOMPLETE_TEXT = {
    IncompleteReason.MAX_FILES: "file limit (max_files) reached",
    IncompleteReason.MAX_ENTRIES: "entry limit (max_entries_visited) reached",
    IncompleteReason.MAX_DEPTH: "directories deeper than max_depth were not scanned",
    IncompleteReason.TIMEOUT: "time limit (max_duration_seconds) reached",
    IncompleteReason.UNREADABLE: "some entries could not be read",
    IncompleteReason.CHANGED_DURING_SCAN: "some directories changed during the scan",
    IncompleteReason.SCANNER_NOT_INSTALLED: "a scanner is not installed",
    IncompleteReason.SCANNER_ERROR: "a scanner failed",
    IncompleteReason.SCANNER_TIMED_OUT: "a scanner timed out",
    IncompleteReason.FILES_NOT_ANALYZED: "some files could not be analyzed by a scanner",
    IncompleteReason.FILES_ANALYZED_WITH_LIMITATIONS: (
        "some files were scanned only with limitations (e.g. syntax errors)"
    ),
    IncompleteReason.CLEANUP_FAILED: (
        "temporary data of the auditor could not be removed (security error, see below)"
    ),
}


_NOT_ANALYZED_TEXT = {
    NotAnalyzedReason.PARSE_ERROR: "could not be parsed; no other rule ran on it",
    NotAnalyzedReason.IO_ERROR: "could not be read (e.g. not valid UTF-8)",
    NotAnalyzedReason.CHANGED_BEFORE_SCAN: "changed or replaced before the scan",
    NotAnalyzedReason.BATCH_FAILED: "the scanner run for this file failed",
    NotAnalyzedReason.TIMED_OUT: "the scanner timed out",
    NotAnalyzedReason.TOOL_ERROR: "the scanner reported an error for this file",
    NotAnalyzedReason.SKIPPED_BY_TOOL: "the scanner skipped this file",
    NotAnalyzedReason.SIZE_LIMIT: "larger than the scanner's file size limit",
    NotAnalyzedReason.NETWORK_NOT_ALLOWED: "dependencies not checked: network permission not "
    "granted (--allow-network)",
    NotAnalyzedReason.UNSUPPORTED_MANIFEST: "format not supported or never executed; its "
    "dependencies were not audited",
    NotAnalyzedReason.UNSAFE_REPOSITORY: "git history not scanned: the repository structure "
    "cannot be copied safely",
}


def md_code(text: str) -> str:
    """Inline code span that is safe for any text (CommonMark backtick fencing)."""
    text = sanitize_for_display(text)
    longest = run = 0
    for ch in text:
        run = run + 1 if ch == "`" else 0
        longest = max(longest, run)
    fence = "`" * (longest + 1)
    pad = " " if text.startswith("`") or text.endswith("`") or not text else ""
    return f"{fence}{pad}{text}{pad}{fence}"


# "[" and "]" are escaped, so "(" ")" can never form a link and stay readable.
_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]#!|~>])")


def md_text(text: str) -> str:
    """Prose from untrusted data: no Markdown, HTML, link or control-character effects."""
    text = sanitize_for_display(text).replace("&", "&amp;").replace("<", "&lt;")
    return _MD_SPECIAL.sub(r"\\\1", text)


def md_cell(text: str) -> str:
    """A table cell from untrusted data (pipes and line breaks cannot leave the cell)."""
    return md_text(text)


def _listing(paths: list[str], notes: list[str] | None = None) -> list[str]:
    notes = notes or [""] * len(paths)
    lines = [f"- {md_code(p)}{n}" for p, n in zip(paths[:MAX_LISTED], notes, strict=False)]
    if len(paths) > MAX_LISTED:
        lines.append(f"- ... and {len(paths) - MAX_LISTED} more (see inventory.json)")
    return lines


def _scanner_section(execution: ToolExecution, findings: list[Finding]) -> list[str]:
    settings = execution.settings
    title = md_text(execution.tool.capitalize())
    lines = [
        f"## {title}",
        "",
        f"- Status: **{execution.status.value}** - {md_text(execution.reason)}",
        f"- Version: {md_code(execution.version or 'unknown')}",
        f"- Files analyzed: {execution.files_analyzed} of {execution.files_requested}",
        f"- Duration: {execution.duration_seconds:.2f}s",
    ]
    if "target_python" in settings:
        lines.append(
            f"- Target Python: {settings['target_python']} ({settings['target_python_source']})"
        )
    for key in (
        "rules",
        "ruleset_version",
        "ruleset_sha256",
        "ignore_noqa",
        "nosem",
        "config_files",
        "gitignore",
        "cache",
        "method",
        "workers",
        "config",
        "redaction",
        "log_level",
        "target_config",
        "input_check",
        "path_rules",
        "path_allowlists",
        "scope_working_tree",
        "scope_git_history",
        "service",
        "dependencies",
        "markers",
        "severity",
        "result_wording",
        "formats",
        "proxy",
        "scope_history",
        "attribution",
        "personal_data",
        "limits",
        "commits",
        "blobs_reachable",
        "blobs_scanned",
        "commit_messages_scanned",
        "git",
        "network",
    ):
        if key in settings:
            lines.append(f"- {key.replace('_', ' ').capitalize()}: {md_code(settings[key])}")
    lines.append("")
    if settings.get("disabled_by_user") == "true":
        lines += [
            f"> **{title} was disabled by the user.** Nothing in this report reflects {title} "
            "analysis.",
            "",
        ]
        return lines

    if execution.status is not ToolStatus.SUCCESS:
        lines += [
            f"> {title} did not complete successfully. Findings below (if any) are partial; "
            "the absence of findings is **not** a clean result.",
            "",
        ]

    severity_counts = Counter(f.severity for f in findings)
    summary = ", ".join(f"{s.value} {severity_counts[s]}" for s in Severity if severity_counts[s])
    lines += [f"**{len(findings)} findings**" + (f": {summary}" if summary else ""), ""]
    if findings:
        rules = Counter((f.rule_id, f.title, f.severity) for f in findings)
        lines += ["| Rule | Name | Severity | Count |", "|---|---|---|---|"]
        for (rule, name, severity), count in sorted(
            rules.items(), key=lambda item: (SEVERITY_RANK[item[0][2]], item[0][0])
        ):
            lines.append(f"| {md_code(rule)} | {md_code(name)} | {severity.value} | {count} |")
        lines += ["", "### Findings", ""]
        ordered = sorted(
            findings,
            key=lambda f: (SEVERITY_RANK[f.severity], f.relative_path, f.start_line or 0),
        )
        for f in ordered[:MAX_LISTED]:
            where = f.relative_path + (f":{f.start_line}" if f.start_line else "")
            lines.append(
                f"- **{f.severity.value}** [{f.context.value}] {md_code(f.rule_id)} "
                f"{md_code(where)} {md_code(f.description)}"
            )
        if len(ordered) > MAX_LISTED:
            lines.append(f"- ... and {len(ordered) - MAX_LISTED} more (see findings.json)")
        lines.append("")

    if execution.suppressed:
        total = sum(s.count for s in execution.suppressed)
        lines += [
            f"### Suppressed by policy ({total}, not counted above)",
            "",
            *[
                f"- {md_code(s.rule_id)}: {s.count} - {md_text(s.reason)}; "
                "the rule still applies to all non-test code"
                for s in execution.suppressed
            ],
            "",
        ]

    if execution.coverage_limitations:
        lines += [
            f"### Scanned with limitations by {title} ({len(execution.coverage_limitations)})",
            "",
            "These files were scanned, but the analysis may be incomplete. Findings from them "
            "are kept.",
            "",
        ]
        for item in execution.coverage_limitations[:MAX_LISTED]:
            detail = md_text(item.detail or item.reason)
            lines.append(f"- {md_code(item.relative_path)} - {detail}")
        lines.append("")

    if execution.not_analyzed:
        lines += [f"### Not analyzed by {title} ({len(execution.not_analyzed)})", ""]
        for item in execution.not_analyzed[:MAX_LISTED]:
            lines.append(f"- {md_code(item.relative_path)} - {_NOT_ANALYZED_TEXT[item.reason]}")
        lines.append("")
    if execution.warnings:
        lines += ["### Warnings", ""]
        lines += [f"- {md_text(w)}" for w in dict.fromkeys(execution.warnings)]
        lines.append("")
    return lines


def _findings_summary(audit: AuditReport) -> list[str]:
    outcome, gate = audit.outcome, audit.gate
    counts = ", ".join(f"{k} {v}" for k, v in outcome.by_severity.items())
    unrated = (f"; {outcome.unrated} UNRATED: the tool gives no severity, the gate counts it as "
               f"{gate.unrated_as}" if outcome.unrated else "")  # fmt: skip
    groups = (
        f" - {outcome.related_groups} relation group(s) cover {outcome.findings_in_groups} "
        "finding(s); every finding is still counted"
        if outcome.related_groups
        else ""
    )
    gate_line = f"- Gate: **{gate.status.value}**"
    if gate.status is GateStatus.NOT_EVALUATED:
        gate_line += " (`--fail-on none`: findings do not change the exit code)"
    else:
        gate_line += (f" (`--fail-on {gate.fail_on}`, UNRATED as {gate.unrated_as}): "
                      f"{gate.counted} finding(s) at or above the threshold")  # fmt: skip
    context = ([f"- Context: {context_counts(outcome.by_context)} (path-based, not a security "
                "proof: derived from directory and file names only)"]
               if outcome.by_context else [])  # fmt: skip
    return [
        f"- Findings: **{outcome.total}**" + (f" ({counts}{unrated})" if counts else "") + groups,
        *context,
        gate_line,
        "- Meaning of the status: COMPLETE describes coverage only; it does not mean that no "
        "problems were found or that the project is safe. PARTIAL means some areas were not "
        "covered. Coverage and the gate are independent.",
    ]


def _areas_section(audit: AuditReport) -> list[str]:
    lines = ["## Coverage by area", "", "| Area | Tool | Status | Reason |", "|---|---|---|---|"]
    for a in audit.coverage.areas:
        lines.append(
            f"| {md_cell(a.area)} | {md_cell(a.tool or '-')} | {a.status.value} "
            f"| {md_cell(a.reason)} |"
        )
    return [*lines, ""]


def _groups_section(audit: AuditReport) -> list[str]:
    if not audit.groups:
        return []
    lines = [
        f"## Related findings ({len(audit.groups)} groups)",
        "",
        "Relations never merge or remove findings; each member is listed above.",
        "",
    ]
    for g in audit.groups[:MAX_LISTED]:
        basis = ", ".join(f"{k}={v}" for k, v in g.basis.items())
        lines.append(
            f"- {md_code(g.group_id)} **{g.relation.value}** ({md_text(basis)}): "
            f"{', '.join(md_code(i) for i in g.finding_ids)} - {md_text(g.statement)}"
        )
    return [*lines, ""]


def _coverage_summary(audit: AuditReport) -> dict[str, dict[str, int]]:
    summary: dict[str, Counter] = {}
    for row in audit.file_coverage:
        for tool, state in row.scanners.items():
            summary.setdefault(tool, Counter())[state.status.value] += 1
    return {tool: dict(sorted(c.items())) for tool, c in sorted(summary.items())}


def render_markdown(audit: AuditReport) -> str:
    inv = redact_inventory(audit.discovery)
    is_audit = audit.mode == "audit"
    status = audit.coverage.status
    title = "Audit Report" if is_audit else "Discovery Report"
    lines = [f"# AI Code Auditor - {title}", ""]

    if status is ScanStatus.PARTIAL:
        reasons = "; ".join(_INCOMPLETE_TEXT[r] for r in audit.coverage.incomplete_reasons)
        lines += [
            "> **WARNING: PARTIAL SCAN - the results are INCOMPLETE.**",
            f"> Reasons: {reasons}.",
        ]
        if inv.status is ScanStatus.PARTIAL:
            lines.append(f"> Directories never visited: {inv.unvisited_directories}.")
        lines += ["> Do not treat this report as full coverage of the target.", ""]

    for error in audit.operational_errors:
        lines += [
            f"> **SECURITY ERROR [{error.code.value}] ({md_text(error.component)}):** "
            f"{md_text(error.message)}",
            "> The findings below are still valid; the run itself did not end cleanly.",
            "",
        ]
    for warning in audit.operational_warnings:
        lines += [
            f"> **SECURITY WARNING [{warning.code.value}] ({md_text(warning.component)}):** "
            f"{md_text(warning.message)}",
            "",
        ]

    if any(n.reason is NotAnalyzedReason.NETWORK_NOT_ALLOWED for e in audit.tools
           for n in e.not_analyzed):  # fmt: skip
        lines += [
            "> **Dependency vulnerabilities were NOT checked: network permission not granted.** "
            "Run with `--allow-network` to check them; exact package names and versions are "
            "then sent to api.osv.dev.",
            "",
        ]

    disabled = [a for a in audit.coverage.areas if a.status is AreaStatus.DISABLED]
    if disabled:
        names = ", ".join(f"{md_text(a.area)} ({md_text(a.tool or '-')})" for a in disabled)
        lines += [
            f"> **NOTE: disabled by the user (--disable-scanner): {names}.** This report "
            "contains no analysis for these areas and is not a complete security audit.",
            "",
        ]

    lines.append(f"- Status: **{status.value}**")
    if is_audit:
        lines += _findings_summary(audit)
        not_requested = [a.area for a in audit.coverage.areas
                         if a.status is AreaStatus.NOT_REQUESTED]  # fmt: skip
        if not_requested:
            lines.append(f"- Not requested (not scanned): {', '.join(not_requested)}")
    lines += [
        f"- Target: {md_code(audit.target_name)} (local, read-only)",
        f"- Run ID: {md_code(audit.run.run_id)}",
        f"- Started (UTC): {audit.run.started_at.isoformat()}",
        f"- Duration: {audit.run.duration_seconds:.2f}s",
        f"- Entries visited: {inv.entries_visited}",
        f"- Schema version: {audit.schema_version} (report.json; {audit.report_schema})",
        "",
    ]
    if is_audit:
        lines += _areas_section(audit)
    lines += [
        "## Files considered",
        "",
        "| Category | Files |",
        "|---|---|",
    ]
    lines += [f"| {cat} | {n} |" for cat, n in inv.files_by_category.items()]
    lines += [f"| **total** | **{len(inv.files)}** |", ""]

    coverage_note = (
        "Only scanners with status SUCCESS produced complete results. Any other status means "
        "that scanner's area was **not** covered - never a clean result."
        if is_audit
        else "Discovery only. No scanner has run, so **no findings exist yet** - this is not "
        "a clean result."
    )
    lines += [
        "## Scanner coverage",
        "",
        coverage_note,
        "",
        "| Tool | Status | Reason |",
        "|---|---|---|",
    ]
    lines += [
        f"| {md_cell(s.tool)} | {s.status.value} | {md_cell(s.reason)} |" for s in inv.scanners
    ]
    lines.append("")

    if is_audit:
        for execution in audit.tools:
            tool_findings = [f for f in audit.findings if f.source_tool == execution.tool]
            lines += _scanner_section(execution, tool_findings)
        lines += _groups_section(audit)
        summary = _coverage_summary(audit)
        if summary:
            statuses = [s.value for s in CoverageStatus]
            lines += [
                "## File coverage",
                "",
                "Every inventory file has a state per scanner (details in report.json).",
                "",
                "| Scanner | " + " | ".join(statuses) + " |",
                "|---|" + "---|" * len(statuses),
            ]
            for tool, counts in summary.items():
                cells = " | ".join(str(counts.get(s, 0)) for s in statuses)
                lines.append(f"| {md_cell(tool)} | {cells} |")
            lines.append("")

    lines += ["## Excluded or not scanned", ""]
    if not inv.excluded:
        lines += ["Nothing was excluded.", ""]
    for reason, count in inv.excluded_by_reason.items():
        reason_enum = ExclusionReason(reason)
        lines += [f"### {reason} ({count}) - {_EXCLUSION_TEXT[reason_enum]}", ""]
        entries = [e for e in inv.excluded if e.reason is reason_enum]
        notes = [
            " - target outside the scan root" if e.points_outside_root else "" for e in entries
        ]
        lines += _listing([e.relative_path for e in entries], notes)
        lines.append("")

    sensitive = [f.relative_path for f in inv.files if f.is_sensitive]
    lines += [
        "## Sensitive files",
        "",
        f"{len(sensitive)} file(s) match sensitive-file patterns. Their contents were not "
        "read, are never sent to AI context, and remain eligible for secret scanning "
        "(Stage 4).",
        "",
    ]
    lines += [*_listing(sensitive), ""] if sensitive else []

    oversized = [f.relative_path for f in inv.files if f.oversized]
    if oversized:
        lines += [
            "## Oversized files",
            "",
            f"Larger than {inv.limits.max_file_size_bytes} bytes; listed but excluded from "
            "AI context.",
            "",
            *_listing(oversized),
            "",
        ]

    redacted = sum(f.path_redacted for f in inv.files) + sum(e.path_redacted for e in inv.excluded)
    warnings = list(audit.warnings)  # canonical (equals the inventory warnings when built)
    if redacted:
        warnings.append(f"{redacted} path(s) contained secret-looking names and are redacted.")
    if warnings:
        lines += ["## Warnings", "", *[f"- {md_text(w)}" for w in warnings], ""]

    history = next((e for e in audit.tools if e.tool == "gitleaks-history"), None)
    lines += [
        "## Limits",
        "",
        "| Limit | Value |",
        "|---|---|",
        f"| max_files | {inv.limits.max_files} |",
        f"| max_entries_visited | {inv.limits.max_entries_visited} |",
        f"| max_depth | {inv.limits.max_depth} |",
        f"| max_file_size_bytes | {inv.limits.max_file_size_bytes} |",
        f"| max_duration_seconds | {inv.limits.max_duration_seconds} |",
        "",
        "## Method",
        "",
        "- Discovery used metadata only: directory listings and file sizes.",
        "- Ruff (if run) read Python files in its own process with the auditor's trusted "
        "rules: target configuration ignored, no cache, no fixes, `# noqa` ignored."
        if is_audit
        else "- Metadata only: no file contents were read.",
        "- Links (symlinks, junctions, reparse points) are never followed.",
        "- The target was not modified and no code from it was executed.",
        "- Redaction of secret-looking names and message fragments is heuristic. It reduces "
        "exposure but does **not** guarantee that no secret appears in this report.",
        *[
            f"- {_LIMITATION_LABEL.get(item.tool, item.tool)} limitation: {item.text}"
            for item in audit.limitations
        ],  # fmt: skip
        _git_history_line(history),
        "- Privacy: this report never contains secret values, file contents, commit messages, "
        "author names or e-mail addresses; it is not prepared for AI context.",
        "",
    ]
    return "\n".join(lines)


_LIMITATION_LABEL = {"semgrep": "Semgrep", "gitleaks": "Gitleaks", "pip-audit": "pip-audit",
                     "gitleaks-history": "git history"}  # fmt: skip


def _git_history_line(history) -> str:
    if history is None:
        return (
            "- Version-control metadata (e.g. `.git`) is outside discovery. Git history: "
            "**NOT_SCANNED** (a separate, explicitly enabled scan: `--scan-git-history`)."
        )
    state = "scanned" if history.status is ToolStatus.SUCCESS else f"**{history.status.value}**"
    return (
        f"- Git history: {state} by the separate gitleaks-history scan (see its section); "
        "git never ran on the target's own .git."
    )
