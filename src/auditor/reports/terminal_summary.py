"""Terminal summary, rendered only from the canonical AuditReport (scan and report commands).

Every value from the report passes ``sanitize_for_display`` (control, ANSI and bidi characters
become visible escapes), because a report read back by ``auditor report`` is untrusted data.
"""

from collections import Counter

from auditor.core.audit_report import AreaStatus, AuditReport, GateStatus
from auditor.core.models import FileContext, ScanStatus, Severity, ToolStatus
from auditor.core.redaction import sanitize_for_display as safe

_LIMITATION_TEXT = {
    "SYNTAX_ERROR_RECOVERY": "syntax errors",
    "PATH_RULES_UNAVAILABLE": "path-dependent rules not applied",
    "CONTENT_NOT_DECODED": "archives not extracted",
    "DEPENDENCIES_NOT_AUDITED": "dependency entries not audited",
}
_NOUN = {"gitleaks": "files", "pip-audit": "dependency manifests",
         "gitleaks-history": "history objects"}  # fmt: skip


def _counts(counter: dict[str, int]) -> str:
    return ", ".join(f"{safe(k)} {v}" for k, v in counter.items())


def _gate_line(audit: AuditReport) -> str:
    gate = audit.gate
    if gate.status is GateStatus.NOT_EVALUATED:
        return "Gate:      NOT_EVALUATED (--fail-on none; findings do not change the exit code)"
    return (
        f"Gate:      {gate.status.value} (--fail-on {safe(gate.fail_on)}, UNRATED as "
        f"{safe(gate.unrated_as)}): {gate.counted} finding(s) at or above the threshold"
    )


def _total_line(audit: AuditReport) -> str:
    o = audit.outcome
    unrated = (f" - {o.unrated} UNRATED (no severity from the tool; the gate counts it as "
               f"{safe(audit.gate.unrated_as)})" if o.unrated else "")  # fmt: skip
    groups = (f"; {o.related_groups} relation group(s), every finding counted"
              if o.related_groups else "")  # fmt: skip
    detail = _counts(o.by_severity)
    return f"Total:     {o.total} findings" + (f" [{detail}]" if detail else "") + unrated + groups


def context_counts(by_context: dict[str, int]) -> str:
    """'production 1, test 2, ...' in FileContext order (shared by terminal and Markdown)."""
    return ", ".join(
        f"{c.value} {by_context[c.value]}" for c in FileContext if c.value in by_context
    )


def _context_line(audit: AuditReport) -> list[str]:
    if not audit.outcome.by_context:
        return []
    return [
        f"Context:   {context_counts(audit.outcome.by_context)} (path-based, not a security proof)"
    ]


def _tool_lines(audit: AuditReport) -> list[str]:
    lines = []
    history_ran = any(e.tool == "gitleaks-history" for e in audit.tools)
    for execution in audit.tools:
        label = f"{safe(execution.tool).capitalize() + ':':<10}"
        if execution.settings.get("disabled_by_user") == "true":
            lines.append(f"{label} DISABLED by user - no {safe(execution.tool)} coverage in this "
                         "run (not a complete audit)")  # fmt: skip
            continue
        own = [f for f in audit.findings if f.source_tool == execution.tool]
        counts = Counter(f.severity for f in own)
        detail = ", ".join(f"{s.value} {counts[s]}" for s in Severity if counts[s])
        suppressed = ", ".join(f"+{s.count} suppressed: {safe(s.rule_id)} in test files"
                               for s in execution.suppressed)  # fmt: skip
        not_run = ", not run" if execution.status is ToolStatus.SKIPPED else ""
        lines.append(f"{label} {execution.status.value} (version "
                     f"{safe(execution.version or 'unknown')}{not_run}) - {len(own)} findings"
                     + (f" [{detail}]" if detail else "")
                     + (f" ({suppressed})" if suppressed else ""))  # fmt: skip
        lines += [f"           NOTE: {safe(w)}" for w in dict.fromkeys(execution.warnings)]
        if execution.coverage_limitations:
            kinds = sorted({_LIMITATION_TEXT.get(i.reason, safe(i.reason))
                            for i in execution.coverage_limitations})  # fmt: skip
            lines.append(f"           {len(execution.coverage_limitations)} file(s) scanned with "
                         f"limitations ({', '.join(kinds)}; see report)")  # fmt: skip
        s = execution.settings
        noun = _NOUN.get(execution.tool, "Python files")
        context = (
            f"target Python {safe(s['target_python'])} ({safe(s['target_python_source'])})"
            if "target_python" in s and "target_python_source" in s
            else f"ruleset {safe(s['ruleset_version'])}" if "ruleset_version" in s
            else "working tree only; git history: see Gitleaks-history"
            if "scope_git_history" in s and history_ran
            else "working tree only; git history NOT_SCANNED" if "scope_git_history" in s
            else f"{safe(s['commits'])} commits, all refs; git {safe(s.get('git', '?'))}"
            if "commits" in s
            else safe(execution.reason)
        )  # fmt: skip
        lines.append(f"           {execution.files_analyzed}/{execution.files_requested} {noun} "
                     f"analyzed; {context}")  # fmt: skip
    return lines


def summary(audit: AuditReport, paths=None, quiet: bool = False) -> tuple[list[str], list[str]]:
    """(stdout lines, stderr lines). ``paths`` (ReportPaths) only after a fresh scan."""
    inv = audit.discovery
    out = ["AI Code Auditor - audit (read-only)", f"Target:    {safe(audit.target_name)}"]
    meaning = (" (coverage only - not a verdict on findings)"
               if audit.coverage.status is ScanStatus.COMPLETE else "")  # fmt: skip
    out.append(f"Status:    {audit.coverage.status.value}{meaning}")
    out.append(
        "Coverage:  " + ", ".join(f"{a.area} {a.status.value}" for a in audit.coverage.areas)
    )
    disabled = [a for a in audit.coverage.areas if a.status is AreaStatus.DISABLED]
    if disabled:
        out.append("Disabled:  " + ", ".join(f"{a.area} ({safe(a.tool or '-')})" for a in disabled)
                   + " - switched off by the user: not part of this audit")  # fmt: skip
    if not quiet:
        categories = ", ".join(f"{safe(k)} {v}" for k, v in inv.files_by_category.items())
        excluded = ", ".join(f"{safe(k)} {v}" for k, v in inv.excluded_by_reason.items())
        out += [
            f"Files:     {len(inv.files)} ({categories or 'none'})",
            f"Excluded:  {len(inv.excluded)} ({excluded or 'none'})",
            f"Sensitive: {inv.sensitive_file_count} (never sent to AI; eligible for secret scan)",
            *_tool_lines(audit),
        ]
    out += [_total_line(audit), *_context_line(audit), _gate_line(audit)]
    if paths is not None:
        out.append(f"Report:    {safe(str(paths.markdown))}")
        if not quiet:
            out.append(f"JSON:      {safe(str(paths.report_json))} (canonical, schema "
                       f"{audit.schema_version})")  # fmt: skip
            out.append(
                f"Legacy:    {safe(str(paths.inventory_json))}"
                + (f", {safe(str(paths.findings_json))}" if paths.findings_json else "")
            )
    err = []
    for error in audit.operational_errors:
        err.append(f"SECURITY ERROR [{error.code.value}] ({safe(error.component)}): "
                   f"{safe(error.message)}")  # fmt: skip
    for warning in audit.operational_warnings:
        err.append(f"SECURITY WARNING [{warning.code.value}] ({safe(warning.component)}): "
                   f"{safe(warning.message)}")  # fmt: skip
    if audit.coverage.status is ScanStatus.PARTIAL:
        reasons = ", ".join(r.value for r in audit.coverage.incomplete_reasons)
        err.append(f"WARNING: PARTIAL scan - results are INCOMPLETE ({reasons}). "
                   "This is not full coverage of the target.")  # fmt: skip
    if audit.gate.status is GateStatus.FAILED:
        err.append(f"QUALITY GATE FAILED: {audit.gate.counted} finding(s) at or above "
                   f"{safe(audit.gate.fail_on).upper()}.")  # fmt: skip
    return out, err
