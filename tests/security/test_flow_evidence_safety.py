"""H5 evidence is data from the target: attacker-chosen names must come out normalised and
inert in report.json, report.md and the terminal, and must never carry code or values."""

import json
import textwrap

import pytest
from tests.unit.test_flow_evidence import finding

from auditor.application.audit_service import run_audit
from auditor.core.models import FindingCategory, Severity, VerificationStatus
from auditor.findings.flow_verification import FlowObservation, apply_flow_evidence
from auditor.reports.markdown_report import render_markdown
from auditor.reports.terminal_summary import summary

# a directory name an attacker controls (must be creatable on Windows, so no < > : | or
# control characters here): bidi override, zero-width space, Markdown link/emphasis/code
HOSTILE_DIR = "v‮​[go](evil.invalid)`b`_c_#!~"  # no * ? < > : | (Windows)
VIEW = """
    from flask import request
    import lib
    def v():
        return lib.find(request.form["u"])
"""
LIB = """
    import sqlite3
    def find(name):
        c = sqlite3.connect("db").cursor()
        return c.execute("SELECT secret FROM t WHERE n = '%s'" % name).fetchall()
"""
RAW_CONTROL = {"\x1b", "‮", "​"}


def hostile_project(tmp_path):
    root = tmp_path / "project"  # the output directory must never be inside the target
    (root / HOSTILE_DIR).mkdir(parents=True)
    (root / HOSTILE_DIR / "view.py").write_text(textwrap.dedent(VIEW).lstrip("\n"), "utf-8")
    (root / "lib.py").write_text(textwrap.dedent(LIB).lstrip("\n"), "utf-8")
    return root


def test_evidence_reference_is_normalised_and_holds_no_code(tmp_path):
    root = hostile_project(tmp_path)
    call_file = f"{HOSTILE_DIR}/view.py"
    obs = [FlowObservation("sql_sink", "lib.py", 4, 16),
           FlowObservation("request_call", call_file, 4, 21)]  # fmt: skip

    (f,), verified = apply_flow_evidence(root, [finding(relative_path="lib.py", start_line=4)], obs)

    assert verified == 1 and f.severity is Severity.HIGH
    assert f.verification_status is VerificationStatus.NEEDS_REVIEW
    (evidence,) = f.evidence
    assert not (set(evidence.reference) & RAW_CONTROL)  # control/bidi/zero-width made visible
    assert evidence.reference.endswith(" request data -> find(name) -> lib.py:4 SQL text")
    for forbidden in ("SELECT", "secret", "request.form", str(root)):
        assert forbidden not in evidence.reference


def test_names_that_are_not_identifiers_are_never_written(tmp_path):
    """Function and parameter names come from the AST, so they are identifiers; the guard
    stays as defence in depth should a resolver change ever hand over anything else."""
    from auditor.findings import flow_verification as fv

    assert fv.safe_name("login") == "login"
    assert fv.safe_name("lo\x1bgin") == "<non-identifier>"
    assert fv.safe_name("x" * 200) == "<non-identifier>"
    # paths: control, ANSI and bidi characters become visible escapes; length is bounded
    assert fv.safe_path("a\x1b[31m‮/b.py") == "a\\u001b[31m\\u202e/b.py"
    assert fv.safe_path("<img src=x>|y.py") == "<img src=x>|y.py"  # escaped by the renderers
    assert len(fv.safe_path("d/" * 300 + "x.py")) <= fv.MAX_REFERENCE_PATH + 1


@pytest.mark.semgrep
def test_hostile_names_are_inert_in_every_output(tmp_path, out_dir):
    root = hostile_project(tmp_path)

    run = run_audit(root, out_dir, disabled=("gitleaks", "pip-audit"))

    high = [f for f in run.audit.findings if "verified-data-flow" in f.tags]
    assert high and all(f.verification_status is VerificationStatus.NEEDS_REVIEW for f in high)
    assert all(f.category is FindingCategory.SECURITY for f in high)
    assert not any(
        f.rule_id.startswith("auditor.python.flow-evidence.") for f in run.audit.findings
    )
    text = json.dumps(json.loads(run.reports.report_json.read_text("utf-8")))  # valid, re-encoded
    assert "SELECT" not in text and str(root) not in text
    markdown = render_markdown(run.audit)
    out, err = summary(run.audit, run.reports)
    for rendered in (markdown, out + err):
        assert not (set(rendered) & RAW_CONTROL)
    assert "<img" not in markdown and "](http://evil.invalid)" not in markdown
