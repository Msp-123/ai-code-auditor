"""The auditor's Semgrep ruleset, verified with the real engine (marked: semgrep).

- ``semgrep --test`` per rule file, sequentially (parallel runs race on Semgrep's
  settings file on Windows and Semgrep still exits 0 — so config errors are checked
  explicitly, not via the exit code).
- A real scan of the fixtures checks rule metadata and that the documented known false
  positives (todook) and false negatives (todoruleid) really behave as documented.
"""

import json
import re
import subprocess
import tempfile
from pathlib import Path

import pytest

from auditor.core.models import FileCategory, FileEntry, FindingCategory
from auditor.scanners.base import ScanContext
from auditor.scanners.executables import semgrep_executable
from auditor.scanners.semgrep_adapter import (
    EVIDENCE_RULE_PREFIX,
    SemgrepAdapter,
    SemgrepOptions,
    semgrep_env,
    short_temp_base,
)
from auditor.scanners.semgrep_rules import RULES_DIR

pytestmark = pytest.mark.semgrep

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "semgrep_rules"
RULE_FILES = sorted(RULES_DIR.glob("*.yaml"))
REQUIRED_METADATA = ("cwe", "owasp", "confidence", "auditor_severity", "auditor_recommendation")


@pytest.fixture(scope="module")
def semgrep():
    exe = semgrep_executable()
    if exe is None:
        pytest.skip("Semgrep is not installed in the tool environment (see README)")
    return str(exe)


def test_every_rule_file_has_a_fixture():
    assert RULE_FILES
    for rule in RULE_FILES:
        assert (FIXTURES / f"{rule.stem}.py").is_file(), f"missing fixture for {rule.name}"


@pytest.mark.parametrize("rule", RULE_FILES, ids=lambda p: p.stem)
def test_rule_passes_its_semgrep_test(semgrep, rule):
    short_temp_base().mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="t-", dir=short_temp_base()) as scratch:
        completed = subprocess.run(  # noqa: S603 - trusted Semgrep, fixed argv
            [
                semgrep,
                "scan",
                "--test",
                "--json",
                "--metrics=off",
                "--disable-version-check",
                "--config",
                str(rule),
                str(FIXTURES / f"{rule.stem}.py"),
            ],
            cwd=scratch,
            env=semgrep_env(Path(scratch)),
            capture_output=True,
            timeout=300,
            check=False,
        )
    data = json.loads(completed.stdout.decode("utf-8"))

    assert data["config_with_errors"] == []
    assert data["config_missing_tests"] == []
    checks = [c for r in data["results"].values() for c in r["checks"].items()]
    assert checks, "no checks ran"
    for check_id, info in checks:
        assert info["passed"], f"{check_id}: {info['matches']}"


@pytest.fixture(scope="module")
def fixture_scan(semgrep, tmp_path_factory):
    """One real adapter run over all rule fixtures (the fixtures are the 'target')."""
    root = FIXTURES.resolve()
    files = [
        FileEntry(
            relative_path=p.name,
            size_bytes=p.stat().st_size,
            category=FileCategory.PYTHON_SOURCE,
            is_sensitive=False,
            ai_context_allowed=True,
            secret_scan_eligible=True,
            oversized=False,
        )
        for p in sorted(root.glob("*.py"))
    ]
    workspace = tmp_path_factory.mktemp("ws")
    return SemgrepAdapter(SemgrepOptions()).scan(
        ScanContext(root=root, files=files, workspace=workspace)
    )


def _annotated(kind: str) -> set[tuple[str, int, str]]:
    """(file, line of the code below the annotation, rule id) for '# kind: id[, id]'."""
    found = set()
    for path in FIXTURES.glob("*.py"):
        lines = path.read_text(encoding="utf-8").splitlines()
        for number, line in enumerate(lines, start=1):
            match = re.match(rf"\s*# {kind}: (.+)$", line)
            if match:
                code_line = number + 1
                while lines[code_line - 1].lstrip().startswith("#"):
                    code_line += 1
                for rule in match.group(1).split(","):
                    found.add((path.name, code_line, rule.strip()))
    return found


def test_fixture_scan_succeeds_and_findings_carry_metadata(fixture_scan):
    assert fixture_scan.execution.status.value == "SUCCESS", fixture_scan.execution.reason
    assert fixture_scan.findings
    for finding in fixture_scan.findings:
        assert finding.category is FindingCategory.SECURITY
        assert finding.verification_status.value == "NEEDS_REVIEW"
        assert any(t.startswith("CWE-") for t in finding.tags), finding.rule_id
        assert any(t.startswith("A") and ":20" in t for t in finding.tags), finding.rule_id
        assert finding.recommendation, finding.rule_id
        assert finding.references and all(r.startswith("https://") for r in finding.references)


def _declared_ids() -> set[str]:
    return {
        m.group(1)
        for rule in RULE_FILES
        for m in re.finditer(r"^\s*- id: (\S+)", rule.read_text(encoding="utf-8"), re.M)
    }


def test_every_rule_id_is_exercised_by_a_finding(fixture_scan):
    declared = {i for i in _declared_ids() if not i.startswith(EVIDENCE_RULE_PREFIX)}
    reported = {f.rule_id for f in fixture_scan.findings}

    assert declared == reported
    for rule in RULE_FILES:  # metadata fields present in the YAML of every rule
        text = rule.read_text(encoding="utf-8")
        for key in REQUIRED_METADATA:
            assert text.count(f"{key}:") >= text.count("- id:"), (rule.name, key)


def test_documented_false_positives_are_really_reported(fixture_scan):
    reported = {(f.relative_path, f.start_line, f.rule_id) for f in fixture_scan.findings}
    for item in _annotated("todook"):
        assert item in reported, f"documented false positive no longer occurs: {item}"


def test_documented_false_negatives_are_really_missed(fixture_scan):
    reported = {(f.relative_path, f.start_line, f.rule_id) for f in fixture_scan.findings}
    for item in _annotated("todoruleid"):
        assert item not in reported, f"documented false negative is now detected: {item}"


def test_expected_findings_and_no_unexpected_ones(fixture_scan):
    reported = {(f.relative_path, f.start_line, f.rule_id) for f in fixture_scan.findings}
    expected = {a for a in _annotated("ruleid") if not a[2].startswith(EVIDENCE_RULE_PREFIX)}
    allowed = expected | _annotated("todook")

    assert expected <= reported
    assert reported <= allowed, f"unexpected: {sorted(reported - allowed)}"


def test_evidence_rules_become_observations_not_findings(fixture_scan):
    """H5: the flow-evidence rules are exercised by the fixture but never reported."""
    expected = {a for a in _annotated("ruleid") if a[2].startswith(EVIDENCE_RULE_PREFIX)}
    assert expected  # the fixture exercises both evidence rules
    observed = {
        (o.relative_path, o.line, EVIDENCE_RULE_PREFIX + o.kind_rule)
        for o in fixture_scan.observations
    }
    assert expected <= observed
    assert not any(f.rule_id.startswith(EVIDENCE_RULE_PREFIX) for f in fixture_scan.findings)
    assert {i for i in _declared_ids() if i.startswith(EVIDENCE_RULE_PREFIX)} == {
        EVIDENCE_RULE_PREFIX + "param-to-sql-text",
        EVIDENCE_RULE_PREFIX + "request-to-call-arg",
    }
