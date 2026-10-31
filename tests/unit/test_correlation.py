"""Stage 6 step 3: finding relations R1-R3 (D-048). Findings are never merged or removed."""

from auditor.core.audit_report import RelationType
from auditor.core.models import (
    Confidence,
    Finding,
    FindingCategory,
    FindingIdentifiers,
    Severity,
    VerificationStatus,
)
from auditor.findings.correlation import relate

BLOB = "b" * 40


def f(fid, tool, rule, path="app.py", line=3, end=None, category=FindingCategory.SECURITY,
      severity=Severity.HIGH, **extra):  # fmt: skip
    return Finding(
        finding_id=fid, fingerprint=fid * 4, source_tool=tool, rule_id=rule, title="t",
        description="d", category=category, severity=severity, confidence=Confidence.HIGH,
        verification_status=VerificationStatus.NEEDS_REVIEW, relative_path=path,
        start_line=line, end_line=end, **extra,
    )  # fmt: skip


def groups_of(findings, relation):
    related, groups = relate(findings)
    return related, [g for g in groups if g.relation is relation]


# --------------------------------------------------------------------------- R1 location


def test_r1_relates_security_findings_of_different_tools_at_the_same_line():
    findings = [f("a", "gitleaks", "gitleaks.generic-api-key"), f("b", "ruff", "S105"),
                f("c", "semgrep", "auditor.x", line=1, end=5)]  # fmt: skip

    related, groups = groups_of(findings, RelationType.SAME_LOCATION)

    (group,) = groups
    assert sorted(group.finding_ids) == ["a", "b", "c"]
    assert group.basis == {"path": "app.py", "line": 3, "tools": ["gitleaks", "ruff", "semgrep"]}
    assert "not the same root cause" in group.statement
    assert len(related) == 3 and all(group.group_id in r.group_ids for r in related)


def test_r1_never_relates_the_same_tool_style_findings_or_other_lines():
    findings = [
        f("a", "ruff", "E401", line=1, category=FindingCategory.STYLE),
        f("b", "ruff", "F401", line=1, category=FindingCategory.MAINTAINABILITY),
        f("c", "ruff", "S105", line=7),
        f("d", "ruff", "S106", line=7),  # same tool
        f("e", "gitleaks", "gitleaks.github-pat", line=9),
        f("g", "semgrep", "auditor.y", line=10),  # adjacent, not overlapping
        f("h", "gitleaks-history", "gitleaks.github-pat", line=9),  # history: not a location
    ]

    _, groups = groups_of(findings, RelationType.SAME_LOCATION)

    assert groups == []


# ------------------------------------------------------------------ R2 working tree/history


def history(fid, rule="gitleaks.github-pat", line=2, paths=("app/c.py",), blob=BLOB, fmt="sha1"):
    return f(fid, "gitleaks-history", rule, path=paths[0], line=line,
             identifiers=FindingIdentifiers(git_object=blob, object_format=fmt,
                                            history_paths=list(paths)),
             tags=["secret", "git-history", "still-in-working-tree"])  # fmt: skip


def tree(fid, rule="gitleaks.github-pat", line=2, path="app/c.py", sha1=BLOB):
    return f(fid, "gitleaks", rule, path=path, line=line,
             content_ids={"sha1": sha1, "sha256": "c" * 64})  # fmt: skip


def test_r2_relates_identical_content_same_path_rule_and_line():
    _, groups = groups_of([history("h"), tree("w")], RelationType.SAME_CONTENT_IN_HISTORY)

    (group,) = groups
    assert sorted(group.finding_ids) == ["h", "w"]
    assert group.basis["path"] == "app/c.py" and group.basis["rule"] == "gitleaks.github-pat"
    assert group.basis["content"] == "identical git blob" and BLOB not in str(group.basis)


def test_r2_needs_every_condition():
    cases = [
        [history("h"), tree("w", sha1="d" * 40)],  # content differs (e.g. CRLF)
        [history("h"), tree("w", path="other.py")],  # other path
        [history("h"), tree("w", rule="gitleaks.generic-api-key")],  # other rule
        [history("h"), tree("w", line=3)],  # other line
        [history("h", fmt="sha256", blob="c" * 40), tree("w")],  # other format
        [history("h", blob=None), tree("w")],  # no verified object
    ]
    for findings in cases:
        _, groups = groups_of(findings, RelationType.SAME_CONTENT_IN_HISTORY)
        assert groups == [], findings


def test_r2_keeps_two_occurrences_on_one_line_as_separate_findings():
    found = [history("h1"), history("h2"), tree("w1"), tree("w2")]

    related, groups = groups_of(found, RelationType.SAME_CONTENT_IN_HISTORY)

    assert len(related) == 4  # nothing merged
    assert {tuple(sorted(g.finding_ids)) for g in groups} == {("h1", "h2", "w1", "w2")}


# --------------------------------------------------------------------------- R3 dependency


def vuln(fid, ids, package="jinja2", version="2.10", path="requirements.txt"):
    return f(fid, "pip-audit", f"pip-audit.{ids[0]}", path=path, severity=Severity.UNRATED,
             identifiers=FindingIdentifiers(package=package, version=version,
                                            vulnerability_ids=list(ids)))  # fmt: skip


def test_r3_relates_the_same_vulnerability_through_ids_or_aliases():
    findings = [vuln("a", ["PYSEC-1", "CVE-1"], path="requirements.txt"),
                vuln("b", ["GHSA-x", "CVE-1"], path="pylock.toml")]  # fmt: skip

    _, groups = groups_of(findings, RelationType.SAME_VULNERABILITY)

    (group,) = groups
    assert sorted(group.finding_ids) == ["a", "b"]
    assert group.basis == {"package": "jinja2", "version": "2.10", "ids": ["CVE-1"]}


def test_r3_needs_package_version_and_a_shared_id():
    for other in (vuln("b", ["CVE-2"]), vuln("b", ["CVE-1"], version="2.11"),
                  vuln("b", ["CVE-1"], package="flask")):  # fmt: skip
        _, groups = groups_of([vuln("a", ["CVE-1"]), other], RelationType.SAME_VULNERABILITY)
        assert groups == []


# ------------------------------------------------------------------------------ invariants


def test_relations_never_remove_merge_or_change_findings():
    findings = [f("a", "gitleaks", "gitleaks.x"), f("b", "ruff", "S105"),
                vuln("c", ["CVE-1"]), vuln("d", ["CVE-1"], path="pylock.toml")]  # fmt: skip

    related, groups = relate(findings)

    assert [r.finding_id for r in related] == [x.finding_id for x in findings]
    for before, after in zip(findings, related, strict=True):
        assert before.model_copy(update={"group_ids": after.group_ids}) == after
    assert len(groups) == 2


def test_group_ids_are_stable_and_independent_of_input_order():
    findings = [f("a", "gitleaks", "gitleaks.x"), f("b", "ruff", "S105")]

    _, first = relate(findings)
    _, second = relate(list(reversed(findings)))

    assert [g.group_id for g in first] == [g.group_id for g in second]
