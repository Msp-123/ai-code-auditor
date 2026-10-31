"""P9 (RC validation): finding identities must not depend on the order in which Gitleaks
reports results. Working-tree (4a) and git-history (4b) scans together, real Gitleaks,
several secrets per file and two matches on one line, repeated runs compared as sets."""

import pytest

from auditor.application.audit_service import run_audit
from auditor.scanners.git_history_adapter import GitHistoryOptions

pytestmark = pytest.mark.gitleaks
DISABLED = ("ruff", "semgrep", "pip-audit")


def _repo(git_builder, fake_secrets):
    r = git_builder()
    r.write(
        ".bash_profile",
        f"export A={fake_secrets['aws']}\nexport G={fake_secrets['github']}\n"
        f"export S={fake_secrets['slack']}\nexport X={fake_secrets['generic']}\n",
    )
    r.write(
        "two.txt", f"a={fake_secrets['github']} b={fake_secrets['aws']}\n"
    )  # one line, 2 matches
    r.write("key.pem", fake_secrets["pem"] + "\n")
    r.commit("c1")
    r.write("later.txt", f"t={fake_secrets['jwt']}\n")
    r.commit("c2")
    return r


def _identity(run):
    return {
        tool: sorted(
            (f.rule_id, f.relative_path, f.start_line, f.start_column, f.end_column, f.fingerprint,
             f.finding_id, f.severity.value, tuple(f.tags))
            for f in run.audit.findings
            if f.source_tool == tool
        )
        for tool in ("gitleaks", "gitleaks-history")
    }  # fmt: skip


def test_working_tree_and_history_identities_are_stable_across_runs(
    git_builder, fake_secrets, out_dir
):
    r = _repo(git_builder, fake_secrets)
    runs = []
    for i in range(3):
        out = out_dir / f"run{i}"
        out.mkdir(parents=True)
        runs.append(
            run_audit(r.path, out, git_history_options=GitHistoryOptions(), disabled=DISABLED)
        )

    identities = [_identity(run) for run in runs]
    assert identities[0]["gitleaks"] and identities[0]["gitleaks-history"]
    assert all(i == identities[0] for i in identities)
    # the two matches on one line are two findings with distinct ids and distinct columns
    two = [x for x in identities[0]["gitleaks"] if x[1] == "two.txt"]
    assert len(two) == 2 and len({x[5] for x in two}) == 2 and two[0][3] != two[1][3]
    # relation groups, coverage and the gate do not vary either
    assert all(
        (len(run.audit.groups), run.audit.coverage.status, run.audit.gate.status)
        == (len(runs[0].audit.groups), runs[0].audit.coverage.status, runs[0].audit.gate.status)
        for run in runs
    )
    assert len(runs[0].audit.groups) >= 1  # R2: working tree <-> history for identical blobs


def test_no_value_and_no_column_free_duplicate_is_produced(git_builder, fake_secrets, out_dir):
    r = _repo(git_builder, fake_secrets)

    run = run_audit(r.path, out_dir, git_history_options=GitHistoryOptions(), disabled=DISABLED)

    text = run.reports.report_json.read_text("utf-8") + run.reports.markdown.read_text("utf-8")
    assert not fake_secrets.leaks(text)
    gitleaks = [f for f in run.audit.findings if f.source_tool == "gitleaks"]
    assert all(f.start_column and f.end_column for f in gitleaks)
    assert not any("duplicate-match" in f.tags for f in gitleaks)
