"""End-to-end ``auditor scan`` with real Ruff + real Semgrep (marked: semgrep)."""

import os
import shutil
import subprocess
import sys
import time

import pytest
from typer.testing import CliRunner

from auditor.cli import app
from auditor.core.models import FindingsReport
from auditor.scanners.semgrep_adapter import short_temp_base

pytestmark = pytest.mark.semgrep
runner = CliRunner()

VULNERABLE_APP = """
import os
import pickle
import subprocess

import requests
import yaml
from flask import Flask, render_template_string, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host")
    return subprocess.check_output("ping -c 1 " + host, shell=True)


@app.route("/user")
def user(db):
    name = request.args.get("name")
    return db.execute(f"SELECT * FROM users WHERE name = '{name}'").fetchall()


@app.route("/file")
def read_file():
    return open(os.path.join("/srv/files", request.args["f"])).read()


@app.route("/fetch")
def fetch():
    return requests.get(request.args["url"]).text


@app.route("/calc")
def calc():
    return str(eval(request.args["expr"]))


@app.route("/state", methods=["POST"])
def state():
    return pickle.loads(request.get_data())


@app.route("/hello")
def hello():
    return render_template_string("<p>" + request.args["name"] + "</p>")


def load_config(text):
    return yaml.load(text)


def insecure_download(url):
    return requests.get(url, verify=False)


if __name__ == "__main__":
    app.run(debug=True)
"""

SAFE_APP = """
import os
import shlex
import subprocess

import requests
import yaml
from flask import Flask, render_template, request, send_from_directory

app = Flask(__name__)
ALLOWED = {"a.example.com", "b.example.com"}


@app.route("/ping")
def ping():
    host = request.args.get("host")
    return subprocess.check_output(["ping", "-c", "1", host])


@app.route("/user")
def user(db):
    return db.execute("SELECT * FROM users WHERE name = ?", (request.args["name"],)).fetchall()


@app.route("/file")
def read_file():
    return send_from_directory("/srv/files", request.args["f"])


@app.route("/item")
def item():
    return requests.get("https://api.example.com/items/" + request.args["id"]).text


@app.route("/hello")
def hello():
    return render_template("hello.html", name=request.args["name"])


def load_config(text):
    return yaml.safe_load(text)


def quoted(name):
    return subprocess.run("ls " + shlex.quote(name), shell=True)


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
"""

EXPECTED_GROUPS = {
    "command-injection",
    "sql-injection",
    "path-traversal",
    "ssrf",
    "code-injection",
    "deserialization",
    "template-injection",
    "tls",
    "misconfig",
}


def scan(root, out_dir, *extra):
    return runner.invoke(app, ["scan", str(root), "--output-dir", str(out_dir), *extra])


def load(out_dir):
    run_dir = next(out_dir.iterdir())
    report = FindingsReport.model_validate_json((run_dir / "findings.json").read_text("utf-8"))
    return report, (run_dir / "report.md").read_text("utf-8")


def by_tool(report, tool):
    return next(e for e in report.tool_executions if e.tool == tool)


def test_vulnerable_app_is_detected_in_every_category(make_tree, out_dir):
    root = make_tree({"app.py": VULNERABLE_APP})

    result = scan(root, out_dir)
    report, markdown = load(out_dir)

    assert result.exit_code == 0, result.output
    semgrep = [f for f in report.findings if f.source_tool == "semgrep"]
    groups = {f.rule_id.split(".")[2] for f in semgrep}
    assert EXPECTED_GROUPS <= groups, f"missing: {EXPECTED_GROUPS - groups}"
    assert all(f.verification_status.value == "NEEDS_REVIEW" for f in report.findings)
    assert by_tool(report, "semgrep").status.value == "SUCCESS"
    assert by_tool(report, "ruff").status.value == "SUCCESS"
    assert {f.source_tool for f in report.findings} == {"ruff", "semgrep"}  # both kept
    assert "## Semgrep" in markdown and "Semgrep limitation:" in markdown


def test_safe_counterpart_has_no_semgrep_findings(make_tree, out_dir):
    root = make_tree({"app.py": SAFE_APP})

    result = scan(root, out_dir)
    report, _ = load(out_dir)

    assert result.exit_code == 0, result.output
    semgrep = [(f.rule_id, f.start_line) for f in report.findings if f.source_tool == "semgrep"]
    assert semgrep == []


def test_parse_error_cross_check_with_real_tools(make_tree, out_dir):
    broken = "from flask import request\nx = eval(request.args['e'])\ndef f(:\n    pass\n"
    root = make_tree({"broken.py": broken, "ok.py": "VALUE = 1\n"})

    result = scan(root, out_dir)
    report, markdown = load(out_dir)

    assert result.exit_code == 3
    reasons = {r.value for r in report.incomplete_reasons}
    assert {"FILES_NOT_ANALYZED", "FILES_ANALYZED_WITH_LIMITATIONS"} <= reasons
    sg = by_tool(report, "semgrep")
    assert [(i.relative_path, i.reason) for i in sg.coverage_limitations] == [
        ("broken.py", "SYNTAX_ERROR_RECOVERY")
    ]
    # Semgrep's finding before the syntax error is kept, not deleted.
    assert any(
        f.source_tool == "semgrep" and f.relative_path == "broken.py" for f in report.findings
    )
    row = next(c for c in report.file_coverage if c.relative_path == "broken.py")
    assert row.scanners["semgrep"].status.value == "SCANNED_WITH_LIMITATIONS"
    assert row.scanners["ruff"].status.value == "NOT_ANALYZED"
    assert "Scanned with limitations by Semgrep" in markdown


def test_version_gated_syntax_is_not_a_semgrep_limitation(make_tree, out_dir):
    code = "def f(v):\n    match v:\n        case 1:\n            return 1\n    return 0\n"

    result = scan(make_tree({"m.py": code}), out_dir, "--target-python", "3.8")
    report, _ = load(out_dir)

    assert result.exit_code == 0, result.output
    assert by_tool(report, "semgrep").coverage_limitations == []


def test_disable_scanner_semgrep(make_tree, out_dir):
    result = scan(make_tree({"app.py": VULNERABLE_APP}), out_dir, "--disable-scanner", "semgrep")
    report, markdown = load(out_dir)

    assert result.exit_code == 0, result.output
    sg = by_tool(report, "semgrep")
    assert sg.status.value == "SKIPPED" and sg.settings["disabled_by_user"] == "true"
    assert not [f for f in report.findings if f.source_tool == "semgrep"]
    assert "DISABLED by user" in result.output
    assert "not a complete security audit" in markdown


def test_unknown_scanner_name_is_rejected(make_tree, out_dir):
    result = scan(make_tree({"a.py": ""}), out_dir, "--disable-scanner", "bandit")

    assert result.exit_code == 2


def test_unicode_and_long_paths(tmp_path, out_dir):
    root = tmp_path / "proje İ 日本"
    prefix = "\\\\?\\" if os.name == "nt" else ""
    deep = os.path.join(prefix + str(root), *(["klasör_çok_uzun_ad"] * 14))
    os.makedirs(deep)
    with open(os.path.join(deep, "derin.py"), "w", encoding="utf-8") as fh:
        fh.write("x = eval(input())\n")
    short_base = short_temp_base()
    before = set(short_base.iterdir()) if short_base.exists() else set()
    try:
        result = scan(root, out_dir)
        report, _ = load(out_dir)

        assert result.exit_code == 0, result.output
        (finding,) = [f for f in report.findings if f.source_tool == "semgrep"]
        assert finding.relative_path.endswith("klasör_çok_uzun_ad/derin.py")
        assert len(str(root)) + len(finding.relative_path) > 260
        # D-042: findings of both scanners survive, and the >260-character mirror copy and
        # raw output are gone (they used to stay behind silently).
        assert [f.rule_id for f in report.findings if f.source_tool == "ruff"] == ["S307"]
        assert report.operational_errors == []
        assert set(short_base.iterdir()) == before
        assert list((tmp_path / "appdata" / "ai-code-auditor" / "tmp").iterdir()) == []
        # D-040 regression guard: a \\?\ target under a plain cwd made Semgrep walk the
        # enclosing git repository (~70 s on the development machine).
        assert by_tool(report, "semgrep").duration_seconds < 30
    finally:
        shutil.rmtree(prefix + str(root))


def test_doctor_reports_semgrep_and_ruleset():
    result = runner.invoke(app, ["doctor"])

    assert result.exit_code == 0, result.output
    assert "semgrep     1.182.1 (" in result.output
    assert "verified" in result.output


def test_missing_semgrep_makes_the_scan_partial(make_tree, out_dir, monkeypatch, tmp_path):
    monkeypatch.setenv("AUDITOR_TOOLS_DIR", str(tmp_path / "no-tools"))

    result = scan(make_tree({"a.py": "VALUE = 1\n"}), out_dir)
    report, _ = load(out_dir)

    assert result.exit_code == 3
    assert by_tool(report, "semgrep").status.value == "NOT_INSTALLED"
    assert "SCANNER_NOT_INSTALLED" in {r.value for r in report.incomplete_reasons}


def test_semgrep_scan_is_fast_and_does_not_walk_outside(make_tree, out_dir):
    # Regression guard for D-040: without the private mirror, Semgrep walked the whole
    # enclosing git repository (this machine: ~70 s for one file).
    root = make_tree({"a.py": "x = eval(input())\n"})

    result = scan(root, out_dir)
    report, _ = load(out_dir)

    assert result.exit_code == 0, result.output
    assert by_tool(report, "semgrep").duration_seconds < 30


def test_real_subprocess_scan_keeps_old_leftovers_and_removes_its_own(make_tree, out_dir, tmp_path):
    """A real ``auditor`` process (inherits the test's TEMP/LOCALAPPDATA sandbox): old
    workspaces of both bases survive and are reported; the run's own ones are removed."""
    old = time.time() - 3 * 24 * 3600
    short_base = short_temp_base()
    short_base.mkdir(parents=True, exist_ok=True)
    app_tmp = tmp_path / "appdata" / "ai-code-auditor" / "tmp"
    app_tmp.mkdir(parents=True)
    leftovers = [short_base / "r-oldleft1", app_tmp / "run-oldleft1"]
    for leftover in leftovers:
        leftover.mkdir()
        (leftover / "copy.py").write_text("OLD_COPY = 1\n", encoding="utf-8")
        os.utime(leftover, (old, old))
    before = {base: set(base.iterdir()) for base in (short_base, app_tmp)}
    root = make_tree({"app.py": "x = eval(input())\n"})

    completed = subprocess.run(  # noqa: S603 - runs our own package only
        [sys.executable, "-m", "auditor", "scan", str(root), "--output-dir", str(out_dir)],
        shell=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
        timeout=300,
        check=False,
    )
    report, _ = load(out_dir)

    assert completed.returncode == 0, completed.stderr
    assert all((p / "copy.py").exists() for p in leftovers)  # never deleted automatically
    assert {base: set(base.iterdir()) for base in before} == before  # own workspaces removed
    assert sorted((w.component, w.workspace) for w in report.operational_warnings) == [
        ("scanner-output", "run-*"),
        ("semgrep", "r-*"),
    ]
    assert "SECURITY WARNING [STALE_WORKSPACES_FOUND] (semgrep)" in completed.stderr
    assert {f.source_tool for f in report.findings} == {"ruff", "semgrep"}
