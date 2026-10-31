"""H5 end to end with the real Semgrep and Ruff: cross-function SQL injection becomes HIGH
only when the whole chain is verified; the gate counts it; nothing else changes."""

import json
import textwrap

import pytest
from typer.testing import CliRunner

from auditor.cli import app

pytestmark = pytest.mark.semgrep
runner = CliRunner()

VIEW = """
    from flask import Flask, request
    import libuser

    app = Flask(__name__)

    @app.route("/login", methods=["POST"])
    def login():
        return libuser.login(request.form["username"], request.form["password"])

    @app.route("/seed")
    def seed():
        return libuser.seed("admin")

    @app.route("/by-id")
    def by_id():
        return libuser.by_id(request.args["id"])

    @app.route("/safe")
    def safe():
        return libuser.safe_login(request.form["username"])
"""
LIB = """
    import sqlite3

    def login(username, password):
        c = sqlite3.connect("db").cursor()
        # Semgrep formatted-sql-query and Ruff S608 both flag the next line (as in Vulpy)
        return c.execute("SELECT * FROM t WHERE u = '{}' AND p = '{}'".format(username, password))

    def seed(name):
        c = sqlite3.connect("db").cursor()
        c.execute("INSERT INTO users (u) VALUES ('%s')" % name)

    def by_id(ident):
        c = sqlite3.connect("db").cursor()
        return c.execute("SELECT * FROM users WHERE id = %d" % int(ident)).fetchone()

    def safe_login(username):
        c = sqlite3.connect("db").cursor()
        return c.execute("SELECT * FROM users WHERE u = ?", (username,)).fetchone()
"""


def scan(make_tree, out_dir, *args):
    root = make_tree({"mod_user.py": textwrap.dedent(VIEW).lstrip("\n"),
                      "libuser.py": textwrap.dedent(LIB).lstrip("\n")})  # fmt: skip
    result = runner.invoke(app, ["scan", str(root), "--output-dir", str(out_dir),
                                 "--disable-scanner", "gitleaks", "--disable-scanner", "pip-audit",
                                 *args])  # fmt: skip
    (run_dir,) = out_dir.glob("2*")
    report = json.loads((run_dir / "report.json").read_text("utf-8"))
    return result, report


def sql_findings(report):
    return {
        (f["source_tool"], f["relative_path"], f["start_line"]): f
        for f in report["findings"]
        if f["rule_id"].endswith(("formatted-sql-query", "S608"))
    }


def test_only_the_verified_cross_function_flow_is_high(make_tree, out_dir):
    result, report = scan(make_tree, out_dir)

    sql = sql_findings(report)
    assert sql[("semgrep", "libuser.py", 6)]["severity"] == "HIGH"  # login: request -> username
    assert sql[("ruff", "libuser.py", 6)]["severity"] == "HIGH"
    assert sql[("semgrep", "libuser.py", 10)]["severity"] == "MEDIUM"  # seed: constant
    assert sql[("semgrep", "libuser.py", 14)]["severity"] == "MEDIUM"  # by_id: int() sanitiser
    assert not any(path == "libuser.py" and line == 18 for _, path, line in sql)  # parameterised
    high = sql[("semgrep", "libuser.py", 6)]
    assert high["verification_status"] == "NEEDS_REVIEW"
    assert any(e["kind"] == "verified_data_flow" and e["reference"].startswith("mod_user.py:8 ")
               for e in high["evidence"])  # fmt: skip
    assert not any(f["rule_id"].startswith("auditor.python.flow-evidence.")
                   for f in report["findings"])  # fmt: skip
    assert result.exit_code == 0  # COMPLETE; the gate was not requested


def test_the_gate_counts_the_verified_flow(make_tree, out_dir):
    result, report = scan(make_tree, out_dir, "--fail-on", "high")

    assert result.exit_code == 4
    assert report["gate"]["status"] == "FAILED" and report["gate"]["counted"] == 2
