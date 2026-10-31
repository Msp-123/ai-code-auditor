"""MVP end to end (Stage 6): all five scan components with the real tools on one fixture
repository - Ruff, Semgrep, Gitleaks (working tree), Gitleaks over git history and pip-audit
(against a local mock OSV; no internet). Checks the canonical report, relations R1-R3, the
gate, the exit code, ``auditor report``, stable ids, privacy and the read-only invariant."""

import hashlib
import json
import os
import secrets
import string
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from typer.testing import CliRunner

from auditor.cli import app
from auditor.scanners.pip_audit_adapter import PipAuditOptions

pytestmark = [pytest.mark.semgrep, pytest.mark.gitleaks, pytest.mark.pip_audit,
              pytest.mark.git_history]  # fmt: skip
ALNUM = string.ascii_letters + string.digits
runner = CliRunner()


def token(prefix="gh" + "p_", n=36):
    return prefix + "".join(secrets.choice(ALNUM) for _ in range(n))


class MockOsv:
    def __init__(self):
        self.requests: list[dict] = []
        mock = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802 - http.server API
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                mock.requests.append(body)
                vulns = []
                if (body["package"]["name"], body["version"]) == ("jinja2", "2.10"):
                    vulns = [{"id": "PYSEC-2019-217", "aliases": ["CVE-2019-10906"],
                              "summary": "Sandbox escape", "affected": [{
                                  "package": {"name": "jinja2", "ecosystem": "PyPI"},
                                  "ranges": [{"type": "ECOSYSTEM", "events": [
                                      {"introduced": "0"}, {"fixed": "2.10.1"}]}]}]}]  # fmt: skip
                payload = json.dumps({"vulns": vulns} if vulns else {}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/v1/query"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()


def digest(root: Path) -> str:
    h = hashlib.sha256()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames):
            p = Path(dirpath, name)
            h.update(str(p.relative_to(root)).encode() + b"\0" + p.read_bytes())
    return h.hexdigest()


@pytest.fixture
def project(git_builder):
    r = git_builder("mvp")
    values = {"api": token("", 32), "kept": token(), "removed": token()}
    r.write("app/__init__.py", "")
    r.write("app/views.py", "import subprocess\n\nfrom flask import request\n\n\ndef run():\n"
            "    return subprocess.call(request.args['c'], shell=True)\n")  # fmt: skip
    r.write("app/settings.py", f'token = "{values["api"]}"\n')
    r.write("app/kept.py", f"KEPT = '{values['kept']}'\n")
    r.write("app/old.py", f"OLD = '{values['removed']}'\n")
    r.write("requirements.txt", "jinja2==2.10\n")
    r.write("requirements-dev.txt", "jinja2==2.10\npackaging==24.2\n")
    r.commit("initial")
    r.git("rm", "-q", "app/old.py")
    r.commit("remove old secret")
    return r, values


def scan(out_dir, root, osv, monkeypatch, *args):
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    monkeypatch.setattr("auditor.cli.PipAuditOptions",
                        lambda **kw: PipAuditOptions(**kw, osv_url=osv.url))  # fmt: skip
    return runner.invoke(app, ["scan", str(root), "--output-dir", str(out_dir), "--allow-network",
                               "--scan-git-history", *args])  # fmt: skip


def test_the_mvp_end_to_end(project, out_dir, tmp_path, monkeypatch):
    r, values = project
    osv = MockOsv()
    before = digest(r.path)
    try:
        result = scan(out_dir / "first", r.path, osv, monkeypatch, "--fail-on", "high")
        second = scan(out_dir / "second", r.path, osv, monkeypatch)
    finally:
        osv.server.shutdown()
    (run_dir,) = (out_dir / "first").iterdir()
    report = json.loads((run_dir / "report.json").read_text("utf-8"))

    # coverage: every area of the MVP ran completely
    areas = {a["area"]: a["status"] for a in report["coverage"]["areas"]}
    assert areas == {
        "discovery": "COMPLETE",
        "code_quality": "COMPLETE",
        "static_security": "COMPLETE",
        "secrets_working_tree": "COMPLETE",
        "secrets_history": "COMPLETE",
        "dependencies": "COMPLETE",
    }, result.output
    assert report["coverage"]["status"] == "COMPLETE"
    # gate and exit code: findings at HIGH or above -> 4; without --fail-on -> 0
    assert result.exit_code == 4 and report["gate"]["status"] == "FAILED", result.output
    assert second.exit_code == 0, second.output
    # findings of every component, canonical severities kept
    by_tool = report["outcome"]["by_source"]
    assert {"ruff", "semgrep", "gitleaks", "gitleaks-history", "pip-audit"} <= set(by_tool)
    assert by_tool["pip-audit"] == {"UNRATED": 2}
    # relations R1-R3, nothing merged
    relations = {}
    for g in report["groups"]:
        relations.setdefault(g["relation"], []).append(g)
    assert {"same_location", "same_content_in_history", "same_vulnerability"} <= set(relations)
    tools_at_views = [set(g["basis"]["tools"]) for g in relations["same_location"]
                      if g["basis"]["path"] == "app/views.py"]  # fmt: skip
    assert {"ruff", "semgrep"} in tools_at_views
    (r2,) = [g for g in relations["same_content_in_history"] if g["basis"]["path"] == "app/kept.py"]
    assert len(r2["finding_ids"]) == 2
    (r3,) = relations["same_vulnerability"]
    assert r3["basis"]["ids"] == ["CVE-2019-10906", "PYSEC-2019-217"]
    assert report["outcome"]["total"] == len(report["findings"])
    # stable ids: the same findings and groups in a second run
    (second_dir,) = (out_dir / "second").iterdir()
    again = json.loads((second_dir / "report.json").read_text("utf-8"))
    assert sorted(f["finding_id"] for f in again["findings"]) == sorted(
        f["finding_id"] for f in report["findings"])  # fmt: skip
    assert sorted(g["group_id"] for g in again["groups"]) == sorted(
        g["group_id"] for g in report["groups"])  # fmt: skip
    # auditor report shows the stored run (validated against its integrity record)
    shown = runner.invoke(app, ["report", run_dir.name, "--reports-dir", str(out_dir / "first"),
                                "--format", "json"])  # fmt: skip
    assert shown.exit_code == 0 and json.loads(shown.output)["run"]["run_id"] == run_dir.name
    # privacy and the read-only invariant
    files = "\n".join(p.read_text("utf-8", "replace") for p in out_dir.rglob("*") if p.is_file())
    text = files + result.output + second.output
    for value in values.values():
        assert value not in text
    for personal in ("Fixture Person", "fixture@example.invalid", "remove old secret"):
        assert personal not in text
    for absolute in (str(r.path), str(tmp_path), os.environ["USERPROFILE"]):
        for form in (absolute, absolute.replace("\\", "/"), json.dumps(absolute)[1:-1]):
            assert form not in files  # reports carry relative paths only
    assert str(r.path) not in result.output  # the terminal names only the user's output dir
    assert digest(r.path) == before
    temp = tmp_path / "appdata" / "ai-code-auditor" / "tmp"
    assert not temp.exists() or list(temp.iterdir()) == []
    assert {(q["package"]["name"], q["version"]) for q in osv.requests} == {
        ("jinja2", "2.10"), ("packaging", "24.2")}  # fmt: skip
