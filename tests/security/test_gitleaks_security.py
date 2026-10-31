"""Secrets never leak, and the target cannot hide them (real Gitleaks 8.30.1; marked).

Canary: random fake secrets; neither a value nor any 8-character window of it may appear in
the terminal output, any report file, the temp directories or the serialised findings (the
future LLM context).
"""

import hashlib
import os
import sys

import pytest
from typer.testing import CliRunner

import auditor.scanners.gitleaks_adapter as adapter_module
from auditor.application.audit_service import run_audit
from auditor.cli import app
from auditor.core.models import FindingsReport, ToolStatus
from auditor.scanners.gitleaks_adapter import ARGV_TEMPLATE, FORBIDDEN_ARGS

pytestmark = pytest.mark.gitleaks
runner = CliRunner()
HOSTILE = '[extend]\nuseDefault = true\n[allowlist]\nregexes = [""".*"""]\npaths = [""".*"""]\n'


def secrets_tree(make_tree, s, extra=None):
    spec = {
        "settings.py": f'AWS = "{s["aws"]}"\nGH = "{s["github"]}"\n',
        ".env": f"API_KEY={s['generic']}\nSLACK={s['slack']}\n",
        "id_rsa": s["pem"] + "\n",
        "auth.js": f"const t = '{s['jwt']}';\n",
    }
    spec.update(extra or {})
    return make_tree(spec)


def all_text(result, out_dir, temp_dirs):
    texts = [result.output]
    for base in [out_dir, *temp_dirs]:
        if base.exists():
            texts += [
                p.read_bytes().decode("utf-8", "replace") for p in base.rglob("*") if p.is_file()
            ]
    return texts


def test_no_secret_value_appears_anywhere(make_tree, out_dir, fake_secrets, tmp_path):
    root = secrets_tree(make_tree, fake_secrets)

    result = runner.invoke(app, ["scan", str(root), "--output-dir", str(out_dir)])
    run_dir = next(out_dir.iterdir())
    report = FindingsReport.model_validate_json((run_dir / "findings.json").read_text("utf-8"))

    assert len([f for f in report.findings if f.source_tool == "gitleaks"]) == 6
    temp_dirs = [tmp_path / "appdata" / "ai-code-auditor" / "tmp"]
    texts = all_text(result, out_dir, temp_dirs)
    assert len(texts) >= 4  # terminal + inventory.json + findings.json + report.md
    assert not any(fake_secrets.leaks(text) for text in texts)
    # the future LLM context: every finding object, serialised
    assert not any(fake_secrets.leaks(f.model_dump_json()) for f in report.findings)
    assert list(temp_dirs[0].iterdir()) == []  # no workspace (and no content copy) remains


def test_target_cannot_hide_secrets(make_tree, out_dir, fake_secrets, monkeypatch, tmp_path):
    hostile_file = tmp_path / "hostile.toml"
    hostile_file.write_text(HOSTILE, encoding="utf-8")
    monkeypatch.setenv("GITLEAKS_CONFIG", str(hostile_file))
    monkeypatch.setenv("GITLEAKS_CONFIG_TOML", HOSTILE)
    s = fake_secrets
    root = make_tree(
        {
            ".gitleaks.toml": HOSTILE,
            ".gitleaksignore": "\n".join(
                f"{p}:{r}:{n}" for p, r, n in [("a.py", "github-pat", 1), ("", "github-pat", 1)]
            )
            + "\n:github-pat:1\n",
            "a.py": f'T = "{s["github"]}"  # gitleaks:allow\nA = "{s["aws"]}"\n',
        }
    )

    run = run_audit(root, out_dir)
    e = next(x for x in run.findings.tool_executions if x.tool == "gitleaks")
    found = {
        (f.relative_path, f.rule_id) for f in run.findings.findings if f.source_tool == "gitleaks"
    }

    assert found == {("a.py", "gitleaks.github-pat"), ("a.py", "gitleaks.aws-access-token")}
    warnings = " ".join(e.warnings)
    assert "2 Gitleaks configuration/ignore file(s)" in warnings
    assert "1 inline 'gitleaks:allow'" in warnings


def test_target_is_not_modified(make_tree, out_dir, fake_secrets):
    root = secrets_tree(make_tree, fake_secrets)

    def snapshot():
        state = {}
        for dirpath, dirnames, filenames in os.walk(root):
            for name in dirnames + filenames:
                path = os.path.join(dirpath, name)
                data = open(path, "rb").read() if os.path.isfile(path) else b""
                state[path] = (os.lstat(path).st_size, hashlib.sha256(data).hexdigest())
        return state

    before = snapshot()
    run_audit(root, out_dir)

    assert snapshot() == before


def test_planted_gitleaks_in_target_and_path_is_never_run(
    make_tree, out_dir, fake_secrets, monkeypatch, tmp_path
):
    marker = tmp_path / "PLANTED_RAN"
    planted = f"import pathlib\npathlib.Path({str(marker)!r}).write_text('x')\n"
    root = secrets_tree(
        make_tree,
        fake_secrets,
        {
            "gitleaks.py": planted,
            "gitleaks.cmd": f'@"{sys.executable}" "%~dp0gitleaks.py"\n',
            "gitleaks.bat": f'@"{sys.executable}" "%~dp0gitleaks.py"\n',
        },
    )
    monkeypatch.setenv("PATH", str(root) + os.pathsep + os.environ.get("PATH", ""))
    monkeypatch.chdir(root)

    run = run_audit(root, out_dir)

    assert not marker.exists()
    e = next(x for x in run.findings.tool_executions if x.tool == "gitleaks")
    assert e.status is ToolStatus.SUCCESS and e.version == "8.30.1"


def test_debug_logging_can_never_be_enabled():
    # Measured (step 0): at debug/trace level Gitleaks prints full secrets to stderr even
    # with --redact=100. The argv is a constant; nothing (option, env) can add a log level.
    assert ARGV_TEMPLATE[ARGV_TEMPLATE.index("--log-level") + 1] == "error"
    assert ARGV_TEMPLATE.count("--log-level") == 1
    assert not set(FORBIDDEN_ARGS) & set(ARGV_TEMPLATE)
    assert "--redact=100" in ARGV_TEMPLATE
    assert not hasattr(adapter_module.GitleaksOptions(), "log_level")


def test_real_run_never_keeps_stderr(make_tree, out_dir, fake_secrets):
    root = secrets_tree(make_tree, fake_secrets)

    run = run_audit(root, out_dir)
    e = next(x for x in run.findings.tool_executions if x.tool == "gitleaks")

    assert e.stderr_excerpt is None
    assert not fake_secrets.leaks(e.model_dump_json())
