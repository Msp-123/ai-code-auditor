"""End-to-end ``auditor scan`` with the real Gitleaks 8.30.1 binary (marked: gitleaks).

All secrets are random fake values in real token formats, generated at runtime.
"""

import io
import zipfile

import pytest
from typer.testing import CliRunner

from auditor.application.audit_service import run_audit
from auditor.cli import app
from auditor.core.models import (
    Confidence,
    FindingsReport,
    NotAnalyzedReason,
    ScanStatus,
    Severity,
    ToolStatus,
)
from auditor.scanners.gitleaks_adapter import (
    CONFIG_DIR,
    SKIPPED_FORMATS,
    GitleaksAdapter,
    GitleaksOptions,
)

pytestmark = pytest.mark.gitleaks
runner = CliRunner()


def project(make_tree, s, extra=None):
    spec = {
        "app": {
            "settings.py": f'import os\n\nAWS_KEY = "{s["aws"]}"\n\n\n\n'
            f'GITHUB_TOKEN = "{s["github"]}"\n'
        },
        ".env": f"DEBUG=1\nAPI_KEY={s['generic']}\nSLACK_TOKEN={s['slack']}\n",
        "keys": {"id_rsa": s["pem"] + "\n"},
        "web": {"auth.js": f"// demo\n\n\nconst t = '{s['jwt']}';\n"},
        "clean.py": "def ok():\n    return 1\n",
    }
    spec.update(extra or {})
    return make_tree(spec)


EXPECTED = {
    ("app/settings.py", "gitleaks.aws-access-token", 3),
    ("app/settings.py", "gitleaks.github-pat", 7),
    (".env", "gitleaks.generic-api-key", 2),
    (".env", "gitleaks.slack-bot-token", 3),
    ("keys/id_rsa", "gitleaks.private-key", 1),
    ("web/auth.js", "gitleaks.jwt", 4),
}


def scan(root, out_dir, *args):
    result = runner.invoke(app, ["scan", str(root), "--output-dir", str(out_dir), *args])
    run_dir = next(out_dir.iterdir())
    report = FindingsReport.model_validate_json((run_dir / "findings.json").read_text("utf-8"))
    return result, report, run_dir


def gitleaks(report):
    return {
        (f.relative_path, f.rule_id, f.start_line)
        for f in report.findings
        if f.source_tool == "gitleaks"
    }


def execution(report):
    return next(e for e in report.tool_executions if e.tool == "gitleaks")


def test_fake_secrets_of_every_supported_type_are_found(make_tree, out_dir, fake_secrets):
    root = project(make_tree, fake_secrets)

    result, report, _ = scan(root, out_dir)
    e = execution(report)

    assert result.exit_code == 0, result.output
    assert gitleaks(report) == EXPECTED
    assert e.status is ToolStatus.SUCCESS and e.version == "8.30.1"
    assert e.files_analyzed == e.files_requested == 5
    assert e.not_analyzed == [] and e.coverage_limitations == []
    by_rule = {f.rule_id: f for f in report.findings if f.source_tool == "gitleaks"}
    assert by_rule["gitleaks.private-key"].severity is Severity.CRITICAL
    assert by_rule["gitleaks.generic-api-key"].confidence is Confidence.LOW
    assert "Gitleaks:  SUCCESS (version 8.30.1) - 6 findings" in result.output
    assert "git history NOT_SCANNED" in result.output


def test_clean_project_is_scanned_completely(make_tree, out_dir):
    root = make_tree({"a.py": "x = 1\n", "README.md": "# hi\n", "conf.ini": "[s]\nk=v\n"})

    result, report, run_dir = scan(root, out_dir)
    e = execution(report)

    assert result.exit_code == 0
    assert e.status is ToolStatus.SUCCESS and gitleaks(report) == set()
    assert e.files_analyzed == e.files_requested == 3
    states = {
        row.relative_path: row.scanners["gitleaks"].status.value for row in report.file_coverage
    }
    assert set(states.values()) == {"SCANNED"}
    markdown = (run_dir / "report.md").read_text("utf-8")
    assert "Scope git history: `NOT_SCANNED" in markdown
    assert "Gitleaks limitation: Each file is passed to Gitleaks on stdin" in markdown


def test_ordinary_yaml_project_is_complete_not_partial(make_tree, out_dir):
    root = make_tree(
        {
            ".github": {"workflows": {"ci.yml": "on: push\njobs:\n  t:\n    runs-on: x\n"}},
            "config": {"settings.yaml": "debug: false\nport: 8080\n"},
            "app.py": "x = 1\n",
        }
    )

    result, report, _ = scan(root, out_dir)
    e = execution(report)

    assert result.exit_code == 0, result.output  # was PARTIAL (exit 3) before the revision
    assert report.status is ScanStatus.COMPLETE
    assert e.coverage_limitations == [] and e.not_analyzed == []
    assert gitleaks(report) == set()


def test_pkcs12_file_is_reported_as_potentially_sensitive_not_as_a_secret(make_tree, out_dir):
    root = make_tree({"cert.p12": b"\x30\x82\x01\x00" + bytes(200), "a.py": "x = 1\n"})

    result, report, _ = scan(root, out_dir)
    (finding,) = [f for f in report.findings if f.source_tool == "gitleaks"]
    states = {r.relative_path: r.scanners["gitleaks"].status.value for r in report.file_coverage}

    assert result.exit_code == 0
    assert finding.rule_id == "gitleaks.pkcs12-file" and finding.start_line is None
    assert "POTENTIALLY_SENSITIVE_FILE" in finding.tags and "secret" not in finding.tags
    assert "No secret value was detected" in finding.description
    assert states["cert.p12"] == "SCANNED"


def test_secret_inside_an_archive_is_not_found_and_says_so(make_tree, out_dir, fake_secrets):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("inner.py", f'T = "{fake_secrets["github"]}"\n')
    root = make_tree({"bundle.zip": buffer.getvalue()})

    result, report, _ = scan(root, out_dir)

    assert gitleaks(report) == set()  # known false negative
    # Measured: Gitleaks does not read zip/gzip/PDF input as text on stdin; the missing end
    # marker shows it, so the file is reported as not analyzed (not as "scanned").
    (item,) = execution(report).not_analyzed
    assert item.reason is NotAnalyzedReason.SKIPPED_BY_TOOL
    assert "archive" in item.detail
    assert result.exit_code == 3 and report.status is ScanStatus.PARTIAL


def test_known_false_negatives_and_false_positives(make_tree, out_dir, fake_secrets):
    example = "AK" + "IA" + "IOSFODNN7" + "EXAMPLE"  # AWS documentation placeholder
    root = make_tree(
        {
            "placeholder.py": f'K = "{example}"\n',
            "weak.py": 'password = "' + "hun" + 'ter2"\n',  # low entropy
            "split.py": f'T = "{fake_secrets["github"][:20]}" + "{fake_secrets["github"][20:]}"\n',
            "package-lock.json": f'{{"t": "{fake_secrets["github"]}"}}\n',
        }
    )

    _, report, _ = scan(root, out_dir)
    found = {path for path, _, _ in gitleaks(report)}

    assert "placeholder.py" not in found  # default rules allow the documentation example
    assert "weak.py" not in found  # false negative: low-entropy password
    assert "split.py" not in found  # false negative: value built at runtime
    # false-positive-prone: the lockfile path allowlist does not apply on stdin
    assert "package-lock.json" in found


def test_file_over_the_size_limit_is_partial_coverage(make_tree, out_dir, fake_secrets):
    root = make_tree({"big.txt": "x" * 4000 + f"\nT={fake_secrets['github']}\n", "a.py": "1\n"})

    run = run_audit(root, out_dir, gitleaks_options=GitleaksOptions(max_file_bytes=1000))
    e = execution(run.findings)

    (missing,) = e.not_analyzed
    assert (missing.relative_path, missing.reason) == ("big.txt", NotAnalyzedReason.SIZE_LIMIT)
    assert run.findings.status is ScanStatus.PARTIAL


@pytest.mark.parametrize("workers", [1, 4, 8, 16])
def test_results_do_not_depend_on_the_worker_count(make_tree, out_dir, fake_secrets, workers):
    root = project(make_tree, fake_secrets)

    run = run_audit(root, out_dir, gitleaks_options=GitleaksOptions(workers=workers))

    assert gitleaks(run.findings) == EXPECTED
    assert execution(run.findings).settings["workers"] == str(workers)


def test_long_and_unicode_paths(tmp_path, out_dir, fake_secrets):
    import os

    root = tmp_path / "proje İ 日本"
    prefix = "\\\\?\\" if os.name == "nt" else ""
    deep = os.path.join(prefix + str(root), *(["klasör_çok_uzun_ad"] * 14))
    os.makedirs(deep)
    with open(os.path.join(deep, "derin.env"), "w", encoding="utf-8") as fh:
        fh.write(f"TOKEN={fake_secrets['github']}\n")

    run = run_audit(root, out_dir)

    ((path, rule, line),) = gitleaks(run.findings)
    assert path.endswith("klasör_çok_uzun_ad/derin.env") and line == 1
    assert len(str(root)) + len(path) > 260


def test_scanners_stay_independent(make_tree, out_dir, fake_secrets, tmp_path):
    root = make_tree({"a.py": f'import os\nT = "{fake_secrets["github"]}"\n'})
    tampered = tmp_path / "tampered"
    tampered.mkdir()
    for source in CONFIG_DIR.glob("*.toml"):
        (tampered / source.name).write_bytes(source.read_bytes())
    (tampered / "gitleaks.toml").write_text("[extend]\nuseDefault = false\n", encoding="utf-8")
    from auditor.scanners.ruff_adapter import RuffAdapter

    run = run_audit(
        root,
        out_dir,
        scanners=[RuffAdapter(), GitleaksAdapter(GitleaksOptions(config_dir=tampered))],
    )

    tools = {e.tool: e.status for e in run.findings.tool_executions}
    assert tools == {"ruff": ToolStatus.SUCCESS, "gitleaks": ToolStatus.ERROR}
    assert any(f.source_tool == "ruff" for f in run.findings.findings)
    assert run.findings.status is ScanStatus.PARTIAL


def test_doctor_reports_the_verified_gitleaks():
    result = runner.invoke(app, ["doctor"])

    assert "gitleaks    8.30.1 (" in result.output and "SHA-256 verified" in result.output
    assert "gitleaks    config verified" in result.output


def _sqlite_bytes(tmp_path, text: str) -> bytes:
    import sqlite3

    path = tmp_path / "probe.sqlite"
    con = sqlite3.connect(path)
    con.execute("create table t (v text)")
    con.execute("insert into t values (?)", (text,))
    con.commit()
    con.close()
    data = path.read_bytes()
    path.unlink()
    return data


def test_sqlite_database_is_skipped_by_tool_not_a_tool_error(
    make_tree, out_dir, fake_secrets, tmp_path
):
    """H2 (pilot 01 P5): Gitleaks skips SQLite input by its header; that is a known format gap,
    not a tool failure. Coverage stays PARTIAL either way."""
    root = make_tree({"users.sqlite": _sqlite_bytes(tmp_path, f'T = "{fake_secrets["github"]}"')})

    result, report, _ = scan(root, out_dir)

    (item,) = execution(report).not_analyzed
    assert item.reason is NotAnalyzedReason.SKIPPED_BY_TOOL
    assert "SQLite" in item.detail
    assert result.exit_code == 3 and report.status is ScanStatus.PARTIAL


def _format_samples(tmp_path) -> dict[str, bytes]:
    """One realistic sample per entry of SKIPPED_FORMATS (header + plausible body)."""
    import bz2
    import gzip

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("inner.txt", "x = 1\n" * 40)
    body = ("x = 1\n" * 40).encode()
    return {
        "zip archive": buffer.getvalue(),
        "zip archive (empty)": b"PK\x05\x06" + bytes(18),
        "gzip archive": gzip.compress(body),
        "PDF document": b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<< /Type /Catalog >>\nendobj\n"
        + body,
        "7-Zip archive": b"7z\xbc\xaf\x27\x1c\x00\x04" + bytes(24) + body,
        "RAR archive": b"Rar!\x1a\x07\x01\x00" + bytes(16) + body,
        "bzip2 archive": bz2.compress(body),
        "SQLite database": _sqlite_bytes(tmp_path, "x = 1"),
    }


def test_the_measured_skip_list_matches_this_gitleaks_version(make_tree, out_dir, tmp_path):
    """Every format in SKIPPED_FORMATS must really be skipped by the pinned Gitleaks (no end
    marker), and binary-looking text (NUL bytes) must still be analysed. If a Gitleaks upgrade
    changes either behaviour this test fails and the list must be re-measured."""
    samples = _format_samples(tmp_path)
    assert set(samples) == set(SKIPPED_FORMATS.values())  # every listed format has a sample
    files = {f"f{i}.dat": data for i, data in enumerate(samples.values())}
    files["control.dat"] = b"x = 1\x00\n" * 40 + b"\x00" * 300 + b"\ny = 2\n"

    _, report, _ = scan(make_tree(files), out_dir)

    skipped = {n.relative_path: n for n in execution(report).not_analyzed}
    assert set(skipped) == set(files) - {"control.dat"}
    assert all(n.reason is NotAnalyzedReason.SKIPPED_BY_TOOL for n in skipped.values())
    for index, name in enumerate(samples):
        assert name in skipped[f"f{index}.dat"].detail
