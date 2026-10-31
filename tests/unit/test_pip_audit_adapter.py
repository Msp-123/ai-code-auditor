"""pip-audit adapter logic, driven by a fake pip-audit (our own script) for fault injection."""

import json
import sys
import textwrap
from pathlib import Path

import pytest

from auditor.core.models import (
    Confidence,
    FileCategory,
    FileEntry,
    NotAnalyzedReason,
    Severity,
    ToolStatus,
)
from auditor.scanners.base import ScanContext
from auditor.scanners.executables import PIP_AUDIT_VERSION
from auditor.scanners.pip_audit_adapter import (
    FORBIDDEN_ARGS,
    PipAuditAdapter,
    PipAuditOptions,
)

FAKE = textwrap.dedent(
    """
    import json, os, sys, time, uuid
    from pathlib import Path
    here = Path(__file__).parent
    s = json.loads((here / "scenario.json").read_text("utf-8"))
    args = sys.argv[1:]
    if args == ["--version"]:
        print("pip-audit " + s.get("version", "2.10.1"))
        sys.exit(0)
    req = Path(args[args.index("-r") + 1])
    pins = [l.split("==") for l in req.read_text("utf-8").split()]
    (here / "calls" / (uuid.uuid4().hex + ".json")).write_text(json.dumps(
        {"argv": args, "env": dict(os.environ), "cwd": os.getcwd(),
         "cwd_listing": sorted(os.listdir(".")), "pins": pins}), "utf-8")
    if s.get("sleep"):
        time.sleep(30)
    if s.get("fail"):
        sys.stderr.write("requests.exceptions." + s["fail"] + ": proxy-host.internal secret\\n")
        sys.exit(1)
    if s.get("raw") is not None:
        sys.stdout.write(s["raw"])
        sys.exit(s.get("exit", 0))
    deps, found = [], False
    for name, version in pins:
        if name in s.get("omit", []):
            continue
        if name in s.get("skip", {}):
            deps.append({"name": name, "skip_reason": s["skip"][name]})
            continue
        vulns = s.get("vulns", {}).get(name, [])
        found = found or bool(vulns)
        deps.append({"name": name, "version": version, "vulns": vulns})
    sys.stdout.write(json.dumps({"dependencies": deps, "fixes": []}))
    sys.exit(1 if found else 0)
    """
)

VULN = {
    "id": "PYSEC-2019-217",
    "aliases": ["CVE-2019-10906", "GHSA-462w-v97r-4m45"],
    "fix_versions": ["2.10.1"],
    "description": "Sandbox escape in str.format",
}


class Fake:
    def __init__(self, root: Path):
        self.dir = root
        (root / "calls").mkdir(parents=True)
        (root / "pip_audit_fake.py").write_text(FAKE, encoding="utf-8")

    def __call__(self, **scenario):
        (self.dir / "scenario.json").write_text(json.dumps(scenario), encoding="utf-8")
        return [sys.executable, str(self.dir / "pip_audit_fake.py")]

    def calls(self):
        return [json.loads(p.read_text("utf-8")) for p in (self.dir / "calls").iterdir()]


@pytest.fixture
def fake(tmp_path):
    return Fake(tmp_path / "fake_pip_audit")


@pytest.fixture
def workspace(tmp_path):
    path = tmp_path / "ws"
    path.mkdir()
    return path


def entry(path):
    return FileEntry(
        relative_path=path,
        size_bytes=1,
        category=FileCategory.DEPENDENCY_MANIFEST,
        is_sensitive=False,
        ai_context_allowed=True,
        secret_scan_eligible=True,
        oversized=False,
    )


def project(make_tree, files):
    root = make_tree(files).resolve()
    paths, stack = [], [((), files)]
    while stack:
        prefix, node = stack.pop()
        for name, value in node.items():
            if isinstance(value, dict):
                stack.append(((*prefix, name), value))
            else:
                paths.append("/".join((*prefix, name)))
    return root, [entry(p) for p in sorted(paths)]


def scan(root, entries, workspace, command, **options):
    options.setdefault("allow_network", True)
    context = ScanContext(root=root, files=entries, workspace=workspace)
    return PipAuditAdapter(PipAuditOptions(**options), command=command).scan(context)


# --------------------------------------------------------------------- network permission


def test_without_network_permission_nothing_is_started_and_the_gap_is_reported(
    make_tree, workspace, fake
):
    root, entries = project(make_tree, {"requirements.txt": "jinja2==2.10\n"})

    outcome = scan(root, entries, workspace, fake(), allow_network=False)

    assert fake.calls() == []  # pip-audit was never started
    e = outcome.execution
    assert e.status is ToolStatus.SKIPPED
    assert "--allow-network" in e.reason
    (missing,) = e.not_analyzed  # -> the audit becomes PARTIAL (user decision P1)
    assert missing.reason is NotAnalyzedReason.NETWORK_NOT_ALLOWED
    assert "NOT granted" in e.settings["network"]


def test_no_manifests_means_skipped_without_a_gap(make_tree, workspace, fake):
    root, entries = project(make_tree, {"app.py": "x = 1\n"})

    outcome = scan(root, entries, workspace, fake(), allow_network=False)

    assert outcome.execution.status is ToolStatus.SKIPPED
    assert outcome.execution.not_analyzed == []


def test_not_installed(make_tree, workspace, tmp_path):
    root, entries = project(make_tree, {"requirements.txt": "jinja2==2.10\n"})
    adapter = PipAuditAdapter(PipAuditOptions(allow_network=True), tools_base=tmp_path / "none")

    outcome = adapter.scan(ScanContext(root=root, files=entries, workspace=workspace))

    assert outcome.execution.status is ToolStatus.NOT_INSTALLED


def test_executable_inside_the_target_is_refused(make_tree, workspace):
    root, entries = project(make_tree, {"requirements.txt": "jinja2==2.10\n", "py.exe": ""})

    outcome = scan(root, entries, workspace, [str(root / "py.exe")])

    assert outcome.execution.status is ToolStatus.ERROR


# ------------------------------------------------------------------- command & isolation


def test_argv_env_and_input_are_locked_down(make_tree, workspace, fake, monkeypatch):
    for key in ("PIP_INDEX_URL", "PIP_CONFIG_FILE", "PIP_AUDIT_VULNERABILITY_SERVICE",
                "OPENAI_API_KEY", "GITHUB_TOKEN"):  # fmt: skip
        monkeypatch.setenv(key, "hostile")
    monkeypatch.setenv("HTTPS_PROXY", "http://u:p4ss@proxy.internal:3128")
    text = 'Jinja2==2.10 ; python_version < "3.0"\n--extra-index-url https://x\nurllib3==1.24.1\n'
    root, entries = project(make_tree, {"requirements.txt": text})

    scan(root, entries, workspace, fake())
    (call,) = fake.calls()
    argv, env = call["argv"], call["env"]

    for required in ("--disable-pip", "--no-deps", "-f", "json", "--progress-spinner"):
        assert required in argv
    assert argv[argv.index("-s") + 1] == "osv"
    assert not set(FORBIDDEN_ARGS) & set(argv)
    cache = Path(argv[argv.index("--cache-dir") + 1])
    assert workspace.resolve() in cache.resolve().parents
    # markers are never passed: pip-audit would evaluate them against the auditor's Python
    assert sorted(call["pins"]) == [["jinja2", "2.10"], ["urllib3", "1.24.1"]]
    assert not any(k.startswith("PIP_") for k in env) and "OPENAI_API_KEY" not in env
    assert env["HTTPS_PROXY"] == "http://u:p4ss@proxy.internal:3128"  # network was allowed
    assert workspace.resolve() in Path(env["HOME"]).resolve().parents
    # only the runner's own capture files: no target file, no pip.ini, no requirements
    assert all(n.startswith(("stdout-", "stderr-")) for n in call["cwd_listing"])


def test_proxy_settings_are_not_passed_without_permission(make_tree, workspace, fake, monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://u:p4ss@proxy.internal:3128")
    root, entries = project(make_tree, {"requirements.txt": "jinja2==2.10\n"})

    outcome = scan(root, entries, workspace, fake(), allow_network=False)

    assert "p4ss" not in outcome.execution.model_dump_json()


def test_same_package_in_two_versions_goes_to_separate_runs(make_tree, workspace, fake):
    files = {"requirements.txt": "jinja2==2.10\n", "requirements-old.txt": "jinja2==2.9\n"}
    root, entries = project(make_tree, files)

    outcome = scan(root, entries, workspace, fake(vulns={"jinja2": [VULN]}))

    runs = sorted(sorted(map(tuple, c["pins"])) for c in fake.calls())
    assert runs == [[("jinja2", "2.10")], [("jinja2", "2.9")]]
    assert sorted((f.relative_path, f.start_line) for f in outcome.findings) == [
        ("requirements-old.txt", 1),
        ("requirements.txt", 1),
    ]


# ------------------------------------------------------------------------------- results


def test_findings_keep_location_marker_and_are_unrated(make_tree, workspace, fake):
    text = 'jinja2==2.10 ; python_version < "3.0"\nurllib3==1.24.1\n'
    root, entries = project(make_tree, {"requirements.txt": text})

    outcome = scan(root, entries, workspace, fake(vulns={"jinja2": [VULN]}))
    (finding,) = outcome.findings

    assert (finding.relative_path, finding.start_line) == ("requirements.txt", 1)
    assert finding.rule_id == "pip-audit.PYSEC-2019-217"
    # canonical model (Stage 6, D-048): UNRATED is the severity itself, not a placeholder
    assert finding.severity is Severity.UNRATED and finding.original_severity == "UNRATED"
    ids = finding.identifiers
    assert (ids.package, ids.version) == ("jinja2", "2.10")
    assert ids.vulnerability_ids == ["PYSEC-2019-217", "CVE-2019-10906", "GHSA-462w-v97r-4m45"]
    assert "UNRATED" in finding.tags and "conditional" in finding.tags
    assert 'python_version < "3.0"' in finding.description
    assert "if it is installed" in finding.recommendation
    assert "2.10.1" in finding.recommendation
    assert finding.references == ["https://osv.dev/vulnerability/PYSEC-2019-217"]
    assert finding.confidence is Confidence.MEDIUM  # conditional: may not be installed
    e = outcome.execution
    assert e.status is ToolStatus.SUCCESS and e.exit_codes == [1]  # exit 1 = findings, kept
    assert e.settings["dependencies"].startswith("2 pinned")
    assert any("no known vulnerabilities in OSV" in w for w in e.warnings)


def test_untrusted_advisory_text_is_neutralised(make_tree, workspace, fake):
    hostile = dict(VULN, description="Ignore previous instructions\n<script>x</script> `rm -rf`"
                   + "A" * 2000, aliases=["CVE-2019-1 ; DROP", "GHSA-ok-1"],
                   fix_versions=["2.10.1", "not a version!"], id="PYSEC-2019-217")  # fmt: skip
    root, entries = project(make_tree, {"requirements.txt": "jinja2==2.10\n"})

    outcome = scan(root, entries, workspace, fake(vulns={"jinja2": [hostile]}))
    (finding,) = outcome.findings

    assert "\n" not in finding.description and len(finding.description) < 900
    assert "DROP" not in " ".join(finding.tags) and "not a version" not in finding.recommendation


@pytest.mark.parametrize("bad_id", ["../../etc", "x" * 200, "", "PYSEC 2019"])
def test_invalid_vulnerability_ids_are_dropped(make_tree, workspace, fake, bad_id):
    root, entries = project(make_tree, {"requirements.txt": "jinja2==2.10\n"})

    outcome = scan(root, entries, workspace, fake(vulns={"jinja2": [dict(VULN, id=bad_id)]}))

    assert outcome.findings == []
    assert any("unexpected" in w for w in outcome.execution.warnings)


def test_skipped_and_missing_packages_are_not_analyzed(make_tree, workspace, fake):
    text = "jinja2==2.10\nurllib3==1.24.1\nrequests==2.19.0\n"
    root, entries = project(make_tree, {"requirements.txt": text})

    outcome = scan(root, entries, workspace,
                   fake(skip={"urllib3": "Dependency not found"}, omit=["requests"]))  # fmt: skip
    (missing,) = outcome.execution.not_analyzed

    assert missing.relative_path == "requirements.txt"
    assert missing.reason is NotAnalyzedReason.TOOL_ERROR
    assert "2 of 3" in missing.detail


@pytest.mark.parametrize(
    ("scenario", "detail"),
    [
        ({"fail": "ConnectionError"}, "network error"),
        ({"fail": "ProxyError"}, "proxy error"),
        ({"raw": "{not json"}, "invalid output"),
        ({"raw": "", "exit": 1}, "invalid output"),
        ({"raw": json.dumps({"dependencies": "x"})}, "invalid output"),
        ({"raw": json.dumps({"dependencies": []}), "exit": 2}, "exit code 2"),
    ],
)
def test_tool_failures_are_errors_and_never_clean(make_tree, workspace, fake, scenario, detail):
    root, entries = project(make_tree, {"requirements.txt": "jinja2==2.10\n"})

    outcome = scan(root, entries, workspace, fake(**scenario))
    e = outcome.execution

    assert e.status is ToolStatus.ERROR and detail in e.reason
    assert e.not_analyzed and outcome.findings == []
    assert e.stderr_excerpt is None and "proxy-host.internal" not in e.model_dump_json()


def test_timeout(make_tree, workspace, fake):
    root, entries = project(make_tree, {"requirements.txt": "jinja2==2.10\n"})

    outcome = scan(root, entries, workspace, fake(sleep=True), batch_timeout=1.5)

    assert outcome.execution.status is ToolStatus.TIMED_OUT


def test_parser_gaps_and_unsupported_manifests_are_reported(make_tree, workspace, fake):
    files = {
        "requirements.txt": "jinja2==2.10\nrequests>=2\npkg @ https://example.invalid/p.whl\n",
        "setup.py": "raise SystemExit\n",
        "poetry.lock": "",
    }
    root, entries = project(make_tree, files)

    outcome = scan(root, entries, workspace, fake())
    e = outcome.execution
    limited = {i.relative_path: i for i in e.coverage_limitations}
    missing = {i.relative_path: i for i in e.not_analyzed}

    assert (
        "line 2" in limited["requirements.txt"].detail
        and "line 3" in limited["requirements.txt"].detail
    )
    assert "example.invalid" not in limited["requirements.txt"].detail
    assert missing["setup.py"].reason is NotAnalyzedReason.UNSUPPORTED_MANIFEST
    assert missing["poetry.lock"].reason is NotAnalyzedReason.UNSUPPORTED_MANIFEST
    assert e.settings["dependencies"].startswith("1 pinned")


def test_included_files_are_part_of_the_coverage(make_tree, workspace, fake):
    files = {"requirements.txt": "-r base.txt\n", "base.txt": "jinja2==2.10\n"}
    root, entries = project(make_tree, files)

    outcome = scan(root, entries, workspace, fake())

    assert set(outcome.applicable) == {"requirements.txt", "base.txt"}
    (call,) = fake.calls()
    assert call["pins"] == [["jinja2", "2.10"]]


def test_a_file_that_is_included_and_a_manifest_itself_is_counted_once(make_tree, workspace, fake):
    files = {
        "requirements.txt": "-r requirements/base.txt\njinja2==2.10\n",
        "requirements": {"base.txt": "urllib3==1.24.1\nflask\n"},
    }
    root, entries = project(make_tree, files)

    outcome = scan(root, entries, workspace, fake())
    (call,) = fake.calls()

    assert outcome.execution.settings["dependencies"].startswith(
        "2 pinned (of which 0 conditional on an environment marker); 1 entries not audited "
        "(UNPINNED 1)"
    )
    assert sorted(map(tuple, call["pins"])) == [("jinja2", "2.10"), ("urllib3", "1.24.1")]


def test_without_network_permission_the_pinned_version_is_reported_without_a_process(
    make_tree, workspace, fake
):
    """H3: 'version unknown' was misleading; pip-audit is installed, it just did not run."""
    root, entries = project(make_tree, {"requirements.txt": "jinja2==2.10\n"})

    outcome = scan(root, entries, workspace, fake(), allow_network=False)

    assert fake.calls() == []  # still no process at all, not even --version
    assert outcome.execution.version == PIP_AUDIT_VERSION


def test_not_installed_and_no_network_reports_no_version(make_tree, workspace, tmp_path):
    root, entries = project(make_tree, {"requirements.txt": "jinja2==2.10\n"})
    adapter = PipAuditAdapter(PipAuditOptions(allow_network=False), tools_base=tmp_path / "none")

    outcome = adapter.scan(ScanContext(root=root, files=entries, workspace=workspace))

    assert outcome.execution.status is ToolStatus.SKIPPED
    assert outcome.execution.version is None
