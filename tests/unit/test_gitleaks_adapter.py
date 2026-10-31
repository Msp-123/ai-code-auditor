"""Gitleaks adapter logic, driven by a fake gitleaks (our own script) for fault injection.

The fake echoes the matched line into every non-allowlisted field (Secret, Match, Line,
Fingerprint, Description, ...), so these tests prove that only RuleID/StartLine survive.
"""

import hashlib
import json
import os
import sys
import textwrap
from pathlib import Path

import pytest

import auditor.scanners.gitleaks_adapter as adapter_module
from auditor.core.models import (
    Confidence,
    FileCategory,
    FileEntry,
    NotAnalyzedReason,
    Severity,
    ToolStatus,
)
from auditor.scanners.base import ScanContext
from auditor.scanners.gitleaks_adapter import (
    ARGV_TEMPLATE,
    CONFIG_DIR,
    CONFIG_PATH,
    FORBIDDEN_ARGS,
    PATH_RULES,
    GitleaksAdapter,
    GitleaksOptions,
    config_for,
    end_marker,
    with_end_marker,
)

FAKE_GITLEAKS = textwrap.dedent(
    """
    import hashlib, json, os, sys, time, uuid
    from pathlib import Path
    here = Path(__file__).parent
    scenario = json.loads((here / "scenario.json").read_text("utf-8"))
    if sys.argv[1:] == ["version"]:
        print(scenario.get("version", "8.30.1"))
        sys.exit(0)
    started = time.time()
    first = sys.stdin.buffer.read(64)
    if b"NOREAD" in first:  # exits without consuming the rest of its input
        sys.stdout.write("[]")
        sys.exit(0)
    data = first if b"EARLYCLOSE" in first else first + sys.stdin.buffer.read()
    text = data.decode("utf-8", "replace")
    sys.stderr.write("stderr-echo: " + text[:200])
    config = Path(sys.argv[sys.argv.index("--config") + 1]).name if "--config" in sys.argv else ""
    cut = data.rfind(b"\\n" * 8 + b"ghp_")
    head = data[:cut] if cut >= 0 else data
    rec = {"argv": sys.argv[1:], "env": dict(os.environ), "cwd": os.getcwd(), "config": config,
           "cwd_listing": sorted(os.listdir(".")), "head_sha": hashlib.sha256(head).hexdigest(),
           "start": started}
    if "SLEEP" in text:
        time.sleep(30)
    if "PAUSE" in text:
        time.sleep(0.5)
    out = []
    for n, line in enumerate(text.split("\\n"), 1):
        if "ghp_" in line and not scenario.get("hide_marker"):
            out.append({"RuleID": "github-pat", "StartLine": n})
            if scenario.get("double_marker"):
                out.append({"RuleID": "github-pat", "StartLine": n})
        k8s = "kubernetes" in config or scenario.get("pathless_everywhere")
        if "kind: Secret" in line and k8s and not scenario.get("no_k8s"):
            out.append({"RuleID": "auditor-pathless-kubernetes-secret-yaml", "StartLine": n})
        if "FAKESECRET" not in line:
            continue
        rule = line.split("RULE=")[1].split()[0] if "RULE=" in line else "generic-api-key"
        item = {"RuleID": rule, "StartLine": int(scenario.get("line", n)), "EndLine": n,
                "StartColumn": 3, "EndColumn": 40, "Secret": line, "Match": line,
                "Line": line, "Fingerprint": ":" + rule + ":" + line, "Entropy": 4.2,
                "Description": "desc " + line, "File": line, "SymlinkFile": line,
                "Author": line, "Email": line, "Message": line, "Commit": line,
                "Date": line, "Tags": [line]}
        out.append(item)
        if "SECONDMATCH" in line:  # a second match of the same rule on the same line
            out.append(dict(item, StartColumn=50, EndColumn=90))
        if "EXACTDUP" in line:  # Gitleaks reporting the very same match twice
            out.append(dict(item))
    if scenario.get("reverse_order"):  # Gitleaks' per-file result order is not stable
        out.reverse()
    rec["end"] = time.time()
    (here / "calls" / (uuid.uuid4().hex + ".json")).write_text(json.dumps(rec), "utf-8")
    if "EXIT2" in text:
        sys.exit(2)
    if "BADJSON" in text:
        sys.stdout.write("{not json")
    elif "EMPTYOUT" in text:
        pass
    elif "FLOOD" in text:
        sys.stdout.write("[" + " " * 5_000_000 + "]")
    elif "OBJECT" in text:
        sys.stdout.write("{}")
    else:
        sys.stdout.write(json.dumps(out))
    sys.exit(0)
    """
)


def entry(path, category=FileCategory.OTHER, size=1):
    return FileEntry(
        relative_path=path,
        size_bytes=size,
        category=category,
        is_sensitive=path.endswith((".env", ".p12", ".pfx")),
        ai_context_allowed=True,
        secret_scan_eligible=True,
        oversized=False,
    )


class Fake:
    def __init__(self, root: Path):
        self.dir = root
        (root / "calls").mkdir(parents=True)
        (root / "gitleaks.py").write_text(FAKE_GITLEAKS, encoding="utf-8")

    def __call__(self, **scenario):
        (self.dir / "scenario.json").write_text(json.dumps(scenario), encoding="utf-8")
        return [sys.executable, str(self.dir / "gitleaks.py")]

    def calls(self):
        return [json.loads(p.read_text("utf-8")) for p in (self.dir / "calls").iterdir()]

    def file_calls(self, root, files):
        """Calls that scanned one of the given files (the self-check calls are left out)."""
        wanted = {}
        for rel in files:
            data = (root / rel).read_bytes()
            head = data if (not data or data.endswith(b"\n")) else data + b"\n"
            wanted[hashlib.sha256(head).hexdigest()] = rel
        return {wanted[c["head_sha"]]: c for c in self.calls() if c["head_sha"] in wanted}


@pytest.fixture
def fake(tmp_path):
    return Fake(tmp_path / "fake_gitleaks")


@pytest.fixture
def workspace(tmp_path):
    path = tmp_path / "ws"
    path.mkdir()
    return path


def tree(make_tree, files):
    """files: {relpath: content}; returns (root, entries)."""
    spec = {}
    for rel, content in files.items():
        node = spec
        parts = rel.split("/")
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = content
    root = make_tree(spec).resolve()
    cat = {"tests": FileCategory.TEST}
    entries = [entry(rel, cat.get(rel.split("/")[0], FileCategory.OTHER)) for rel in files]
    return root, entries


def scan(root, entries, workspace, command, **options):
    context = ScanContext(root=root, files=entries, workspace=workspace)
    return GitleaksAdapter(GitleaksOptions(**options), command=command).scan(context)


CANARY = "FAKESECRET-" + "zq81" + "XcV7" + "pL0w"  # assembled at runtime, no literal


def everything(outcome) -> str:
    return outcome.execution.model_dump_json() + "".join(
        f.model_dump_json() for f in outcome.findings
    )


# ------------------------------------------------------------------------------ status


def test_not_installed_when_tool_environment_is_missing(make_tree, workspace, tmp_path):
    root, entries = tree(make_tree, {"a.py": "x"})
    adapter = GitleaksAdapter(GitleaksOptions(), tools_base=tmp_path / "no-tools")

    outcome = adapter.scan(ScanContext(root=root, files=entries, workspace=workspace))

    assert outcome.execution.status is ToolStatus.NOT_INSTALLED


def test_executable_inside_the_target_is_refused(make_tree, workspace):
    root, entries = tree(make_tree, {"a.py": "x", "gitleaks.exe": ""})

    outcome = scan(root, entries, workspace, [str(root / "gitleaks.exe")])

    assert outcome.execution.status is ToolStatus.ERROR
    assert "inside the scan target" in outcome.execution.reason


def test_executable_with_wrong_hash_is_never_run(make_tree, workspace, tmp_path):
    tools = tmp_path / "tools"
    exe = tools / "gitleaks" / "8.30.1" / ("gitleaks.exe" if os.name == "nt" else "gitleaks")
    exe.parent.mkdir(parents=True)
    exe.write_bytes(b"MZ not the pinned binary")
    root, entries = tree(make_tree, {"a.py": "x"})

    outcome = GitleaksAdapter(GitleaksOptions(), tools_base=tools).scan(
        ScanContext(root=root, files=entries, workspace=workspace)
    )

    assert outcome.execution.status is ToolStatus.ERROR
    assert "SHA-256" in outcome.execution.reason


def test_platform_without_pinned_hash_is_an_error(make_tree, workspace, tmp_path, monkeypatch):
    tools = tmp_path / "tools"
    exe = tools / "gitleaks" / "8.30.1" / ("gitleaks.exe" if os.name == "nt" else "gitleaks")
    exe.parent.mkdir(parents=True)
    exe.write_bytes(b"x")
    monkeypatch.setattr(adapter_module, "pinned_gitleaks_sha256", lambda: None)
    root, entries = tree(make_tree, {"a.py": "x"})

    outcome = GitleaksAdapter(GitleaksOptions(), tools_base=tools).scan(
        ScanContext(root=root, files=entries, workspace=workspace)
    )

    assert outcome.execution.status is ToolStatus.ERROR
    assert "no pinned" in outcome.execution.reason


@pytest.mark.parametrize("name", ["gitleaks.toml", "path-kubernetes-secret-yaml.toml"])
def test_tampered_configuration_is_an_error(make_tree, workspace, fake, tmp_path, name):
    tampered = tmp_path / "configs"
    tampered.mkdir()
    for source in CONFIG_DIR.glob("*.toml"):
        (tampered / source.name).write_bytes(source.read_bytes())
    target = tampered / name
    target.write_bytes(target.read_bytes() + b"\n[allowlist]\nregexes = ['''.*''']\n")
    root, entries = tree(make_tree, {"a.py": "x"})

    outcome = scan(root, entries, workspace, fake(), config_dir=tampered)

    assert outcome.execution.status is ToolStatus.ERROR
    assert "integrity" in outcome.execution.reason
    assert fake.calls() == []


def test_skipped_without_eligible_files(make_tree, workspace, fake):
    root, _ = tree(make_tree, {"a.py": "x"})

    outcome = scan(root, [], workspace, fake())

    assert outcome.execution.status is ToolStatus.SKIPPED


@pytest.mark.parametrize("workers", [0, 17, -1])
def test_worker_count_has_a_safe_upper_bound(workers):
    with pytest.raises(ValueError):
        GitleaksOptions(workers=workers)


# --------------------------------------------------------------------- command & isolation


def test_argv_template_is_locked_down():
    joined = " ".join(ARGV_TEMPLATE)
    for required in (
        "stdin",
        "--redact=100",
        "--log-level",
        "error",
        "--exit-code",
        "0",
        "--ignore-gitleaks-allow",
        "--report-path",
        "-",
        "--no-banner",
    ):
        assert required in ARGV_TEMPLATE, required
    for forbidden in FORBIDDEN_ARGS:
        assert forbidden not in ARGV_TEMPLATE
    assert "debug" not in joined and "trace" not in joined


def test_command_line_environment_and_cwd_are_isolated(make_tree, workspace, fake, monkeypatch):
    for key in (
        "GITLEAKS_CONFIG",
        "GITLEAKS_CONFIG_TOML",
        "OPENAI_API_KEY",
        "AWS_SECRET_ACCESS_KEY",
        "GITHUB_TOKEN",
    ):
        monkeypatch.setenv(key, "hostile-value")
    root, entries = tree(make_tree, {"a.py": "x = 1\n"})

    outcome = scan(root, entries, workspace, fake())
    call = fake.file_calls(root, ["a.py"])["a.py"]
    argv, env = call["argv"], call["env"]

    assert outcome.execution.status is ToolStatus.SUCCESS
    assert argv[0] == "stdin"
    config = Path(argv[argv.index("--config") + 1])
    assert config.read_bytes() == CONFIG_PATH.read_bytes()  # verified private copy
    assert workspace.resolve() in config.resolve().parents
    ignore = Path(argv[argv.index("--gitleaks-ignore-path") + 1])
    assert ignore.read_bytes() == b""
    assert call["cwd_listing"] == []  # no .gitleaks.toml / .gitleaksignore can be picked up
    assert workspace.resolve() in Path(call["cwd"]).resolve().parents
    assert not any(k.upper().startswith("GITLEAKS") for k in env)
    assert "hostile-value" not in json.dumps(env)
    assert workspace.resolve() in Path(env["HOME"]).resolve().parents
    assert env["USERPROFILE"] == env["HOME"]


def test_every_file_gets_its_own_process_with_exactly_its_bytes(make_tree, workspace, fake):
    files = {"a.py": "a\n", "b/.env": "B=1\n", "tests/t.py": "t\n", "c.yml": "c: 1\n"}
    root, entries = tree(make_tree, files)

    outcome = scan(root, entries, workspace, fake())
    calls = fake.file_calls(root, files)

    assert set(calls) == set(files)  # each file's exact bytes went to a process of its own
    assert len(fake.calls()) == len(files) + 2  # + the two self-check processes
    assert {rel: c["config"] for rel, c in calls.items()} == {
        "a.py": "gitleaks.toml",
        "b/.env": "gitleaks.toml",
        "tests/t.py": "gitleaks.toml",
        "c.yml": "path-kubernetes-secret-yaml.toml",
    }
    assert outcome.execution.files_analyzed == 4 == outcome.execution.files_requested
    assert outcome.findings == []  # the end markers are removed


def test_workers_run_in_parallel_and_give_the_same_result(make_tree, workspace, fake, tmp_path):
    files = {f"m{i}.py": f"PAUSE {i}\nk = 1 FAKESECRET RULE=github-pat\n" for i in range(8)}
    root, entries = tree(make_tree, files)
    serial = scan(root, entries, workspace, fake(), workers=1)
    parallel_fake = Fake(tmp_path / "fake2")
    ws2 = tmp_path / "ws2"
    ws2.mkdir()

    parallel = scan(root, entries, ws2, parallel_fake(), workers=4)

    key = sorted((f.relative_path, f.start_line, f.rule_id) for f in serial.findings)
    assert key == sorted((f.relative_path, f.start_line, f.rule_id) for f in parallel.findings)
    calls = sorted(parallel_fake.calls(), key=lambda c: c["start"])
    overlaps = sum(1 for a, b in zip(calls, calls[1:], strict=False) if b["start"] < a["end"])
    assert overlaps >= 1  # processes really overlapped
    assert parallel.execution.settings["workers"] == "4"


# --------------------------------------------------------------------- findings & leakage


def test_findings_are_mapped_and_nothing_but_rule_and_line_is_kept(make_tree, workspace, fake):
    files = {
        "app.py": f"import os\n\nTOKEN = 1  {CANARY} RULE=github-pat\n",
        "keys/id_rsa": f"{CANARY} RULE=private-key\n",
        ".env": f"A=1\nB = {CANARY} RULE=generic-api-key\n",
        "tests/test_x.py": f"{CANARY} RULE=aws-access-token\n",
        "web/a.js": f"\n{CANARY} RULE=jwt\n",
    }
    root, entries = tree(make_tree, files)

    outcome = scan(root, entries, workspace, fake())
    by_path = {f.relative_path: f for f in outcome.findings}

    assert {(p, f.rule_id, f.start_line) for p, f in by_path.items()} == {
        ("app.py", "gitleaks.github-pat", 3),
        ("keys/id_rsa", "gitleaks.private-key", 1),
        (".env", "gitleaks.generic-api-key", 2),
        ("tests/test_x.py", "gitleaks.aws-access-token", 1),
        ("web/a.js", "gitleaks.jwt", 2),
    }
    assert by_path["keys/id_rsa"].severity is Severity.CRITICAL
    assert by_path["app.py"].severity is Severity.HIGH
    assert by_path[".env"].confidence is Confidence.LOW
    test_finding = by_path["tests/test_x.py"]
    assert "test-path" in test_finding.tags
    # K4: the test location never lowers severity or confidence
    assert (test_finding.severity, test_finding.confidence) == (Severity.HIGH, Confidence.HIGH)
    for f in outcome.findings:
        # P9: the match position (columns) is kept as location metadata; nothing else is
        assert (f.start_column, f.end_column, f.end_line) == (3, 40, f.start_line)
        assert f.verification_status.value == "NEEDS_REVIEW"
        assert all(e.redacted for e in f.evidence)
    text = everything(outcome)
    assert CANARY not in text
    for key in (
        '"Secret"',
        '"Match"',
        '"Line"',
        '"Fingerprint"',
        '"Entropy"',
        '"Author"',
        '"Email"',
        '"Message"',
        '"Commit"',
        "desc FAKESECRET",
    ):
        assert key not in text, key


def test_content_ids_are_git_blob_ids_of_the_analysed_bytes_and_never_serialised(
    make_tree, workspace, fake
):
    """Stage 6 (R2): computed from the file's own bytes, before the end marker is appended."""
    import hashlib

    data = f"x = 1\nTOKEN = 1  {CANARY} RULE=github-pat\n".encode()
    root, entries = tree(make_tree, {"app.py": data.decode()})

    (finding,) = scan(root, entries, workspace, fake()).findings

    data = (root / "app.py").read_bytes()  # the bytes on disk (line endings as written)
    header = b"blob %d\0" % len(data)
    assert finding.content_ids == {
        "sha1": hashlib.sha1(header + data).hexdigest(),  # noqa: S324 - git's object id
        "sha256": hashlib.sha256(header + data).hexdigest(),
    }
    assert "content_ids" not in finding.model_dump_json()
    assert finding.content_ids["sha1"] not in finding.model_dump_json()


def test_stderr_of_the_tool_is_never_kept(make_tree, workspace, fake):
    root, entries = tree(make_tree, {"a.py": f"{CANARY}\n", "b.py": "EXIT2\n"})

    outcome = scan(root, entries, workspace, fake())

    assert outcome.execution.stderr_excerpt is None
    assert CANARY not in everything(outcome) and "stderr-echo" not in everything(outcome)


def test_workspace_holds_no_copy_of_any_content(make_tree, workspace, fake):
    root, entries = tree(make_tree, {"a.env": f"K={CANARY}\n"})

    scan(root, entries, workspace, fake())

    for path in workspace.rglob("*"):
        if path.is_file():
            assert CANARY.encode() not in path.read_bytes(), path.name


def test_unexpected_rule_ids_and_lines_are_dropped(make_tree, workspace, fake):
    root, entries = tree(make_tree, {"a.py": f"{CANARY} RULE=bad/../rule\n"})

    outcome = scan(root, entries, workspace, fake())
    assert outcome.findings == []
    assert any("unexpected rule id" in w for w in outcome.execution.warnings)

    fake2 = Fake(workspace.parent / "fake_line")
    ws2 = workspace.parent / "ws_line"
    ws2.mkdir()
    (root / "b.py").write_text(f"{CANARY} RULE=github-pat\n", encoding="utf-8")
    outcome2 = scan(root, [entry("b.py")], ws2, fake2(line=99))
    assert outcome2.findings == []
    assert any("line number" in w for w in outcome2.execution.warnings)


# -------------------------------------------------------------------- coverage & failures


@pytest.mark.parametrize(
    ("content", "detail"),
    [
        ("EXIT2\n", "exit code 2"),
        ("BADJSON\n", "invalid JSON"),
        ("EMPTYOUT\n", "no report"),
        ("OBJECT\n", "unexpected report format"),
        ("FLOOD\n", "output too large"),
    ],
)
def test_per_file_tool_failures_are_not_analyzed(make_tree, workspace, fake, content, detail):
    root, entries = tree(make_tree, {"bad.py": content, "good.py": "ok\n"})

    outcome = scan(root, entries, workspace, fake())
    (missing,) = outcome.execution.not_analyzed

    assert missing.relative_path == "bad.py"
    assert missing.reason is NotAnalyzedReason.TOOL_ERROR
    assert detail in missing.detail
    assert outcome.execution.files_analyzed == 1
    assert outcome.execution.status is ToolStatus.SUCCESS  # the rest is still reported


@pytest.mark.parametrize("size", [0, 10, 3 * 1024 * 1024])
def test_input_not_consumed_is_not_counted_as_scanned(make_tree, workspace, fake, size):
    # A small input fits into the pipe buffer, so "all bytes written" proves nothing there;
    # the missing end marker does.
    root, entries = tree(make_tree, {"f.py": "NOREAD" + "x" * size + "\n"})

    outcome = scan(root, entries, workspace, fake())

    (missing,) = outcome.execution.not_analyzed
    assert missing.reason is NotAnalyzedReason.TOOL_ERROR
    assert "end marker" in missing.detail or "input not fully consumed" in missing.detail
    assert outcome.execution.status is ToolStatus.ERROR  # every file failed


def test_early_close_after_partial_reading_is_not_counted_as_scanned(make_tree, workspace, fake):
    content = "EARLYCLOSE\n" + "".join(f"line {i}\n" for i in range(200))
    root, entries = tree(make_tree, {"f.py": content, "ok.py": "fine\n"})

    outcome = scan(root, entries, workspace, fake())

    (missing,) = outcome.execution.not_analyzed
    assert missing.relative_path == "f.py" and "end marker" in missing.detail
    assert outcome.execution.files_analyzed == 1


def test_self_check_failure_means_no_file_is_trusted(make_tree, workspace, fake):
    root, entries = tree(make_tree, {"a.py": "ok\n"})

    outcome = scan(root, entries, workspace, fake(hide_marker=True))

    assert outcome.execution.status is ToolStatus.ERROR
    assert "self-check failed" in outcome.execution.reason
    assert fake.file_calls(root, ["a.py"]) == {}  # no target file was sent


def test_self_check_covers_the_path_rule_configuration(make_tree, workspace, fake):
    root, entries = tree(make_tree, {"a.py": "ok\n"})

    outcome = scan(root, entries, workspace, fake(no_k8s=True))

    assert outcome.execution.status is ToolStatus.ERROR
    assert "path-rule configuration" in outcome.execution.reason


def test_per_file_timeout(make_tree, workspace, fake):
    root, entries = tree(make_tree, {"slow.py": "SLEEP\n", "fast.py": "ok\n"})

    outcome = scan(root, entries, workspace, fake(), file_timeout=2.0)

    (missing,) = outcome.execution.not_analyzed
    assert (missing.relative_path, missing.reason) == ("slow.py", NotAnalyzedReason.TIMED_OUT)


def test_total_timeout_marks_the_rest_as_timed_out(make_tree, workspace, fake):
    files = {f"s{i}.py": "SLEEP\n" for i in range(6)}
    root, entries = tree(make_tree, files)

    outcome = scan(root, entries, workspace, fake(), workers=1, file_timeout=1.5, total_timeout=2.0)

    assert outcome.execution.status is ToolStatus.TIMED_OUT
    assert len(outcome.execution.not_analyzed) == 6
    assert {n.reason for n in outcome.execution.not_analyzed} == {NotAnalyzedReason.TIMED_OUT}


def test_file_over_the_size_limit_is_not_sent(make_tree, workspace, fake):
    root, entries = tree(make_tree, {"big.bin": "x" * 5000, "a.py": "ok\n"})

    outcome = scan(root, entries, workspace, fake(), max_file_bytes=1000)

    (missing,) = outcome.execution.not_analyzed
    assert (missing.relative_path, missing.reason) == ("big.bin", NotAnalyzedReason.SIZE_LIMIT)
    assert set(fake.file_calls(root, ["big.bin", "a.py"])) == {"a.py"}


def test_file_replaced_before_reading_is_not_analyzed(make_tree, workspace, fake, junction):
    root, entries = tree(make_tree, {"a.py": "ok\n", "d/x.py": "ok\n"})
    outside = root.parent / "outside_dir"
    outside.mkdir()
    (root / "d" / "x.py").unlink()
    (root / "d").rmdir()
    junction(root / "d", outside)

    outcome = scan(root, entries, workspace, fake())

    (missing,) = outcome.execution.not_analyzed
    assert missing.relative_path == "d/x.py"
    assert missing.reason in (NotAnalyzedReason.CHANGED_BEFORE_SCAN, NotAnalyzedReason.IO_ERROR)


def test_path_rules_are_applied_per_file_and_only_archives_stay_limited(make_tree, workspace, fake):
    files = {
        "k8s/secret.yaml": "apiVersion: v1\nkind: Secret\n",
        "notes/secret.txt": "apiVersion: v2\nkind: Secret\n",  # same rule match, other path
        "main.tf": "x\n",
        "nuget.config": "<x/>\n",
        "site.php": "<?php\n",
        "ci.yml": "on: push\n",
        "bundle.zip": "PK",
        "a.py": "ok\n",
    }
    root, entries = tree(make_tree, files)

    outcome = scan(root, entries, workspace, fake())
    configs = {rel: c["config"] for rel, c in fake.file_calls(root, files).items()}
    limited = {item.relative_path: item for item in outcome.execution.coverage_limitations}

    assert configs == {
        "k8s/secret.yaml": "path-kubernetes-secret-yaml.toml",
        "notes/secret.txt": "gitleaks.toml",
        "main.tf": "path-hashicorp-tf-password.toml",
        "nuget.config": "path-nuget-config-password.toml",
        "site.php": "path-freemius-secret-key.toml",
        "ci.yml": "path-kubernetes-secret-yaml.toml",
        "bundle.zip": "gitleaks.toml",
        "a.py": "gitleaks.toml",
    }
    assert set(limited) == {"bundle.zip"} and limited["bundle.zip"].reason == "CONTENT_NOT_DECODED"
    ((path, rule, line, tags),) = [
        (f.relative_path, f.rule_id, f.start_line, f.tags) for f in outcome.findings
    ]
    assert (path, rule, line) == ("k8s/secret.yaml", "gitleaks.kubernetes-secret-yaml", 2)
    assert "path-rule-applied-by-auditor" in tags
    assert outcome.execution.files_analyzed == len(files)


def test_pkcs12_is_a_potentially_sensitive_file_not_a_secret_value(make_tree, workspace, fake):
    root, entries = tree(make_tree, {"cert.p12": "bin", "keys/ID.PFX": "bin", "a.py": "ok\n"})

    outcome = scan(root, entries, workspace, fake())
    by_path = {f.relative_path: f for f in outcome.findings}

    assert set(by_path) == {"cert.p12", "keys/ID.PFX"}
    for f in by_path.values():
        assert f.rule_id == "gitleaks.pkcs12-file"
        assert "POTENTIALLY_SENSITIVE_FILE" in f.tags and "secret" not in f.tags
        assert "No secret value was detected" in f.description
        assert f.start_line is None and f.confidence is Confidence.LOW
    assert outcome.execution.coverage_limitations == []  # the content was scanned as well


def test_path_rule_result_for_a_non_matching_file_is_dropped(make_tree, workspace, fake):
    root, entries = tree(make_tree, {"notes.txt": "kind: Secret\n"})

    outcome = scan(root, entries, workspace, fake(pathless_everywhere=True))

    assert outcome.findings == []
    assert any("non-matching file" in w for w in outcome.execution.warnings)


def test_config_selection_uses_the_path_regexes_of_the_pinned_rules():
    assert config_for("deploy/app.YAML") == (
        "path-kubernetes-secret-yaml.toml",
        "kubernetes-secret-yaml",
    )
    assert config_for("x/main.hcl")[1] == "hashicorp-tf-password"
    assert config_for("src/NuGet.Config")[1] == "nuget-config-password"
    assert config_for("web/index.php")[1] == "freemius-secret-key"
    for plain in ("a.py", "yaml.txt", "a.yaml.bak", "tf", "cert.p12"):
        assert config_for(plain) == ("gitleaks.toml", None), plain


def test_content_path_rules_are_mutually_exclusive():
    names = ["a.yaml", "a.yml", "a.tf", "a.hcl", "nuget.config", "a.php", "x.yaml.php"]
    content_rules = [p for p in PATH_RULES if p.config]
    for name in names:
        matching = [p.rule for p in content_rules if __import__("re").search(p.path, name)]
        assert len(matching) <= 1, (name, matching)


@pytest.mark.parametrize(
    ("data", "line"),
    [(b"", 9), (b"x", 10), (b"x\n", 10), (b"a\r\nb\r\n", 11), (b"a\nb", 11)],
)
def test_end_marker_line_arithmetic(data, line):
    marker = end_marker()
    payload, marker_line = with_end_marker(data, marker)

    assert marker_line == line
    assert payload.split(b"\n")[marker_line - 1] == marker
    assert payload.startswith(data) and marker.startswith(b"ghp_") and len(marker) == 40


def test_target_gitleaks_files_and_inline_allows_are_reported_as_ignored(
    make_tree, workspace, fake
):
    files = {
        ".gitleaks.toml": "[allowlist]",
        "sub/.gitleaksignore": "x",
        "a.py": f"k = 1  {CANARY} RULE=github-pat # gitleaks:allow\n",
    }
    root, entries = tree(make_tree, files)

    outcome = scan(root, entries, workspace, fake())

    assert [f.rule_id for f in outcome.findings] == ["gitleaks.github-pat"]  # still reported
    warnings = " ".join(outcome.execution.warnings)
    assert "2 Gitleaks configuration/ignore file(s)" in warnings
    assert "1 inline 'gitleaks:allow'" in warnings


def test_scopes_are_reported_separately(make_tree, workspace, fake):
    root, entries = tree(make_tree, {"a.py": "ok"})

    settings = scan(root, entries, workspace, fake()).execution.settings

    assert settings["scope_working_tree"].startswith("SCANNED")
    assert settings["scope_git_history"].startswith("NOT_SCANNED")


def test_working_tree_scope_reflects_what_really_happened(make_tree, workspace, fake, tmp_path):
    root, entries = tree(make_tree, {"bad.py": "EXIT2\n", "ok.py": "ok\n"})

    partial = scan(root, entries, workspace, fake()).execution.settings["scope_working_tree"]
    missing = GitleaksAdapter(GitleaksOptions(), tools_base=tmp_path / "none").scan(
        ScanContext(root=root, files=entries, workspace=workspace)
    )

    assert partial.startswith("PARTIALLY_SCANNED (1 of 2")
    assert missing.execution.settings["scope_working_tree"].startswith("NOT_SCANNED")


def test_version_other_than_the_pinned_one_is_warned(make_tree, workspace, fake):
    root, entries = tree(make_tree, {"a.py": "ok"})

    outcome = scan(root, entries, workspace, fake(version="9.0.0"))

    assert outcome.execution.version == "9.0.0"
    assert any("8.30.1" in w for w in outcome.execution.warnings)


def test_marker_filter_keeps_real_findings_of_the_same_rule_and_drops_duplicates(
    make_tree, workspace, fake
):
    # A real github-pat finding on the last line (no final newline) must survive; a marker
    # reported twice must not turn into a finding.
    root, entries = tree(make_tree, {"a.env": f"A=1\nT = {CANARY} RULE=github-pat"})

    outcome = scan(root, entries, workspace, fake(double_marker=True))

    assert [(f.rule_id, f.start_line) for f in outcome.findings] == [("gitleaks.github-pat", 2)]
    assert outcome.execution.files_analyzed == 1
    assert any("invalid line number" in w for w in outcome.execution.warnings)
    assert "ghp_" not in everything(outcome)


# ---------------------------------------------------- P9 (RC validation): fingerprint stability

P9_LINES = [
    "a = FAKESECRET RULE=generic-api-key SECONDMATCH",  # two matches of one rule on one line
    "b = FAKESECRET RULE=aws-access-token",
    "c = FAKESECRET RULE=generic-api-key EXACTDUP",  # the very same match reported twice
]


def _p9_scan(make_tree, workspace, fake, lines=P9_LINES, **scenario):
    root, entries = tree(make_tree, {"app.py": chr(10).join(lines) + chr(10)})
    own = workspace / f"run{len(list(workspace.iterdir()))}"  # a fresh workspace per scan
    own.mkdir()
    return scan(root, entries, own, fake(**scenario))


def _ids(outcome):
    return sorted((f.rule_id, f.start_line, f.fingerprint) for f in outcome.findings)


def test_fingerprints_do_not_depend_on_the_order_of_gitleaks_results(make_tree, workspace, fake):
    """P9: Gitleaks' per-file result order is not stable between runs. The fingerprint used an
    index into that order, so the same finding received different ids in different runs."""
    forward = _ids(_p9_scan(make_tree, workspace, fake))
    backward = _ids(_p9_scan(make_tree, workspace, fake, reverse_order=True))

    assert forward == backward
    assert len(forward) == 5 and len({fp for _, _, fp in forward}) == 5  # all distinct


def test_two_matches_on_one_line_are_told_apart_by_their_columns(make_tree, workspace, fake):
    outcome = _p9_scan(make_tree, workspace, fake)

    line1 = sorted((f for f in outcome.findings if f.start_line == 1), key=lambda f: f.start_column)
    assert [(f.start_column, f.end_column) for f in line1] == [(3, 40), (50, 90)]
    assert len({f.fingerprint for f in line1}) == 2
    assert not any("duplicate-match" in f.tags for f in line1)


def test_indistinguishable_duplicates_are_numbered_and_marked_not_guessed(
    make_tree, workspace, fake
):
    outcome = _p9_scan(make_tree, workspace, fake)

    line3 = [f for f in outcome.findings if f.start_line == 3]
    assert len(line3) == 2 and len({f.fingerprint for f in line3}) == 2
    assert all("duplicate-match" in f.tags for f in line3)  # same rule, line and columns
    assert all(f.start_column == 3 for f in line3)


def test_fingerprint_depends_on_location_only_never_on_the_value(make_tree, workspace, fake):
    one = _ids(_p9_scan(make_tree, workspace, fake, lines=["k = FAKESECRET RULE=aws-access-token"]))
    two = _ids(
        _p9_scan(make_tree, workspace, fake, lines=["k = FAKESECRET RULE=aws-access-token x"])
    )

    assert one == two  # same rule, line and columns -> same identity, whatever the text was


def test_counts_rules_lines_and_severities_are_unchanged_by_the_identity_scheme(
    make_tree, workspace, fake
):
    outcome = _p9_scan(make_tree, workspace, fake)

    ordered = sorted(
        outcome.findings, key=lambda f: (f.start_line, f.start_column or 0, f.fingerprint)
    )
    assert [(f.rule_id, f.start_line, f.severity.value) for f in ordered] == [
        ("gitleaks.generic-api-key", 1, "MEDIUM"), ("gitleaks.generic-api-key", 1, "MEDIUM"),
        ("gitleaks.aws-access-token", 2, "HIGH"),
        ("gitleaks.generic-api-key", 3, "MEDIUM"), ("gitleaks.generic-api-key", 3, "MEDIUM"),
    ]  # fmt: skip
