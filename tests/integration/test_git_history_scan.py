"""Git history secret scan, end to end with the real git and the real Gitleaks (Stage 4b).

Fixture repositories are built by the tests (fake secrets generated at runtime). The scan
never runs git on them: it copies objects and refs into a private repository, extracts every
reachable blob and commit message and scans them with ``gitleaks dir`` (D-047).
"""

import base64
import hashlib
import json
import os
import secrets
import string
import sys
import zipfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

import auditor.scanners.git_history as git_history
from auditor.application.audit_service import run_audit
from auditor.cli import app
from auditor.core.models import NotAnalyzedReason, ScanStatus, ToolStatus
from auditor.scanners.git_history_adapter import TOOL, GitHistoryAdapter, GitHistoryOptions

pytestmark = [pytest.mark.gitleaks, pytest.mark.git_history]
ALNUM = string.ascii_letters + string.digits
runner = CliRunner()


def token() -> str:
    return "gh" + "p_" + "".join(secrets.choice(ALNUM) for _ in range(36))


def scan(root, out_dir, **options):
    run = run_audit(root, out_dir, scanners=[GitHistoryAdapter(GitHistoryOptions(**options))])
    (execution,) = run.findings.tool_executions
    return run, execution


def outputs(out_dir, run) -> str:
    texts = [p.read_text("utf-8", "replace") for p in Path(out_dir).rglob("*") if p.is_file()]
    return "\n".join([*texts, run.findings.model_dump_json()])


def digest(path: Path) -> str:
    h = hashlib.sha256()
    for dirpath, dirnames, filenames in os.walk(path):
        dirnames.sort()
        for name in sorted(filenames):
            p = Path(dirpath, name)
            h.update(str(p.relative_to(path)).encode() + p.read_bytes())
    return h.hexdigest()


def oracle_dir(files: dict[str, bytes], work: Path) -> set[tuple[str, str, int]]:
    """(path, rule, line) from the real binary in dir mode on the raw files (no marker)."""
    import subprocess

    from auditor.scanners.executables import gitleaks_executable
    from auditor.scanners.gitleaks_adapter import CONFIG_PATH

    target = work / "files"
    target.mkdir(parents=True)
    for name, data in files.items():
        (target / name).write_bytes(data)
    (work / "empty.ignore").write_text("", encoding="utf-8")
    done = subprocess.run(  # noqa: S603 - pinned binary, fixed argv, test oracle only
        [str(gitleaks_executable()), "dir", str(target), "--config", str(CONFIG_PATH),
         "--gitleaks-ignore-path", str(work / "empty.ignore"), "--ignore-gitleaks-allow",
         "--redact=100", "--no-banner", "--exit-code", "0", "--log-level", "error",
         "--report-format", "json", "--report-path", "-"],
        cwd=work, env={"SystemRoot": os.environ.get("SystemRoot", ""), "HOME": str(work),
                       "USERPROFILE": str(work), "TEMP": str(work), "TMP": str(work)},
        capture_output=True, timeout=120, check=True,
    )  # fmt: skip
    return {(Path(i["File"]).name, i["RuleID"], i["StartLine"]) for i in json.loads(done.stdout)}


# ----------------------------------------------------------------- basic, privacy, isolation


def test_a_removed_secret_is_found_with_verified_commit_path_and_line(git_builder, out_dir):
    r = git_builder()
    value = token()
    r.write("app/config.py", f"DEBUG = True\nTOKEN = '{value}'\n")
    added = r.commit("add config")
    r.write("app/config.py", "DEBUG = True\nTOKEN = os.environ['TOKEN']\n")
    r.commit("move the token out")
    before = digest(r.path / ".git")

    run, e = scan(r.path, out_dir)

    assert e.status is ToolStatus.SUCCESS, e.reason
    (finding,) = run.findings.findings
    assert (finding.source_tool, finding.rule_id) == (TOOL, "gitleaks.github-pat")
    assert (finding.relative_path, finding.start_line) == ("app/config.py", 2)
    assert "git-history" in finding.tags and "still-in-working-tree" not in finding.tags
    assert any(added[:12] in ev.reference for ev in finding.evidence)
    assert run.findings.status is ScanStatus.COMPLETE
    blob = r.git("rev-parse", f"{added}:app/config.py")
    ids = finding.identifiers  # Stage 6 (R2): the history object and its verified paths
    assert (ids.git_object, ids.object_format) == (blob, "sha1")
    assert ids.history_paths == ["app/config.py"]
    text = outputs(out_dir, run)
    assert value not in text and value[4:20] not in text
    for personal in ("Fixture Person", "fixture@example.invalid", "add config"):
        assert personal not in text  # no author, e-mail or commit message text
    assert digest(r.path / ".git") == before  # the target's .git is untouched


def test_git_never_runs_without_a_repository_and_the_scan_is_not_partial(make_tree, out_dir):
    root = make_tree({"a.py": "x = 1\n"})

    run, e = scan(root, out_dir)

    assert e.status is ToolStatus.SKIPPED and "no .git" in e.reason
    assert run.findings.status is ScanStatus.COMPLETE


def test_hostile_repository_config_never_executes(git_builder, out_dir, tmp_path):
    r = git_builder()
    values = {name: token() for name in ("conv", "plain", "inc")}
    r.write(".gitattributes", "*.txt diff=evil\n*.md diff=evil2\n*.cfg -diff\n*.bin binary\n")
    r.write("conv.txt", f"k = {values['conv']}\n")
    r.write("plain.py", f"k = '{values['plain']}'\n")
    r.write("inc.md", f"k {values['inc']}\n")
    r.commit("c1")
    markers = tmp_path / "markers"
    script = tmp_path / "mark.py"
    script.write_text(
        "import sys, pathlib\np = pathlib.Path(sys.argv[1]); p.mkdir(exist_ok=True)\n"
        "(p / (sys.argv[2] + '.txt')).write_text('ran')\n"
        "if len(sys.argv) > 3: sys.stdout.write(open(sys.argv[-1]).read())\n",
        encoding="utf-8",
    )

    def cmd(tag):
        return f"{Path(sys.executable).as_posix()} {script.as_posix()} {markers.as_posix()} {tag}"

    outside = tmp_path / "outside.gitconfig"
    outside.write_text(f'[diff "evil2"]\n\ttextconv = {cmd("include")}\n', encoding="utf-8")
    hooks = r.path / ".git" / "evilhooks"
    hooks.mkdir()
    for hook in ("post-checkout", "reference-transaction", "post-index-change"):
        (hooks / hook).write_text(f"#!/bin/sh\n{cmd(hook)}\n", encoding="utf-8")
    with open(r.path / ".git" / "config", "a", encoding="utf-8") as config:
        config.write(
            f'[diff "evil"]\n\ttextconv = {cmd("textconv")}\n[diff]\n\texternal = {cmd("ext")}\n'
            f"[core]\n\tpager = {cmd('pager')}\n\tfsmonitor = {cmd('fsmonitor')}\n"
            f"\thooksPath = {hooks.as_posix()}\n[log]\n\tshowSignature = true\n"
            f"[gpg]\n\tprogram = {cmd('gpg')}\n[include]\n\tpath = {outside.as_posix()}\n"
        )
    r.git("log", "-p", "--all")  # positive control: the hostile config is live on the target
    assert {p.stem for p in markers.glob("*.txt")} >= {"textconv", "include"}
    for p in markers.glob("*.txt"):
        p.unlink()

    run, e = scan(r.path, out_dir)

    assert list(markers.glob("*.txt")) == []  # nothing ran during the audit
    assert sorted(f.relative_path for f in run.findings.findings) == ["conv.txt", "inc.md",
                                                                      "plain.py"]  # fmt: skip
    assert any("includes other files" in w for w in e.warnings)


def test_attributes_and_gitleaks_path_allowlist_cannot_hide_history(git_builder, out_dir):
    r = git_builder()
    r.write(".gitattributes", "*.cfg -diff\n*.bin binary\n")
    names = ["a.cfg", "b.bin", "x.png", "yarn.lock", "node_modules/m.js", "Pipfile.lock"]
    for name in names:
        r.write(name, f"k = {token()}\n")
    r.commit("c1")
    for name in names:
        r.git("rm", "-q", name)
    r.commit("remove all")

    run, e = scan(r.path, out_dir)

    assert sorted(f.relative_path for f in run.findings.findings) == sorted(names)


def test_merge_only_content_is_found_once(git_builder, out_dir):
    r = git_builder()
    r.write("base.txt", "line = original\n")
    r.commit("c0")
    r.git("checkout", "-q", "-b", "side")
    r.write("base.txt", "line = side\n")
    r.write("side.txt", f"k = {token()}\n")
    r.commit("side")
    r.git("checkout", "-q", "main")
    r.write("base.txt", "line = main\n")
    r.commit("main")
    r.git("merge", "-q", "side", check=False)  # conflict
    r.write("base.txt", f"line = {token()}\n")  # the resolution introduces a secret
    r.write("evil.txt", f"k = {token()}\n")  # and so does an evil merge
    r.git("add", "-A")
    r.git("commit", "-q", "-m", "merge")
    merge = r.git("rev-parse", "HEAD")

    run, _ = scan(r.path, out_dir)
    by_path = {f.relative_path: f for f in run.findings.findings}

    assert sorted(by_path) == ["base.txt", "evil.txt", "side.txt"]  # one finding each
    for path in ("base.txt", "evil.txt"):
        assert any(merge[:12] in ev.reference for ev in by_path[path].evidence)


def test_commit_messages_are_scanned_and_reported_separately(git_builder, out_dir):
    r = git_builder()
    value = token()
    r.write("readme.txt", "nothing\n")
    r.git("add", "-A")
    r.git("commit", "-q", "-m", f"deploy\n\nused {value} for the release")
    commit = r.git("rev-parse", "HEAD")

    run, e = scan(r.path, out_dir)

    (finding,) = run.findings.findings
    assert "commit-message" in finding.tags and finding.relative_path == "(commit message)"
    assert finding.start_line == 3
    assert any(commit[:12] in ev.reference for ev in finding.evidence)
    text = outputs(out_dir, run)
    assert value not in text and "for the release" not in text


def test_replace_refs_cannot_hide_a_commit(git_builder, out_dir):
    r = git_builder()
    r.write("base.txt", "base\n")
    r.commit("c0")
    r.write("leak.txt", f"k = {token()}\n")
    bad = r.commit("c1")
    clean = r.git("commit-tree", r.git("rev-parse", "HEAD~1^{tree}"), "-p", "HEAD~1", "-m", "c1")
    r.git("replace", bad, clean)
    assert r.git("show", "--name-only", "--format=", bad) == ""  # git itself is fooled

    run, e = scan(r.path, out_dir)

    assert [f.relative_path for f in run.findings.findings] == ["leak.txt"]
    assert any("replace refs" in w.lower() for w in e.warnings)


# --------------------------------------------------------------------------- refusals


def _refuse(git_builder, kind, tmp_path):
    r = git_builder()
    r.write("a.txt", "x\n")
    r.commit("c1")
    gitdir = r.path / ".git"
    if kind == "alternates_unc":
        (gitdir / "objects/info/alternates").write_text("\\\\192.0.2.10\\share\\objects\n")
    elif kind == "alternates_outside":
        (gitdir / "objects/info/alternates").write_text((tmp_path / "x").as_posix() + "\n")
    elif kind == "partial_clone":
        (gitdir / "objects/pack/pack-1.promisor").write_bytes(b"")
    elif kind == "reftable":
        (gitdir / "reftable").mkdir()
    elif kind == "unknown_extension":
        with open(gitdir / "config", "a", encoding="utf-8") as config:
            config.write("[extensions]\n\tworktreeConfig = true\n")
    elif kind == "junction":
        import _winapi

        outside = tmp_path / "outside"
        outside.mkdir()
        _winapi.CreateJunction(str(outside), str(gitdir / "objects" / "evil"))
    elif kind == "gitfile":
        import shutil

        shutil.move(str(gitdir), str(tmp_path / "moved.git"))
        (r.path / ".git").write_text(f"gitdir: {(tmp_path / 'moved.git').as_posix()}\n")
    return r


@pytest.mark.parametrize(
    ("kind", "text"),
    [
        ("alternates_unc", "alternates"),
        ("alternates_outside", "alternates"),
        ("partial_clone", "partial clone"),
        ("reftable", "reftable"),
        ("unknown_extension", "unknown repository format"),
        pytest.param("junction", "link or junction", marks=pytest.mark.skipif(
            sys.platform != "win32", reason="NTFS junctions are Windows-only")),
        ("gitfile", "gitdir redirect"),
    ],
)  # fmt: skip
def test_unsafe_repositories_are_refused_before_git_starts(
    git_builder, out_dir, tmp_path, monkeypatch, kind, text
):
    r = _refuse(git_builder, kind, tmp_path)

    def no_git(*args, **kwargs):
        raise AssertionError("git must not be started")

    monkeypatch.setattr(git_history.GitRunner, "stream", no_git)
    run, e = scan(r.path, out_dir)

    assert e.status is ToolStatus.SKIPPED and text in e.reason
    (missing,) = e.not_analyzed
    assert missing.reason is NotAnalyzedReason.UNSAFE_REPOSITORY
    assert run.findings.status is ScanStatus.PARTIAL


# ------------------------------------------------------------- path rules, sentinel, limits


def test_path_conditioned_rules_use_verified_paths_only(git_builder, out_dir):
    r = git_builder()
    value = base64.b64encode("".join(secrets.choice(ALNUM) for _ in range(24)).encode()).decode()
    secret_yaml = f"apiVersion: v1\nkind: Secret\ntype: Opaque\ndata:\n  password: {value}\n"
    r.write("k8s/secret.yaml", secret_yaml)
    r.commit("c1")
    lone = r.git("hash-object", "-w", "--stdin", stdin=f"k = {token()}\n".encode())
    r.git("tag", "lone", lone)

    run, e = scan(r.path, out_dir)

    rules = {(f.relative_path, f.rule_id) for f in run.findings.findings}
    assert ("k8s/secret.yaml", "gitleaks.kubernetes-secret-yaml") in rules
    tagged = [f for f in run.findings.findings if "attribution-unavailable" in f.tags]
    assert len(tagged) == 1 and tagged[0].relative_path == "(git history)"
    assert any("path unknown" in (i.detail or "") for i in e.coverage_limitations)
    assert run.findings.status is ScanStatus.PARTIAL  # path rules not complete for that blob


def _per_path(findings) -> dict[str, set[tuple[str, int]]]:
    """{path: {(rule, line)}} from the introduction evidence of history findings."""
    out: dict[str, set[tuple[str, int]]] = {}
    for f in findings:
        for ev in f.evidence:
            location = ev.reference.split(" ", 2)[2]  # "<commit> <date> <path>:<line>"
            path = location.rsplit(":", 1)[0]
            out.setdefault(path, set()).add((f.rule_id.removeprefix("gitleaks."), f.start_line))
    return out


def test_one_blob_under_a_yaml_and_a_txt_path_gets_each_paths_rules(git_builder, out_dir, tmp_path):
    """The path rule applies to the .yaml path only; the .txt path keeps the base rules."""
    r = git_builder()
    value = base64.b64encode("".join(secrets.choice(ALNUM) for _ in range(24)).encode()).decode()
    content = (f"apiVersion: v1\nkind: Secret\ntype: Opaque\ndata:\n  password: {value}\n"
               f"other: {token()}\n")  # fmt: skip
    r.write("deploy/secret.yaml", content)
    r.write("notes/secret.txt", content)
    r.commit("c1")

    run, e = scan(r.path, out_dir)
    ours = _per_path(run.findings.findings)
    oracle: dict[str, set[tuple[str, int]]] = {}
    for name, rule, line in oracle_dir(
        {"secret.yaml": content.encode(), "secret.txt": content.encode()}, tmp_path / "oracle"
    ):
        path = "deploy/secret.yaml" if name == "secret.yaml" else "notes/secret.txt"
        oracle.setdefault(path, set()).add((rule, line))

    assert any(r == "kubernetes-secret-yaml" for r, _ in oracle["deploy/secret.yaml"])  # control
    assert ours == oracle  # per path exactly what Gitleaks itself reports for that file
    k8s = [f for f in run.findings.findings if f.rule_id == "gitleaks.kubernetes-secret-yaml"]
    assert [f.relative_path for f in k8s] == ["deploy/secret.yaml"]


def test_root_commit_attribution_and_object_counts_reconcile(git_builder, out_dir):
    r = git_builder()
    r.write("root.py", f"k = '{token()}'\n")
    root = r.commit("root")
    r.write("big.txt", "x" * 3000 + "\n")
    r.write("later.txt", "nothing\n")
    r.commit("c2")

    run, e = scan(r.path, out_dir, max_blob_bytes=2000)

    (finding,) = run.findings.findings
    assert finding.relative_path == "root.py"
    assert [ev.reference.split()[0] for ev in finding.evidence] == [root[:12]]
    reachable, scanned = int(e.settings["blobs_reachable"]), int(e.settings["blobs_scanned"])
    blob_gaps = [n for n in e.not_analyzed if not n.relative_path.startswith("(commit message)")]
    assert reachable == 3 and scanned == 2 and len(blob_gaps) == 1  # 3 = 2 + 1
    assert int(e.settings["commit_messages_scanned"]) == int(e.settings["commits"]) == 2
    assert run.findings.status is ScanStatus.PARTIAL


def test_an_object_that_silently_goes_missing_is_a_coverage_error(
    git_builder, out_dir, monkeypatch
):
    import auditor.scanners.git_history_adapter as adapter_module

    r = git_builder()
    r.write("a.txt", "a\n")
    r.write("b.txt", "b\n")
    r.commit("c1")
    original = adapter_module.read_objects

    def drop_first_blob(runner, shas, on_object):
        shas = list(shas)
        dropped = shas[1:] if shas and len(shas[0]) == 40 and len(shas) == 2 else shas
        return original(runner, dropped, on_object)

    monkeypatch.setattr(adapter_module, "read_objects", drop_first_blob)
    run, e = scan(r.path, out_dir)

    assert int(e.settings["blobs_reachable"]) == 2 and int(e.settings["blobs_scanned"]) == 1
    assert any("not extracted" in (n.detail or "") for n in e.not_analyzed)
    assert run.findings.status is ScanStatus.PARTIAL


def test_a_corrupt_object_store_is_an_error_never_clean(git_builder, out_dir):
    r = git_builder()
    r.write("a.py", f"k = '{token()}'\n")
    r.commit("c1")
    loose = [p for p in (r.path / ".git" / "objects").rglob("*")
             if p.is_file() and len(p.parent.name) == 2]  # fmt: skip
    for p in loose:
        os.chmod(p, 0o644)  # git stores objects read-only
        p.write_bytes(b"corrupt")  # the fixture's own objects

    run, e = scan(r.path, out_dir)

    assert e.status is ToolStatus.ERROR and run.findings.findings == []
    assert run.findings.status is ScanStatus.PARTIAL


def test_end_marker_does_not_change_matches_and_archives_are_not_called_scanned(
    git_builder, out_dir, tmp_path
):
    r = git_builder()
    samples = {
        "gh.txt": "token: " + token(),  # value is the last byte of the file
        "generic.cfg": 'a = 1\napi_key = "' + "".join(secrets.choice(ALNUM) for _ in range(32))
        + '"',
        "pem.key": "-----" + "BEGIN RSA PRIVATE KEY-----\n" + "\n".join(
            "".join(secrets.choice(ALNUM) for _ in range(64)) for _ in range(8))
        + "\n-----" + "END RSA PRIVATE KEY-----",
    }  # fmt: skip
    for name, text in samples.items():
        r.write(name, text)
    archive = tmp_path / "bundle.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("inner.txt", f"k = {token()}\n")
    r.write("bundle.zip", archive.read_bytes())
    r.commit("c1")

    run, e = scan(r.path, out_dir)
    ours = {(f.relative_path, f.rule_id.removeprefix("gitleaks."), f.start_line)
            for f in run.findings.findings}  # fmt: skip

    oracle = oracle_dir({n: (r.path / n).read_bytes() for n in samples}, tmp_path / "oracle")
    assert ours == oracle and {p for p, _, _ in oracle} == set(samples)
    zipped = [n for n in e.not_analyzed if "bundle.zip" in n.relative_path]
    assert zipped and zipped[0].reason is NotAnalyzedReason.SKIPPED_BY_TOOL
    assert run.findings.status is ScanStatus.PARTIAL


def test_limits_are_reported_never_complete(git_builder, out_dir):
    r = git_builder()
    r.write("big.txt", "x" * 5000 + f"\nk = {token()}\n")
    r.write("small.txt", f"k = {token()}\n")
    r.commit("c1")

    run, e = scan(r.path, out_dir, max_blob_bytes=1000)
    assert [f.relative_path for f in run.findings.findings] == ["small.txt"]
    assert [n.reason for n in e.not_analyzed] == [NotAnalyzedReason.SIZE_LIMIT]
    assert run.findings.status is ScanStatus.PARTIAL

    run, e = scan(r.path, out_dir, max_git_dir_bytes=10)
    assert e.status is ToolStatus.SKIPPED and "larger than the copy limit" in e.reason
    assert run.findings.status is ScanStatus.PARTIAL

    run, e = scan(r.path, out_dir, max_extract_bytes=100)
    assert any(n.reason is NotAnalyzedReason.SIZE_LIMIT for n in e.not_analyzed)
    assert run.findings.status is ScanStatus.PARTIAL

    run, e = scan(r.path, out_dir, total_timeout=0.001)
    assert e.status is ToolStatus.TIMED_OUT and run.findings.status is ScanStatus.PARTIAL


# ----------------------------------------------------------------- working tree relation


def test_still_in_working_tree_only_for_the_identical_blob_at_the_same_path(git_builder, out_dir):
    r = git_builder()
    same, changed, moved = token(), token(), token()
    r.write("same.py", f"k = '{same}'\n")
    r.write("changed.py", f"k = '{changed}'\n")
    r.write("old_name.py", f"k = '{moved}'\n")
    r.commit("c1")
    r.write("changed.py", f"k = '{changed}'\n# edited\n")  # same secret, different blob
    (r.path / "old_name.py").rename(r.path / "new_name.py")  # same blob, different path
    # (not committed: the working tree differs from history)

    run, _ = scan(r.path, out_dir)
    tags = {f.relative_path: f.tags for f in run.findings.findings}

    assert "still-in-working-tree" in tags["same.py"]
    assert "still-in-working-tree" not in tags["changed.py"]
    assert "still-in-working-tree" not in tags["old_name.py"]
    assert not any("removed-from-tree" in t for t in tags.values())


# ------------------------------------------------------------------------- CLI and default


def test_history_is_off_by_default_and_on_only_with_the_flag(git_builder, out_dir, monkeypatch):
    r = git_builder()
    r.write("a.py", f"k = '{token()}'\n")
    r.commit("c1")
    r.git("rm", "-q", "a.py")
    r.commit("c2")

    def no_git(*args, **kwargs):
        raise AssertionError("git must not run without --scan-git-history")

    with monkeypatch.context() as patched:
        patched.setattr(git_history.GitRunner, "stream", no_git)
        off = runner.invoke(app, ["scan", str(r.path), "--output-dir", str(out_dir / "off")])
    assert "git history NOT_SCANNED" in off.output
    assert "Gitleaks-history" not in off.output

    on = runner.invoke(
        app, ["scan", str(r.path), "--output-dir", str(out_dir / "on"), "--scan-git-history"]
    )
    report = json.loads(next((out_dir / "on").glob("*/findings.json")).read_text("utf-8"))
    history = [f for f in report["findings"] if f["source_tool"] == TOOL]
    assert len(history) == 1 and history[0]["relative_path"] == "a.py"
    assert "Gitleaks-history: SUCCESS" in on.output
    assert "git history: see Gitleaks-history" in on.output
    markdown = next((out_dir / "on").glob("*/report.md")).read_text("utf-8")
    assert "Git history: scanned by the separate gitleaks-history scan" in markdown
    assert "git history limitation: Scope" in markdown
    off_md = next((out_dir / "off").glob("*/report.md")).read_text("utf-8")
    assert "Git history: **NOT_SCANNED**" in off_md and "--scan-git-history" in off_md


# ------------------------------------------------- hostile paths, target gitleaks files, sha256


def test_control_characters_and_dangerous_paths_in_trees_are_only_displayed(git_builder, out_dir):
    r = git_builder()
    r.write("ok.txt", "x\n")
    r.commit("c0")
    blob = r.git("hash-object", "-w", "--stdin", stdin=f"k = {token()}\n".encode())
    hostile = "evil\x1b[31m‮.txt"  # ANSI escape + right-to-left override
    sub = r.git("mktree", stdin=f"100644 blob {blob}\t..\x01name.txt\n".encode())
    tree = r.git("mktree", "--missing", stdin=(
        f"100644 blob {blob}\t{hostile}\n040000 tree {sub}\tdots\n").encode())  # fmt: skip
    commit = r.git("commit-tree", tree, "-p", "HEAD", "-m", "crafted")
    r.git("update-ref", "refs/heads/crafted", commit)

    run, e = scan(r.path, out_dir)

    paths = {f.relative_path for f in run.findings.findings}
    assert len(run.findings.findings) == 1  # one blob, two paths: one finding
    (finding,) = run.findings.findings
    assert "multiple-introductions" in finding.tags
    for text in [*paths, *(ev.reference for ev in finding.evidence)]:
        assert not any(ord(c) < 32 or 0x202A <= ord(c) <= 0x202E for c in text)
    assert not (out_dir / "dots").exists() and not list(Path(r.path).glob("evil*"))


def test_target_gitleaks_files_and_inline_allows_in_history_have_no_effect(git_builder, out_dir):
    r = git_builder()
    value = token()
    r.write(".gitleaks.toml", "[allowlist]\npaths = ['''.*''']\nregexes = ['''.*''']\n")
    r.write(".gitleaksignore", "*\n")
    r.write("app.py", f"k = '{value}'  # gitleaks:allow\n")
    r.commit("try to silence the scanner")

    run, e = scan(r.path, out_dir)

    assert [f.relative_path for f in run.findings.findings] == ["app.py"]


def test_sha256_repositories_are_supported(git_builder, out_dir):
    sha = git_builder("sha256-repo", init_args=("--object-format=sha256",))
    sha.write("k.py", f"k = '{token()}'\n")
    sha.commit("c1")

    run, e = scan(sha.path, out_dir)

    assert e.status is ToolStatus.SUCCESS
    (finding,) = run.findings.findings
    assert finding.relative_path == "k.py" and "still-in-working-tree" in finding.tags


def test_packed_repositories_work_beyond_max_path(git_builder, out_dir, tmp_path):
    """Measured: git for Windows cannot open a pack beyond 260 characters by default."""
    r = git_builder()
    r.write("a.py", f"k = '{token()}'\n")
    r.commit("c1")
    r.git("gc", "-q")
    assert list((r.path / ".git" / "objects" / "pack").glob("*.pack"))
    deep = tmp_path / ("d" * 50) / ("e" * 40)  # workspace < 260, pack and objects > 260

    run = run_audit(r.path, out_dir, scanners=[GitHistoryAdapter()], temp_base=deep)
    (e,) = run.findings.tool_executions

    assert e.status is ToolStatus.SUCCESS, e.reason
    assert [f.relative_path for f in run.findings.findings] == ["a.py"]


# ------------------------------------------------------------------------ cleanup (D-042)


def test_the_private_copy_is_removed_after_success_and_after_failure(
    git_builder, out_dir, tmp_path, monkeypatch
):
    r = git_builder()
    r.write("a.py", f"k = '{token()}'\n")
    r.commit("c1")
    temp_base = tmp_path / "appdata" / "ai-code-auditor" / "tmp"

    scan(r.path, out_dir)
    assert list(temp_base.iterdir()) == []

    def broken(*args, **kwargs):
        raise git_history.GitError("exit code 128", "cat-file")

    import auditor.scanners.git_history_adapter as adapter_module

    monkeypatch.setattr(adapter_module, "read_objects", broken)
    run, e = scan(r.path, out_dir)
    assert e.status is ToolStatus.ERROR and run.findings.status is ScanStatus.PARTIAL
    assert run.findings.findings == [] and list(temp_base.iterdir()) == []


@pytest.mark.skipif(sys.platform != "win32", reason="an open handle blocks deletion on Windows")
def test_a_copy_that_cannot_be_removed_is_a_security_error(git_builder, out_dir, tmp_path):
    from auditor.core.models import IncompleteReason, OperationalErrorCode
    from auditor.scanners.workspace import remove_owned_workspace

    r = git_builder()
    r.write("a.py", f"k = '{token()}'\n")
    r.commit("c1")
    held = []

    class Holding(GitHistoryAdapter):
        def scan(self, context):
            outcome = super().scan(context)
            pack = next(
                p for p in (context.workspace / "copy" / "objects").rglob("*") if p.is_file()
            )
            held.append((open(pack, "rb"), context.workspace.parent))  # noqa: SIM115
            return outcome

    run = run_audit(r.path, out_dir, scanners=[Holding()])
    handle, workspace = held[0]
    handle.close()

    assert IncompleteReason.CLEANUP_FAILED in run.findings.incomplete_reasons
    (error,) = run.findings.operational_errors
    assert error.code is OperationalErrorCode.CLEANUP_FAILED
    assert run.findings.status is ScanStatus.PARTIAL and len(run.findings.findings) == 1
    assert remove_owned_workspace(workspace) is None  # removed by hand afterwards


def test_sqlite_blob_in_history_is_skipped_by_tool_with_the_format_named(
    git_builder, out_dir, tmp_path
):
    """H2 (pilot 01 P5): history objects with a SQLite header were labelled TOOL_ERROR."""
    import sqlite3

    db = tmp_path / "users.sqlite"
    con = sqlite3.connect(db)
    con.execute("create table t (v text)")
    con.execute("insert into t values (?)", (f"k = {token()}",))
    con.commit()
    con.close()
    r = git_builder()
    r.write("users.sqlite", db.read_bytes())
    r.write("ok.txt", "nothing here\n")
    r.commit("c1")

    run, e = scan(r.path, out_dir)

    (item,) = [n for n in e.not_analyzed if "users.sqlite" in n.relative_path]
    assert item.reason is NotAnalyzedReason.SKIPPED_BY_TOOL
    assert "SQLite" in item.detail
    assert run.findings.status is ScanStatus.PARTIAL
