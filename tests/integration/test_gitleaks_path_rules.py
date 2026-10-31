"""Path-conditioned Gitleaks rules on stdin, and small/edge inputs (real Gitleaks; marked).

Oracle: the same fixture scanned by the real binary in ``dir`` mode with the default rules,
where Gitleaks applies its path conditions itself. The adapter (stdin, path condition applied
by the auditor) must report exactly the same (rule, file, line) set. Test code only: the
product never runs ``dir`` mode. All values are random fakes generated at runtime.
"""

import base64
import json
import os
import re
import secrets
import string
import subprocess
import tomllib

import pytest

from auditor.application.audit_service import run_audit
from auditor.core.models import ScanStatus
from auditor.scanners.executables import gitleaks_executable
from auditor.scanners.gitleaks_adapter import CONFIG_DIR, CONFIG_PATH, PATH_RULES, PATHLESS_PREFIX

pytestmark = pytest.mark.gitleaks
ALNUM = string.ascii_letters + string.digits
SAMPLE_ATTEMPTS = 10  # re-draws of the random end-of-file samples (see the EOF test)


def rnd(alphabet, n):
    return "".join(secrets.choice(alphabet) for _ in range(n))


def path_rule_samples():
    b64 = base64.b64encode(rnd(ALNUM, 24).encode()).decode()
    k8s = (
        "apiVersion: v1\nkind: Secret\nmetadata:\n  name: db-credentials\ntype: Opaque\n"
        f"data:\n  password: {b64}\n"
    )
    tf = f'resource "a" "b" {{\n  administrator_login_password = "{rnd("abcdefgh2345", 16)}"\n}}\n'
    nuget = (
        "<configuration>\n  <packageSourceCredentials>\n"
        f'    <add key="ClearTextPassword" value="{rnd(ALNUM, 16)}" />\n'
        "  </packageSourceCredentials>\n</configuration>\n"
    )
    php = f"<?php\n$c = array('secret_key' => 'sk_{rnd(ALNUM, 29)}');\n"
    values = [b64, *re.findall(r'"([a-z0-9]{16})"', tf), *re.findall(r'value="(\w+)"', nuget)]
    values += re.findall(r"'(sk_\w+)'", php)
    # positive (path matches) and negative (same content, path does not match)
    files = {
        "deploy/db-secret.yaml": k8s,
        "deploy/db-secret.yml": k8s.replace("db-credentials", "db2"),
        "notes/db-secret.txt": k8s.replace("db-credentials", "db3"),
        "infra/main.tf": tf,
        "infra/vars.hcl": tf.replace('"a"', '"c"'),
        "infra/main.tf.bak": tf.replace('"a"', '"d"'),
        "NuGet.Config": nuget,
        "nuget.xml": nuget.replace("packageSource", "pkgSource"),
        "web/conf.php": php,
        "web/conf.js": php.replace("$c", "$d"),
        ".github/workflows/ci.yml": "on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n",
    }
    return files, values


def nest(files):
    """{"a/b.txt": content} -> {"a": {"b.txt": content}} for make_tree."""
    spec = {}
    for rel, content in files.items():
        node = spec
        *dirs, name = rel.split("/")
        for part in dirs:
            node = node.setdefault(part, {})
        node[name] = content
    return spec


def oracle_dir_mode(root, tmp_path):
    """(rule, relative path, line) from the real binary in dir mode with the default rules."""
    work = tmp_path / "oracle"
    work.mkdir()
    (work / "empty.ignore").write_text("", encoding="utf-8")
    env = {"SystemRoot": os.environ.get("SystemRoot", ""), "HOME": str(work),
           "USERPROFILE": str(work), "TEMP": str(work), "TMP": str(work)}  # fmt: skip
    completed = subprocess.run(  # noqa: S603 - pinned binary, fixed argv, test fixture only
        [
            str(gitleaks_executable()),
            "dir",
            str(root),
            "--config",
            str(CONFIG_PATH),
            "--gitleaks-ignore-path",
            str(work / "empty.ignore"),
            "--ignore-gitleaks-allow",
            "--redact=100",
            "--no-banner",
            "--exit-code",
            "0",
            "--log-level",
            "error",
            "--report-format",
            "json",
            "--report-path",
            "-",
        ],  # fmt: skip
        cwd=work,
        env=env,
        capture_output=True,
        timeout=120,
        shell=False,
        check=True,
    )
    prefix = str(root).replace("\\", "/").rstrip("/") + "/"
    return {
        (i["RuleID"], i["File"].replace("\\", "/").removeprefix(prefix), i["StartLine"])
        for i in json.loads(completed.stdout)
    }


def adapter_results(report):
    return {
        (f.rule_id.removeprefix("gitleaks."), f.relative_path, f.start_line)
        for f in report.findings
        if f.source_tool == "gitleaks"
    }


def test_path_rules_match_dir_mode_exactly_with_positives_and_negatives(
    make_tree, out_dir, tmp_path
):
    files, values = path_rule_samples()
    root = make_tree(nest(files))
    run = run_audit(root, out_dir)
    ours = adapter_results(run.findings)

    assert ours == oracle_dir_mode(root, tmp_path)
    by_rule = {rule: {p for r, p, _ in ours if r == rule} for rule, _, _ in ours}
    assert by_rule["kubernetes-secret-yaml"] == {"deploy/db-secret.yaml", "deploy/db-secret.yml"}
    assert by_rule["hashicorp-tf-password"] == {"infra/main.tf", "infra/vars.hcl"}
    assert by_rule["nuget-config-password"] == {"NuGet.Config"}
    assert by_rule["freemius-secret-key"] == {"web/conf.php"}
    e = next(x for x in run.findings.tool_executions if x.tool == "gitleaks")
    assert e.coverage_limitations == [] and e.not_analyzed == []
    assert run.findings.status is ScanStatus.COMPLETE  # YAML no longer forces PARTIAL
    texts = [p.read_text("utf-8") for p in out_dir.rglob("*") if p.is_file()]
    assert not any(v in t for v in values for t in texts)  # no value in any report


def test_real_kubernetes_secret_manifest_is_detected(make_tree, out_dir):
    b64 = base64.b64encode(rnd(ALNUM, 30).encode()).decode()
    manifest = (
        "---\napiVersion: v1\nkind: Secret\nmetadata:\n  name: api-token\n  namespace: prod\n"
        f"type: Opaque\ndata:\n  token: {b64}\n"
    )
    root = make_tree({"k8s": {"secret.yaml": manifest}, "app.py": "x = 1\n"})

    run = run_audit(root, out_dir)
    found = {(f.rule_id, f.relative_path) for f in run.findings.findings}

    assert ("gitleaks.kubernetes-secret-yaml", "k8s/secret.yaml") in found
    k8s = next(f for f in run.findings.findings if f.rule_id == "gitleaks.kubernetes-secret-yaml")
    assert "path-rule-applied-by-auditor" in k8s.tags and k8s.start_line == 3


@pytest.mark.parametrize(
    ("name", "build", "line"),
    [
        ("tiny.env", lambda t: t.encode(), 1),  # one line, no trailing newline
        ("lf.env", lambda t: f"A=1\nT={t}\n".encode(), 2),
        ("crlf.env", lambda t: f"A=1\r\nB=2\r\nT={t}\r\n".encode(), 3),
        ("bom.env", lambda t: b"\xef\xbb\xbf" + f"A=1\nT={t}".encode(), 2),
        ("last.env", lambda t: ("x\n" * 50 + f"T={t}").encode(), 51),
    ],
)
def test_small_and_edge_inputs_are_scanned_completely(make_tree, out_dir, name, build, line):
    token = "gh" + "p_" + rnd(ALNUM, 36)
    root = make_tree({name: build(token), "empty.txt": b""})

    run = run_audit(root, out_dir)
    e = next(x for x in run.findings.tool_executions if x.tool == "gitleaks")

    assert adapter_results(run.findings) == {("github-pat", name, line)}
    assert e.files_analyzed == 2 and e.not_analyzed == []  # incl. the empty file
    texts = [p.read_text("utf-8") for p in out_dir.rglob("*") if p.is_file()]
    assert not any(token[4:20] in t for t in texts)


def _embedded_default_config() -> dict:
    raw = gitleaks_executable().read_bytes()
    start = raw.find(b'title = "gitleaks config"')
    return tomllib.loads(raw[start : raw.find(b"\x00", start)].decode("utf-8"))


def test_path_rule_table_matches_the_pinned_binary():
    embedded = {r["id"]: r for r in _embedded_default_config()["rules"]}
    with_path = {rid: r["path"] for rid, r in embedded.items() if "path" in r}

    assert with_path == {p.rule: p.path for p in PATH_RULES}
    for p in PATH_RULES:
        assert (p.config is None) == ("regex" not in embedded[p.rule]), p.rule


def test_path_less_copies_are_verbatim_apart_from_id_and_path():
    embedded = {r["id"]: r for r in _embedded_default_config()["rules"]}
    for p in PATH_RULES:
        if p.config is None:
            continue
        config = tomllib.loads((CONFIG_DIR / p.config).read_text("utf-8"))
        (copy,) = config["rules"]
        original = {k: v for k, v in embedded[p.rule].items() if k != "path"}
        assert copy["id"] == PATHLESS_PREFIX + p.rule
        assert {k: v for k, v in copy.items() if k != "id"} == {
            k: v for k, v in original.items() if k != "id"
        }
        assert config["extend"] == {"useDefault": True}
        assert "allowlist" not in config and "allowlists" not in config  # no global allowlist


def test_self_check_proves_the_real_engine_and_rules_are_active(make_tree, out_dir, tmp_path):
    import hashlib

    from auditor.scanners.gitleaks_adapter import (
        CONFIG_HASHES,
        GitleaksAdapter,
        GitleaksOptions,
    )

    root = make_tree({"a.py": "x = 1\n"})
    good = run_audit(root, out_dir / "good", scanners=[GitleaksAdapter()])
    # A rule set that detects nothing (but whose hash is pinned for this test): the self-check
    # must refuse to trust any scan with it.
    broken = tmp_path / "broken"
    broken.mkdir()
    hashes = {}
    for name in CONFIG_HASHES:
        data = (CONFIG_DIR / name).read_bytes().replace(b"useDefault = true", b"useDefault = false")
        (broken / name).write_bytes(data)
        hashes[name] = hashlib.sha256(data).hexdigest()
    bad = run_audit(
        root,
        out_dir / "bad",
        scanners=[GitleaksAdapter(GitleaksOptions(config_dir=broken, config_hashes=hashes))],
    )

    (ok,) = good.findings.tool_executions
    (refused,) = bad.findings.tool_executions
    assert ok.status.value == "SUCCESS" and ok.files_analyzed == 1
    assert refused.status.value == "ERROR" and "self-check failed" in refused.reason
    assert refused.files_analyzed == 0


def end_of_file_samples():
    """Secrets of several rule types as the very last bytes of a file (no final newline)."""
    pem_body = "\n".join(rnd(ALNUM + "+/", 64) for _ in range(10))
    begin, end = "-----" + "BEGIN RSA PRIVATE KEY-----", "-----" + "END RSA PRIVATE KEY-----"
    b64 = base64.b64encode(rnd(ALNUM, 24).encode()).decode()
    return {
        "aws.txt": "x = 1\nK = " + "AK" + "IA" + rnd("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16),
        "gh.txt": "token: " + "gh" + "p_" + rnd(ALNUM, 36),
        "slack.txt": "s="
        + "xo"
        + "xb-"
        + rnd(string.digits, 12)
        + "-"
        + rnd(string.digits, 12)
        + "-"
        + rnd(ALNUM, 24),
        "generic.cfg": 'a = 1\napi_key = "' + rnd(ALNUM, 32) + '"',
        "generic_bare.cfg": "api_key=" + rnd(ALNUM, 32),  # value ends exactly at EOF
        "jwt.js": "t='"
        + base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
        + "."
        + base64.urlsafe_b64encode(json.dumps({"sub": rnd(ALNUM, 12)}).encode())
        .decode()
        .rstrip("=")
        + "."
        + rnd(ALNUM + "-_", 43)
        + "'",
        "key.pem": f"{begin}\n{pem_body}\n{end}",  # multi-line, END line is the last byte
        "secret.yaml": f"apiVersion: v1\nkind: Secret\ndata:\n  password: {b64}",
        "main.tf": 'password = "' + rnd("abcdefgh2345", 16) + '"',
        "nuget.config": '<add key="ClearTextPassword" value="' + rnd(ALNUM, 16) + '" />',
        "c.php": "$c = array('secret_key' => 'sk_" + rnd(ALNUM, 29) + "');",
    }


@pytest.mark.parametrize("final_newline", [False, True])
def test_end_marker_does_not_change_end_of_file_matches(
    make_tree, out_dir, tmp_path, final_newline
):
    """Appending the gap and the marker must not add, lose or move any finding at EOF.

    Gitleaks itself does not report about 1% of random generic values (measured; a known
    false-negative limitation). So each sample set is first checked with the real binary in
    dir mode; only a set it fully reports is used, at most SAMPLE_ATTEMPTS tries, else FAIL.
    """
    for attempt in range(SAMPLE_ATTEMPTS):
        files = end_of_file_samples()
        if final_newline:
            files = {name: text + "\n" for name, text in files.items()}
        root = make_tree({n: t.encode() for n, t in files.items()}, name=f"target{attempt}")
        (tmp_path / f"o{attempt}").mkdir()
        oracle = oracle_dir_mode(root, tmp_path / f"o{attempt}")
        if {path for _, path, _ in oracle} >= set(files) - {"generic_bare.cfg"}:
            break
    else:
        pytest.fail(f"no sample set fully reported by real Gitleaks in {SAMPLE_ATTEMPTS} tries")

    run = run_audit(root, out_dir)
    ours = adapter_results(run.findings)

    assert ours == oracle
    assert {path for _, path, _ in oracle} >= set(files) - {"generic_bare.cfg"}  # real coverage
    e = next(x for x in run.findings.tool_executions if x.tool == "gitleaks")
    assert e.files_analyzed == len(files) and e.not_analyzed == []


def test_end_marker_never_leaks_and_never_removes_real_findings(
    make_tree, out_dir, tmp_path, monkeypatch
):
    import auditor.scanners.gitleaks_adapter as adapter_module

    marker = ("gh" + "p_" + rnd(ALNUM, 36)).encode()
    monkeypatch.setattr(adapter_module, "end_marker", lambda: marker)
    real = "gh" + "p_" + rnd(ALNUM, 36)
    # the real token is the last line of its file, right before where the marker goes
    root = make_tree({"last.env": f"A=1\nT={real}", "other.env": f"T={real}\n", "a.py": "1\n"})

    run = run_audit(root, out_dir)
    found = adapter_results(run.findings)

    assert found == {("github-pat", "last.env", 2), ("github-pat", "other.env", 1)}
    e = next(x for x in run.findings.tool_executions if x.tool == "gitleaks")
    assert e.files_analyzed == 3 and e.warnings == []
    texts = [p.read_bytes().decode("utf-8", "replace") for p in out_dir.rglob("*") if p.is_file()]
    texts += [f.model_dump_json() for f in run.findings.findings]
    texts += [e.model_dump_json()]
    temp = tmp_path / "appdata" / "ai-code-auditor" / "tmp"
    texts += [p.read_bytes().decode("utf-8", "replace") for p in temp.rglob("*") if p.is_file()]
    core = marker.decode()[4:]
    for text in texts:
        assert not any(core[i : i + 8] in text for i in range(len(core) - 7))
