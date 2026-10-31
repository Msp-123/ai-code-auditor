"""Isolation contract of the git history scan (Stage 4b, D-047): what reaches git, what is
copied, what is parsed. git never runs on the target; the private copy is the only repo."""

import json
import time

import pytest

from auditor.scanners.git_history import (
    HARDENING,
    GitError,
    GitRefused,
    GitRunner,
    _BatchReader,
    _config_flags,
    _without_replace_refs,
    copy_git_history,
    find_git,
    hardened_git_env,
    inspect_git_dir,
    parse_commit,
    parse_git_version,
    split_records,
)
from auditor.scanners.git_history_adapter import _parse, classify_path, configs_for

pytestmark = pytest.mark.git_history
SHA = "a" * 40


def test_the_environment_is_an_allowlist(monkeypatch, tmp_path):
    hostile = {
        "GIT_DIR": "C:/elsewhere/.git", "GIT_CONFIG_PARAMETERS": "'core.pager=evil'",
        "GIT_SSH_COMMAND": "evil", "GIT_EXTERNAL_DIFF": "evil", "GIT_ALTERNATE_OBJECT_DIRECTORIES":
        "C:/x", "HTTPS_PROXY": "http://u:p@proxy.invalid", "GITLEAKS_CONFIG": "C:/x.toml",
        "GIT_CEILING_DIRECTORIES": "C:/", "GIT_TRACE": "C:/trace.txt", "PAGER": "evil",
    }  # fmt: skip
    for key, value in hostile.items():
        monkeypatch.setenv(key, value)
    git = tmp_path / "git" / "git.exe"

    env = hardened_git_env(tmp_path, git)

    assert not set(hostile) & set(env)
    assert env["PATH"] == str(git.parent)
    assert env["GIT_CONFIG_NOSYSTEM"] == "1" and (tmp_path / "git-home") in [
        type(tmp_path)(env["HOME"])]  # fmt: skip
    keys = {env[f"GIT_CONFIG_KEY_{i}"]: env[f"GIT_CONFIG_VALUE_{i}"]
            for i in range(int(env["GIT_CONFIG_COUNT"]))}  # fmt: skip
    assert keys == HARDENING and keys["protocol.allow"] == "never"
    for flag in ("GIT_NO_REPLACE_OBJECTS", "GIT_NO_LAZY_FETCH", "GIT_TERMINAL_PROMPT"):
        assert flag in env


@pytest.mark.parametrize(
    ("config", "expected"),
    [
        ("[core]\n\trepositoryformatversion = 0\n", (set(), False, 0, False)),
        ("[extensions]\n\tobjectFormat = sha256\n", ({"objectformat"}, False, 0, False)),
        ('[remote "origin"]\n\tpromisor = true\n', (set(), True, 0, False)),
        ("[core]\nrepositoryformatversion=1\n[extensions]\nrefStorage=reftable\n",
         ({"refstorage"}, False, 1, False)),
        ('[includeIf "gitdir:~/"]\n\tpath = x\n', (set(), False, 0, True)),
        ("[weird section\n", ({"<unparsed section>"}, False, 0, False)),
    ],
)  # fmt: skip
def test_config_is_scanned_conservatively_for_refusals(config, expected):
    flags = _config_flags(config)

    assert (flags["extensions"], flags["promisor"], flags["version"], flags["include"]) == expected


def _fake_git_dir(root):
    """A hand-made .git with everything that must NOT be copied."""
    g = root / ".git"
    for d in ("objects/ab", "objects/info", "objects/pack", "refs/heads", "refs/replace", "hooks",
              "info", "logs/refs/heads", "worktrees/w"):  # fmt: skip
        (g / d).mkdir(parents=True)
    (g / "objects/ab" / ("c" * 38)).write_bytes(b"loose")
    (g / "objects/info/commit-graph").write_bytes(b"graph")
    (g / "refs/heads/main").write_text(SHA + "\n")
    (g / "refs/replace" / SHA).write_text(SHA + "\n")
    (g / "packed-refs").write_text(
        f"# pack-refs\n{SHA} refs/tags/v1\n^{SHA}\n"
        f"{SHA} refs/replace/{SHA}\n^{SHA}\n{SHA} refs/heads/x\n"
    )
    (g / "HEAD").write_text("ref: refs/heads/main\n")
    (g / "config").write_text('[core]\n\tpager = evil\n[diff "x"]\n\ttextconv = evil\n')
    (g / "hooks/post-checkout").write_text("evil")
    (g / "info/attributes").write_text("* -diff\n")
    (g / "info/grafts").write_text(SHA + "\n")
    (g / "logs/refs/heads/main").write_text("reflog")
    return root


def test_only_objects_refs_and_head_are_copied(tmp_path):
    root = _fake_git_dir(tmp_path / "target")

    info = inspect_git_dir(root)
    copy = copy_git_history(root, tmp_path / "copy", info)

    copied = sorted(p.relative_to(copy).as_posix() for p in copy.rglob("*") if p.is_file())
    assert copied == ["HEAD", "config", f"objects/ab/{'c' * 38}", "packed-refs",
                      "refs/heads/main"]  # fmt: skip
    assert (copy / "config").read_text() == "[core]\n\trepositoryformatversion = 0\n\tbare = true\n"
    assert b"refs/replace" not in (copy / "packed-refs").read_bytes()
    assert (copy / "packed-refs").read_bytes().count(b"^") == 1  # the replace ref's peel is gone
    assert set(info.notes) == {"REPLACE_REFS_IGNORED", "GRAFTS_IGNORED"}
    assert info.limitations == ("LINKED_WORKTREES",)


@pytest.mark.parametrize(
    ("change", "code"),
    [
        (lambda g: (g / "HEAD").write_text("ref: ../../outside\n"), "INVALID_HEAD"),
        (lambda g: (g / "shallow").write_text("not-a-sha\n"), "INVALID_SHALLOW"),
        (lambda g: (g / "objects/info/alternates").write_text("C:/x\n"), "ALTERNATES"),
        (lambda g: (g / "objects/pack/p.promisor").write_text(""), "PARTIAL_CLONE"),
    ],
)
def test_unsafe_structures_are_refused(tmp_path, change, code):
    root = _fake_git_dir(tmp_path / "target")
    change(root / ".git")

    with pytest.raises(GitRefused) as refused:
        inspect_git_dir(root)
    assert refused.value.code == code


def test_size_limit_is_checked_before_and_during_the_copy(tmp_path):
    root = _fake_git_dir(tmp_path / "target")
    with pytest.raises(GitRefused, match="SIZE_LIMIT"):
        inspect_git_dir(root, max_bytes=10)
    info = inspect_git_dir(root)
    with pytest.raises(GitRefused, match="SIZE_LIMIT"):
        copy_git_history(root, tmp_path / "copy", info, max_bytes=3)  # grew after inspection


def test_replace_refs_and_their_peeled_lines_are_dropped():
    packed = f"{SHA} refs/replace/{SHA}\n^{SHA}\n{SHA} refs/tags/v1\n^{SHA}\n".encode()

    assert _without_replace_refs(packed) == f"{SHA} refs/tags/v1\n^{SHA}\n".encode()


def test_commit_parsing_never_returns_names_or_e_mails():
    raw = (
        b"tree " + SHA.encode() + b"\nauthor Ann Example <ann@example.invalid> 1 +0000\n"
        b"committer Bob Example <bob@example.invalid> 1700000000 +0100\n"
        b"gpgsig -----BEGIN PGP SIGNATURE-----\n \n -----END PGP SIGNATURE-----\n\nsubject\n"
    )

    assert parse_commit(raw) == (1700000000, b"subject\n")


def test_batch_output_is_parsed_exactly_and_truncation_is_an_error():
    seen = []
    reader = _BatchReader(lambda sha, kind, data: seen.append((sha, kind, data)))
    stream = f"{SHA} blob 3\nab\n\n{'b' * 40} blob 0\n\n".encode()
    for i in range(0, len(stream), 5):  # arbitrary chunk boundaries
        reader.feed(stream[i : i + 5])
    reader.finish()
    assert seen == [(SHA, b"blob", b"ab\n"), ("b" * 40, b"blob", b"")]

    reader = _BatchReader(lambda *a: None)
    with pytest.raises(GitError):
        reader.feed(f"{SHA} missing\n".encode())
    reader = _BatchReader(lambda *a: None)
    reader.feed(f"{SHA} blob 10\nabc".encode())
    with pytest.raises(GitError):
        reader.finish()


def test_nul_records_survive_any_chunking():
    out = []
    feed, finish = split_records(out.append)
    for piece in (b"a\0b", b"c\0", b"\0d"):
        feed(piece)
    finish()
    assert out == [b"a", b"bc", b"", b"d"]


def test_only_rule_line_and_object_name_are_parsed_from_the_report():
    report = json.dumps([{"RuleID": "github-pat", "StartLine": 3, "File": f"C:/w/base-0/{SHA}",
                          "Secret": "REDACTED", "Match": "x", "Author": "a", "Email": "e",
                          "Message": "m", "Commit": "c"}]).encode()  # fmt: skip

    assert _parse(report) == [("github-pat", 3, SHA)]


@pytest.mark.parametrize(
    ("path", "configs"),
    [
        ("app.py", [("gitleaks.toml", None)]),
        ("deploy/Secret.YAML", [("path-kubernetes-secret-yaml.toml", "kubernetes-secret-yaml")]),
        ("infra/main.tf", [("path-hashicorp-tf-password.toml", "hashicorp-tf-password")]),
    ],
)
def test_path_rules_follow_the_verified_path(path, configs):
    assert configs_for(classify_path(path)) == configs


def test_a_blob_with_two_paths_is_scanned_with_both_rules():
    flags = classify_path("a.yaml") | classify_path("b.php")

    assert {rule for _, rule in configs_for(flags)} == {"kubernetes-secret-yaml",
                                                         "freemius-secret-key"}  # fmt: skip


def test_a_blob_under_a_yaml_and_a_plain_path_also_keeps_the_base_rules():
    flags = classify_path("deploy/secret.yaml") | classify_path("notes/secret.txt")

    assert configs_for(flags) == [
        ("gitleaks.toml", None),
        ("path-kubernetes-secret-yaml.toml", "kubernetes-secret-yaml"),
    ]


def test_git_versions():
    assert parse_git_version("git version 2.47.0.windows.2\n") == (2, 47)
    assert parse_git_version("something else") is None


@pytest.fixture
def copy_runner(git_builder, tmp_path):
    repo = git_builder()
    repo.write("a.txt", "x\n")
    repo.commit("c1")
    git = find_git()
    copy = copy_git_history(repo.path, tmp_path / "copy", inspect_git_dir(repo.path))
    return git, copy, hardened_git_env(tmp_path, git)


def test_git_failures_are_errors_without_tool_output(copy_runner):
    git, copy, env = copy_runner
    runner = GitRunner(git, copy, env, timeout=60)

    with pytest.raises(GitError) as failed:
        runner.output(["cat-file", "-p", "0" * 40])
    assert failed.value.kind.startswith("exit code") and "fatal" not in str(failed.value)


def test_network_protocols_are_never_allowed(copy_runner):
    git, copy, env = copy_runner
    runner = GitRunner(git, copy, env, timeout=60)

    with pytest.raises(GitError):  # refused by protocol.allow=never before any connection
        runner.output(["ls-remote", "https://example.invalid/repo.git"])


def test_the_deadline_kills_git(copy_runner):
    git, copy, env = copy_runner
    runner = GitRunner(git, copy, env, timeout=60, deadline=time.monotonic() + 0.5)

    def never_ending():
        while True:
            time.sleep(0.05)
            yield b""

    started = time.monotonic()
    with pytest.raises(GitError, match="timed out"):
        runner.stream(["cat-file", "--batch"], lambda chunk: None, stdin=never_ending())
    assert time.monotonic() - started < 10


@pytest.mark.parametrize("git", ["git", "git.exe", "./git", "bin/git"])
def test_the_runner_accepts_only_an_absolute_git_executable(tmp_path, git):
    """S603 review: like run_tool, never let the OS search PATH or the cwd for git."""
    with pytest.raises(ValueError, match="absolute"):
        GitRunner(git, tmp_path, {}, timeout=1)
