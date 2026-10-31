"""Blob -> commit -> path attribution in git history (Stage 4b, step 1).

``git rev-list --objects`` names one path per blob and ``git log --find-object`` is not proof
of where content first appeared. The auditor therefore derives attribution from the commit
trees themselves: content B at path P is *introduced* by commit C when C's tree has B at P
and none of C's parents has B at P (a root commit introduces everything it contains).

Every test compares the auditor's result (``git diff-tree`` on the private copy) with an
independent oracle built from the full tree of every commit (``git ls-tree -r``) of the
fixture repository itself.
"""

import secrets
import string

import pytest

from auditor.scanners.git_history import (
    GitRunner,
    copy_git_history,
    find_git,
    hardened_git_env,
    index_history,
    inspect_git_dir,
)

pytestmark = pytest.mark.git_history
ALNUM = string.ascii_letters + string.digits


def fake_token() -> str:
    return "gh" + "p_" + "".join(secrets.choice(ALNUM) for _ in range(36))


def oracle(repo):
    """{blob: {(commit, path)}} introductions and {blob: {path}} from full commit trees."""
    rows = [line.split() for line in repo.git("rev-list", "--all", "--parents").splitlines()]
    trees = {}
    for commit, *_ in rows:
        listing = repo.git("ls-tree", "-r", "-z", "--full-tree", commit)
        tree = {}
        for item in filter(None, listing.split("\0")):
            meta, path = item.split("\t", 1)
            _mode, kind, sha = meta.split()
            if kind == "blob":
                tree[path] = sha
        trees[commit] = tree
    introductions, paths = {}, {}
    for commit, *parents in rows:
        for path, blob in trees[commit].items():
            paths.setdefault(blob, set()).add(path)
            if all(trees[p].get(path) != blob for p in parents):
                introductions.setdefault(blob, set()).add((commit, path))
    return introductions, paths, len(rows)


def blob_of(repo, rev_path: str) -> str:
    return repo.git("rev-parse", rev_path)


@pytest.fixture
def history(git_builder, tmp_path):
    """One repository with the six requested scenarios (plus a tag pointing at a blob)."""
    r = git_builder()
    s = {name: fake_token() for name in
         ("multi", "branch", "merge", "deleted", "picked", "tagged")}  # fmt: skip
    r.write("base.txt", "base\n")
    r.commit("root")
    # 1. the same blob under several paths in one commit
    r.write("a.txt", f"k = {s['multi']}\n")
    r.write("deep/dir/a_copy.txt", f"k = {s['multi']}\n")
    r.commit("same content, two paths")
    # 2. rename and copy of that content later
    r.git("mv", "a.txt", "renamed.txt")
    r.commit("rename")
    r.write("copied.txt", f"k = {s['multi']}\n")
    r.commit("copy")
    # 3. the same blob added independently on two branches
    r.git("checkout", "-q", "-b", "left")
    r.write("k.txt", f"k = {s['branch']}\n")
    r.commit("left adds k")
    r.git("checkout", "-q", "main")
    r.git("checkout", "-q", "-b", "right")
    r.write("k.txt", f"k = {s['branch']}\n")
    r.commit("right adds k")
    r.git("checkout", "-q", "main")
    # 4. content that appears only in a merge commit (evil merge)
    r.git("merge", "-q", "--no-ff", "--no-commit", "left")
    r.write("merge_only.txt", f"k = {s['merge']}\n")
    r.git("add", "-A")
    r.git("commit", "-q", "-m", "merge left")
    # 5. a secret in a file that is deleted later
    r.write("gone.txt", f"k = {s['deleted']}\n")
    r.commit("add gone")
    r.git("rm", "-q", "gone.txt")
    r.commit("delete gone")
    # 6. cherry-pick: the same change on two branches
    r.git("checkout", "-q", "-b", "topic")
    r.write("pick.txt", f"k = {s['picked']}\n")
    picked = r.commit("topic change")
    r.git("checkout", "-q", "main")
    r.write("main_only.txt", "diverge\n")  # else the pick could recreate the same commit
    r.commit("main moves on")
    r.git("cherry-pick", picked)
    # a lightweight tag pointing straight at a blob (reachable, but in no commit tree)
    tagged = r.git("hash-object", "-w", "--stdin", stdin=f"k = {s['tagged']}\n".encode())
    r.git("tag", "lone-blob", tagged)

    git = find_git()
    work = tmp_path / "work"
    work.mkdir()
    copy = copy_git_history(r.path, work / "copy", inspect_git_dir(r.path))
    runner = GitRunner(git, copy, hardened_git_env(work, git), timeout=120)
    return r, runner, s, tagged


def test_attribution_matches_the_tree_oracle_exactly(history):
    repo, runner, _, _ = history

    index = index_history(runner)
    introductions, paths, commits = oracle(repo)

    assert index.commits == commits
    assert index.introductions == introductions
    assert index.paths == paths


def test_the_six_scenarios(history):
    repo, runner, s, tagged = history
    index = index_history(runner)
    commit_of = {repo.git("log", "-1", "--format=%s", c): c
                 for c in repo.git("rev-list", "--all").split()}  # fmt: skip

    multi = blob_of(repo, f"{commit_of['copy']}:copied.txt")
    assert index.paths[multi] == {"deep/dir/a_copy.txt", "renamed.txt", "copied.txt", "a.txt"}
    assert index.introductions[multi] == {
        (commit_of["same content, two paths"], "a.txt"),
        (commit_of["same content, two paths"], "deep/dir/a_copy.txt"),
        (commit_of["rename"], "renamed.txt"),  # a rename is a new path for the same content
        (commit_of["copy"], "copied.txt"),
    }
    branch = blob_of(repo, "left:k.txt")
    assert index.introductions[branch] == {(commit_of["left adds k"], "k.txt"),
                                           (commit_of["right adds k"], "k.txt")}  # fmt: skip
    merge = blob_of(repo, f"{commit_of['merge left']}:merge_only.txt")
    assert index.introductions[merge] == {(commit_of["merge left"], "merge_only.txt")}
    deleted = blob_of(repo, f"{commit_of['add gone']}:gone.txt")
    assert index.introductions[deleted] == {(commit_of["add gone"], "gone.txt")}
    picked = blob_of(repo, "topic:pick.txt")
    assert len(index.introductions[picked]) == 2  # the original and the cherry-picked commit
    assert {p for _, p in index.introductions[picked]} == {"pick.txt"}
    # reachable through a tag only: no commit, no path - never guessed
    assert tagged not in index.paths and tagged not in index.introductions
    assert tagged in index.blobs


def test_wanted_restricts_memory_to_the_blobs_asked_for(history):
    repo, runner, s, _ = history
    full = index_history(runner)
    deleted = blob_of(repo, "HEAD~3:gone.txt")

    narrow = index_history(runner, wanted={deleted})

    assert narrow.introductions == {deleted: full.introductions[deleted]}
    assert narrow.paths == {deleted: full.paths[deleted]}
    assert narrow.commits == full.commits
