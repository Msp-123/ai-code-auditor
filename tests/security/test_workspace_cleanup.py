"""Regression tests for D-042: temporary workspaces (raw output, source copies) are always
removed, also beyond MAX_PATH, never via links, only when ours, and failures are never silent.
"""

import os
import sys
import time
from pathlib import Path

import pytest

import auditor.scanners.workspace as workspace_module
from auditor.core.errors import TargetErrorCode, TargetPathError
from auditor.core.ownership import owned_by_current_user
from auditor.discovery.repository import extended_length_path
from auditor.scanners.semgrep_adapter import short_temp_base
from auditor.scanners.workspace import (
    PrivateWorkspace,
    StaleWorkspaces,
    remove_owned_workspace,
    remove_tree,
)

IS_WINDOWS = os.name == "nt"
OLD = time.time() - 3 * 24 * 3600


def _deep_file(top: Path, min_length: int, content: str = "SOURCE_COPY = 1\n") -> str:
    """Create ``top/m/directory_name_x/.../deep.py`` whose directory path is >= min_length."""
    parts = ["m"]
    while len(os.path.join(str(top), *parts)) < min_length:
        parts.append("directory_name_x")
    deep = os.path.join(extended_length_path(str(top)), *parts)
    os.makedirs(deep)
    with open(os.path.join(deep, "deep.py"), "w", encoding="utf-8") as handle:
        handle.write(content)
    return deep


def _exists(path: Path) -> bool:
    return os.path.lexists(extended_length_path(str(path)))


# ------------------------------------------------------------------- long paths (the bug)


def test_file_beyond_max_path_is_removed(tmp_path, sample_repo):
    base = tmp_path / "tb"
    ws = PrivateWorkspace(sample_repo, base)

    with ws as work:
        deep = _deep_file(work, 300)
        assert len(deep) - (4 if IS_WINDOWS else 0) > 260

    assert not ws.cleanup_failed and ws.failures == []
    assert not _exists(work)
    assert list(base.iterdir()) == []


def test_reproduced_322_character_mirror_copy_is_removed(sample_repo):
    """The exact layout that stayed behind: <short base>\\r-xxxxxxxx\\m\\directory_name_x*16."""
    base = short_temp_base()
    before = set(base.iterdir()) if base.exists() else set()
    ws = PrivateWorkspace(sample_repo, base, prefix="r-")

    with ws as work:
        deep = os.path.join(extended_length_path(str(work)), "m", *(["directory_name_x"] * 16))
        os.makedirs(deep)
        with open(os.path.join(deep, "deep.py"), "w", encoding="utf-8") as handle:
            handle.write("SOURCE_COPY = 1\n")
        assert len(deep) - (4 if IS_WINDOWS else 0) >= 322

    assert not ws.cleanup_failed
    assert not _exists(work)
    assert set(base.iterdir()) == before


def test_failed_deletion_is_recorded_not_swallowed(tmp_path, sample_repo):
    base = tmp_path / "tb"
    ws = PrivateWorkspace(sample_repo, base, component="semgrep", contents="copies")
    blocker = None
    with ws as work:
        locked = work / "sub"
        locked.mkdir()
        (locked / "copy.py").write_text("SOURCE_COPY = 1\n", encoding="utf-8")
        if IS_WINDOWS:
            blocker = open(locked / "copy.py", encoding="utf-8")  # noqa: SIM115 - held open
        else:
            if os.geteuid() == 0:
                pytest.skip("root ignores directory permissions")
            os.chmod(locked, 0o500)
    try:
        assert ws.cleanup_failed
        (failure,) = ws.failures
        assert failure.component == "semgrep" and failure.workspace == work.name
        assert "could not be deleted" in failure.reason
        assert str(base) not in failure.reason and str(tmp_path) not in failure.reason
        assert _exists(locked / "copy.py")  # really left behind: that is what is reported
    finally:
        if blocker is not None:
            blocker.close()
        else:
            os.chmod(locked, 0o700)
        assert remove_owned_workspace(work) is None


def test_stale_long_path_leftover_is_reported_not_deleted(tmp_path, sample_repo):
    base = tmp_path / "tb"
    stale = base / "r-stale123"
    stale.mkdir(parents=True)
    deep = _deep_file(stale, 300)
    os.utime(stale, (OLD, OLD))

    ws = PrivateWorkspace(sample_repo, base, prefix="r-", component="semgrep", contents="c")
    with ws as work:
        pass

    assert os.path.exists(os.path.join(deep, "deep.py"))  # user decision: no auto-deletion
    assert ws.stale == [StaleWorkspaces("semgrep", "c", "r-*", 1)]
    assert not _exists(work)  # the current run's own workspace is still removed
    assert ws.failures == []


def test_safe_removal_stays_available_for_a_future_manual_cleanup(tmp_path):
    stale = tmp_path / "r-stale123"
    stale.mkdir()
    _deep_file(stale, 300)

    assert remove_owned_workspace(stale) is None
    assert not _exists(stale)


def test_stale_leftover_not_owned_by_us_is_never_deleted(tmp_path, sample_repo, monkeypatch):
    base = tmp_path / "tb"
    foreign = base / "r-foreign1"
    foreign.mkdir(parents=True)
    (foreign / "theirs.txt").write_text("x", encoding="utf-8")
    os.utime(foreign, (OLD, OLD))
    real_check = workspace_module.owned_by_current_user
    monkeypatch.setattr(
        workspace_module,
        "owned_by_current_user",
        lambda path: "r-foreign1" not in str(path) and real_check(path),
    )

    ws = PrivateWorkspace(sample_repo, base, prefix="r-")
    with ws:
        pass

    assert (foreign / "theirs.txt").exists()
    assert ws.failures == [] and ws.stale == []  # not ours: not counted as our leftover


def test_fresh_workspace_of_a_concurrent_run_is_kept(tmp_path, sample_repo):
    base = tmp_path / "tb"
    concurrent = base / "r-running1"
    concurrent.mkdir(parents=True)
    (concurrent / "copy.py").write_text("x", encoding="utf-8")

    ws = PrivateWorkspace(sample_repo, base, prefix="r-")
    with ws:
        pass

    assert (concurrent / "copy.py").exists()
    assert ws.stale == []  # younger than the threshold: not reported as a leftover


# --------------------------------------------------------------- link / junction attacks


@pytest.fixture
def outside(tmp_path):
    victim = tmp_path / "outside"
    victim.mkdir()
    (victim / "precious.txt").write_text("must survive", encoding="utf-8")
    return victim


def test_junction_inside_workspace_is_removed_not_followed(
    tmp_path, sample_repo, outside, junction
):
    base = tmp_path / "tb"
    ws = PrivateWorkspace(sample_repo, base)
    with ws as work:
        junction(work / "escape", outside)

    assert (outside / "precious.txt").read_text(encoding="utf-8") == "must survive"
    assert not _exists(work)
    assert ws.failures == []


def test_symlink_inside_workspace_is_removed_not_followed(tmp_path, sample_repo, outside, symlink):
    base = tmp_path / "tb"
    ws = PrivateWorkspace(sample_repo, base)
    with ws as work:
        symlink(work / "dirlink", outside, target_is_directory=True)
        symlink(work / "filelink", outside / "precious.txt")

    assert (outside / "precious.txt").read_text(encoding="utf-8") == "must survive"
    assert not _exists(work)


def test_workspace_swapped_for_a_junction_is_not_deleted(tmp_path, sample_repo, outside, junction):
    base = tmp_path / "tb"
    ws = PrivateWorkspace(sample_repo, base)
    moved = tmp_path / "moved"
    with ws as work:
        work.rename(moved)
        junction(work, outside)  # the workspace path now leads outside

    try:
        assert (outside / "precious.txt").read_text(encoding="utf-8") == "must survive"
        assert ws.cleanup_failed
        assert "replaced by a link" in ws.failures[0].reason
    finally:
        os.rmdir(work)  # removes the junction only
        assert remove_owned_workspace(moved) is None


def test_stale_entry_that_is_a_junction_is_not_followed(
    tmp_path, sample_repo, outside, junction, monkeypatch
):
    base = tmp_path / "tb"
    base.mkdir()
    junction(base / "run-planted", outside)
    monkeypatch.setattr(workspace_module, "STALE_AFTER_SECONDS", -3600)  # everything is stale

    ws = PrivateWorkspace(sample_repo, base)
    with ws:
        pass

    assert (outside / "precious.txt").read_text(encoding="utf-8") == "must survive"
    assert ws.stale == []  # a link is never counted as our leftover
    os.rmdir(base / "run-planted")


def test_directory_changed_during_cleanup_stops_deletion(tmp_path):
    top = tmp_path / "victim"
    top.mkdir()
    (top / "keep.txt").write_text("x", encoding="utf-8")

    with pytest.raises(workspace_module._Unsafe):
        remove_tree(extended_length_path(str(top)), (0, 0))  # identity does not match

    assert (top / "keep.txt").exists()


def test_base_directory_that_is_a_junction_is_refused(tmp_path, sample_repo, outside, junction):
    base = tmp_path / "linkbase"
    junction(base, outside)

    with pytest.raises(TargetPathError) as info, PrivateWorkspace(sample_repo, base):
        pass

    assert info.value.code is TargetErrorCode.UNSAFE_OUTPUT_DIR
    assert sorted(p.name for p in outside.iterdir()) == ["precious.txt"]
    os.rmdir(base)


def test_base_directory_owned_by_someone_else_is_refused(tmp_path, sample_repo, monkeypatch):
    base = tmp_path / "tb"
    base.mkdir()
    monkeypatch.setattr(workspace_module, "owned_by_current_user", lambda path: False)

    with pytest.raises(TargetPathError) as info, PrivateWorkspace(sample_repo, base):
        pass

    assert info.value.code is TargetErrorCode.UNSAFE_OUTPUT_DIR
    assert list(base.iterdir()) == []


# ----------------------------------------------------------------------- ownership check


def test_own_directories_are_recognised(tmp_path):
    assert owned_by_current_user(str(tmp_path))
    deep = _deep_file(tmp_path / "d", 300)
    assert owned_by_current_user(deep)


def test_foreign_and_missing_directories_are_not_ours(tmp_path):
    assert not owned_by_current_user(str(tmp_path / "missing"))
    if sys.platform == "win32":
        assert not owned_by_current_user(os.environ.get("SystemRoot", r"C:\Windows"))
    elif os.geteuid() != 0:
        assert not owned_by_current_user("/")
