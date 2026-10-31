"""Raw scanner output lives only in a private workspace that is always removed."""

import os
import time

import pytest

from auditor.core.errors import TargetErrorCode, TargetPathError
from auditor.scanners.workspace import PrivateWorkspace


def test_workspace_is_created_outside_target_and_removed(tmp_path, sample_repo):
    base = tmp_path / "tmpbase"

    with PrivateWorkspace(sample_repo, base) as work:
        (work / "raw.json").write_text("RAW", encoding="utf-8")
        assert work.parent == base.resolve()

    assert not work.exists()
    assert list(base.iterdir()) == []


def test_workspace_is_removed_when_the_scan_raises(tmp_path, sample_repo):
    base = tmp_path / "tmpbase"

    with pytest.raises(RuntimeError), PrivateWorkspace(sample_repo, base) as work:
        (work / "raw.json").write_text("RAW", encoding="utf-8")
        raise RuntimeError("scanner blew up")

    assert list(base.iterdir()) == []


def test_stale_workspaces_from_killed_runs_are_reported_not_deleted(tmp_path, sample_repo):
    base = tmp_path / "tmpbase"
    base.mkdir()
    stale = base / "run-stale"
    stale.mkdir()
    (stale / "raw.json").write_text("OLD RAW OUTPUT", encoding="utf-8")
    old = time.time() - 3 * 24 * 3600
    os.utime(stale, (old, old))
    fresh = base / "run-fresh"  # may belong to a concurrent run: keep it
    fresh.mkdir()
    unrelated = base / "keep-me.txt"  # not ours: never touched
    unrelated.write_text("x", encoding="utf-8")

    ws = PrivateWorkspace(sample_repo, base)
    with ws:
        pass

    assert (stale / "raw.json").exists()  # D-042: never deleted automatically ...
    assert [(s.pattern, s.count) for s in ws.stale] == [("run-*", 1)]  # ... but reported
    assert fresh.exists()
    assert unrelated.exists()


def test_workspace_base_inside_target_is_refused(sample_repo):
    with pytest.raises(TargetPathError) as info, PrivateWorkspace(sample_repo, sample_repo / "tmp"):
        pass

    assert info.value.code is TargetErrorCode.OUTPUT_INSIDE_TARGET
    assert not (sample_repo / "tmp").exists()


def test_workspace_is_private_on_posix(tmp_path, sample_repo):
    if os.name == "nt":
        pytest.skip("POSIX permission bits; Windows inherits the per-user profile ACL")
    with PrivateWorkspace(sample_repo, tmp_path / "tmpbase") as work:
        assert (os.stat(work).st_mode & 0o777) == 0o700
