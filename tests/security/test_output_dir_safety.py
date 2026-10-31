"""G1: report output must never create anything inside the target, even under races.

``resolve()`` checks alone cannot close a check-then-create race, so the writer also verifies
every directory it creates *after* creating it, pins the staging directory's identity, and
re-verifies before each write and after the final rename. These tests simulate an attacker
swapping parts of the output path for junctions into the target at each step.
"""

import os
import stat
import sys

import pytest

import auditor.reports.writer as writer
from auditor.application.audit_service import run_discovery
from auditor.core.errors import TargetErrorCode, TargetPathError


def entries(root):
    return sorted(os.listdir(root))


def test_missing_parents_are_created_outside_target(sample_repo, tmp_path):
    out = tmp_path / "custom" / "nested" / "reports"

    run = run_discovery(sample_repo, out)

    assert run.reports.directory.parent == out.resolve()


def test_ancestor_swapped_for_junction_before_mkdir_leaves_target_clean(
    sample_repo, tmp_path, junction, monkeypatch
):
    holder = tmp_path / "holder"
    holder.mkdir()
    out = holder / "a" / "b"
    before = entries(sample_repo)
    real_mkdir = os.mkdir
    swapped = False

    def swap_then_mkdir(path, *args, **kwargs):
        nonlocal swapped
        if not swapped and os.path.basename(os.fspath(path)) == "a":
            # After validation passed, "holder" becomes a junction into the target.
            swapped = True
            os.rename(holder, tmp_path / "holder_moved")
            junction(holder, sample_repo)
        return real_mkdir(path, *args, **kwargs)

    monkeypatch.setattr(writer.os, "mkdir", swap_then_mkdir)

    with pytest.raises(TargetPathError) as info:
        run_discovery(sample_repo, out)

    assert swapped
    assert info.value.code is TargetErrorCode.OUTPUT_INSIDE_TARGET
    assert entries(sample_repo) == before  # the directory created by mistake was removed


def test_staging_swapped_for_junction_before_write_is_detected(
    sample_repo, out_dir, junction, monkeypatch
):
    before = entries(sample_repo)
    real_render = writer.render_report_json  # the first document written (Stage 6)

    def swap_staging_then_render(inventory):
        staging = next(p for p in out_dir.iterdir() if p.name.endswith(".incomplete"))
        os.rmdir(staging)
        junction(staging, sample_repo)
        return real_render(inventory)

    monkeypatch.setattr(writer, "render_report_json", swap_staging_then_render)

    with pytest.raises(TargetPathError) as info:
        run_discovery(sample_repo, out_dir)

    assert info.value.code is TargetErrorCode.OUTPUT_INSIDE_TARGET
    assert entries(sample_repo) == before  # no report file landed in the target


def test_created_directories_are_private_on_posix(sample_repo, tmp_path):
    if os.name == "nt":
        pytest.skip("POSIX permission bits; Windows inherits the per-user profile ACL")
    run = run_discovery(sample_repo, tmp_path / "new_out")

    assert stat.S_IMODE(os.stat(run.reports.directory).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(run.reports.markdown).st_mode) == 0o600


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX world-writable directory check")
def test_world_writable_output_parent_without_sticky_bit_is_refused(sample_repo, tmp_path):
    shared = tmp_path / "shared"
    shared.mkdir()
    os.chmod(shared, 0o777)  # noqa: S103 - deliberately unsafe: anyone could swap our dirs

    with pytest.raises(TargetPathError) as info:
        run_discovery(sample_repo, shared / "reports")

    assert info.value.code is TargetErrorCode.UNSAFE_OUTPUT_DIR
