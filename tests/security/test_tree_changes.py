"""The tree may change while it is scanned; such changes must be detected, not followed."""

import os
import shutil

from auditor.core.models import ExclusionReason, IncompleteReason
from auditor.core.policy import ScanPolicy
from auditor.discovery.repository import inspect, validate_target


def test_directory_swapped_between_discovery_and_descent_is_reported(
    make_tree, tmp_path, monkeypatch
):
    root = validate_target(make_tree({"a": {"inner.py": ""}, "z": {"inner.py": ""}}))
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "planted.py").write_text("", encoding="utf-8")
    real_scandir = os.scandir
    swapped = False

    def scandir_then_swap(path):
        nonlocal swapped
        if os.path.basename(os.fspath(path)) == "a" and not swapped:
            # "z" was already discovered (identity recorded) but not yet descended into.
            swapped = True
            os.rename(root / "z", tmp_path / "z_old")  # keep it alive: no file-id reuse
            shutil.copytree(elsewhere, root / "z")
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", scandir_then_swap)

    result = inspect(root, ScanPolicy())

    assert swapped
    assert {e.relative_path: e.reason for e in result.excluded} == {
        "z": ExclusionReason.CHANGED_DURING_SCAN
    }
    assert IncompleteReason.CHANGED_DURING_SCAN in result.incomplete_reasons
    assert [f.relative_path for f in result.files] == ["a/inner.py"]


def test_directory_replaced_by_junction_is_not_followed(make_tree, tmp_path, junction, monkeypatch):
    root = validate_target(make_tree({"a": {"inner.py": ""}}))
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "planted.py").write_text("", encoding="utf-8")
    real_scandir = os.scandir
    calls = 0

    def scandir_then_swap(path):
        nonlocal calls
        calls += 1
        iterator = real_scandir(path)
        if calls == 1:
            # The root listing still reports "a" as a plain directory (stale DirEntry).
            entries = list(iterator)
            iterator.close()
            shutil.rmtree(root / "a")
            junction(root / "a", outside)
            return _ListIterator(entries)
        return iterator

    monkeypatch.setattr(os, "scandir", scandir_then_swap)

    result = inspect(root, ScanPolicy())

    assert "a/planted.py" not in [f.relative_path for f in result.files]
    assert {e.relative_path: e.reason for e in result.excluded} == {
        "a": ExclusionReason.CHANGED_DURING_SCAN
    }


def test_unreadable_subdirectory_is_reported_and_scan_continues(make_tree, monkeypatch):
    root = validate_target(make_tree({"locked": {"x.py": ""}, "open": {"y.py": ""}}))
    real_scandir = os.scandir

    def deny_locked(path):
        if os.path.basename(os.fspath(path)) == "locked":
            raise PermissionError("denied")
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", deny_locked)

    result = inspect(root, ScanPolicy())

    assert [f.relative_path for f in result.files] == ["open/y.py"]
    assert {e.relative_path: e.reason for e in result.excluded} == {
        "locked": ExclusionReason.UNREADABLE
    }
    assert result.incomplete_reasons == [IncompleteReason.UNREADABLE]


def test_entry_that_vanishes_before_stat_is_reported(make_tree, monkeypatch):
    root = validate_target(make_tree({"gone.py": "", "kept.py": ""}))
    real_scandir = os.scandir

    class _VanishingEntry:
        def __init__(self, entry):
            self._entry = entry
            self.name = entry.name
            self.path = entry.path

        def stat(self, follow_symlinks=True):
            raise FileNotFoundError(self.path)

        def is_symlink(self):
            return False

    def scandir_with_vanishing(path):
        iterator = real_scandir(path)
        entries = [_VanishingEntry(e) if e.name == "gone.py" else e for e in iterator]
        iterator.close()
        return _ListIterator(entries)

    monkeypatch.setattr(os, "scandir", scandir_with_vanishing)

    result = inspect(root, ScanPolicy())

    assert [f.relative_path for f in result.files] == ["kept.py"]
    assert {e.relative_path: e.reason for e in result.excluded} == {
        "gone.py": ExclusionReason.UNREADABLE
    }


class _ListIterator:
    """Minimal stand-in for the context-managed iterator returned by os.scandir."""

    def __init__(self, entries):
        self._entries = entries

    def __iter__(self):
        return iter(self._entries)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def close(self):
        pass
