import os
import shutil
from itertools import count

from auditor.core.models import ExclusionReason, IncompleteReason
from auditor.core.policy import ScanPolicy
from auditor.discovery.repository import inspect, validate_target


def run(root, clock=None, **policy):
    kwargs = {"clock": clock} if clock else {}
    return inspect(validate_target(root), ScanPolicy(**policy), **kwargs)


def test_max_files_stops_scan_and_marks_partial(make_tree):
    root = make_tree({f"f{i:02}.py": "" for i in range(10)})

    result = run(root, max_files=3)

    assert [f.relative_path for f in result.files] == ["f00.py", "f01.py", "f02.py"]
    assert result.incomplete_reasons == [IncompleteReason.MAX_FILES]


def test_exactly_max_files_is_complete(make_tree):
    root = make_tree({f"f{i}.py": "" for i in range(3)})

    result = run(root, max_files=3)

    assert len(result.files) == 3
    assert result.incomplete_reasons == []


def test_max_files_reports_unvisited_directories(make_tree):
    root = make_tree({"a": {"1.py": "", "2.py": ""}, "b": {"3.py": ""}, "c": {"4.py": ""}})

    result = run(root, max_files=1)

    assert result.incomplete_reasons == [IncompleteReason.MAX_FILES]
    assert result.unvisited_directories == 2  # "b" and "c" never listed


def test_limit_hit_mid_directory_counts_already_discovered_subdirectories(make_tree):
    # Regression: sorted order is "a", "b", "c.py", "d.py"; the limit is hit at "d.py",
    # after "a" and "b" were discovered in the same listing but before they were visited.
    root = make_tree({"a": {"x.py": ""}, "b": {"y.py": ""}, "c.py": "", "d.py": ""})

    result = run(root, max_files=1)

    assert [f.relative_path for f in result.files] == ["c.py"]
    assert result.incomplete_reasons == [IncompleteReason.MAX_FILES]
    assert result.unvisited_directories == 2


def test_max_entries_counts_directories_and_excluded_entries(make_tree):
    root = make_tree({"node_modules": {}, "a.py": "", "b.py": "", "c.py": ""})

    result = run(root, max_entries_visited=2)

    assert result.entries_visited == 2
    assert result.incomplete_reasons == [IncompleteReason.MAX_ENTRIES]


def test_huge_directory_listing_is_bounded(make_tree):
    root = make_tree({f"f{i:04}.txt": "" for i in range(500)})

    result = run(root, max_entries_visited=50)

    assert result.entries_visited == 50
    assert len(result.files) == 50
    assert result.incomplete_reasons == [IncompleteReason.MAX_ENTRIES]


def test_max_depth_excludes_deeper_directories(make_tree):
    root = make_tree({"d1": {"a.py": "", "d2": {"b.py": "", "d3": {"c.py": ""}}}})

    result = run(root, max_depth=2)

    assert [f.relative_path for f in result.files] == ["d1/a.py", "d1/d2/b.py"]
    assert {e.relative_path: e.reason for e in result.excluded} == {
        "d1/d2/d3": ExclusionReason.MAX_DEPTH
    }
    assert result.incomplete_reasons == [IncompleteReason.MAX_DEPTH]


def _fs(path) -> str:
    """Path usable beyond Windows MAX_PATH (test setup / cleanup only)."""
    text = os.fspath(path)
    return "\\\\?\\" + text if os.name == "nt" else text


def test_very_deep_tree_beyond_max_path_and_recursion_limit(tmp_path):
    # 1100 levels: deeper than Python's default recursion limit (1000) and, on Windows,
    # ~2200 characters long — far beyond the legacy 260-character MAX_PATH.
    root = tmp_path / "target"
    root.mkdir()
    current = _fs(root)
    try:
        for _ in range(1100):
            current = os.path.join(current, "d")
            os.mkdir(current)
        with open(os.path.join(current, "leaf.py"), "w", encoding="utf-8"):
            pass

        result = run(root, max_depth=2000)

        assert len(result.files) == 1
        assert result.files[0].relative_path == "d/" * 1100 + "leaf.py"
        assert result.incomplete_reasons == []
    finally:
        shutil.rmtree(_fs(root))


def test_timeout_marks_partial(make_tree):
    root = make_tree({f"f{i}.py": "" for i in range(20)})
    ticks = count(start=0, step=1)  # each clock() call advances one "second"

    result = run(root, clock=lambda: float(next(ticks)), max_duration_seconds=5)

    assert result.incomplete_reasons == [IncompleteReason.TIMEOUT]
    assert 0 < len(result.files) < 20


def test_multiple_incomplete_reasons_are_all_recorded(make_tree, monkeypatch):
    root = make_tree({"locked": {"x.py": ""}, "d1": {"d2": {"y.py": ""}}})
    real_scandir = os.scandir

    def deny_locked(path):
        if os.path.basename(os.fspath(path)) == "locked":
            raise PermissionError("denied")
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", deny_locked)

    result = run(root, max_depth=1)

    assert set(result.incomplete_reasons) == {
        IncompleteReason.MAX_DEPTH,
        IncompleteReason.UNREADABLE,
    }
