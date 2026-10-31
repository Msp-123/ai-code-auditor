"""Links must be detected without being followed, wherever they point."""

import os

from auditor.core.models import EntryKind, ExclusionReason
from auditor.core.policy import ScanPolicy
from auditor.discovery.repository import inspect, validate_target


def run(root):
    return inspect(validate_target(root), ScanPolicy())


def excluded(result):
    return {e.relative_path: e for e in result.excluded}


def all_paths(result):
    return [f.relative_path for f in result.files] + [e.relative_path for e in result.excluded]


def make_outside(tmp_path):
    outside = tmp_path / "outside"
    (outside / "secret_dir").mkdir(parents=True)
    (outside / "outside_secret.txt").write_text("OUTSIDE-CONTENT", encoding="utf-8")
    (outside / "secret_dir" / "inner_outside.py").write_text("", encoding="utf-8")
    return outside


def test_junction_to_outside_directory_is_not_followed(make_tree, tmp_path, junction):
    root = make_tree({"app.py": ""})
    outside = make_outside(tmp_path)
    junction(root / "escape", outside / "secret_dir")

    result = run(root)
    entry = excluded(result)["escape"]

    assert entry.reason is ExclusionReason.JUNCTION
    assert entry.kind is EntryKind.LINK
    assert entry.points_outside_root is True
    assert not any("inner_outside" in p for p in all_paths(result))


def test_junction_inside_root_is_not_followed(make_tree, junction):
    root = make_tree({"pkg": {"mod.py": ""}})
    junction(root / "alias", root / "pkg")

    result = run(root)

    assert [f.relative_path for f in result.files] == ["pkg/mod.py"]  # no duplicate via alias
    assert excluded(result)["alias"].points_outside_root is False


def test_junction_cycle_terminates(make_tree, junction):
    root = make_tree({"a": {"x.py": ""}})
    junction(root / "a" / "loop", root)

    result = run(root)

    assert [f.relative_path for f in result.files] == ["a/x.py"]
    assert excluded(result)["a/loop"].reason is ExclusionReason.JUNCTION


def test_file_symlink_to_outside_is_not_followed(make_tree, tmp_path, symlink):
    root = make_tree({"app.py": ""})
    outside = make_outside(tmp_path)
    symlink(root / "leak.txt", outside / "outside_secret.txt")

    result = run(root)
    entry = excluded(result)["leak.txt"]

    assert entry.reason is ExclusionReason.SYMLINK
    assert entry.points_outside_root is True
    assert "leak.txt" not in [f.relative_path for f in result.files]


def test_directory_symlink_to_outside_is_not_followed(make_tree, tmp_path, symlink):
    root = make_tree({"app.py": ""})
    outside = make_outside(tmp_path)
    symlink(root / "dirlink", outside / "secret_dir", target_is_directory=True)

    result = run(root)

    assert excluded(result)["dirlink"].reason is ExclusionReason.SYMLINK
    assert not any("inner_outside" in p for p in all_paths(result))


def test_relative_dotdot_symlink_is_classified_outside(make_tree, tmp_path, symlink):
    root = make_tree({"sub": {}})
    make_outside(tmp_path)
    symlink(root / "sub" / "up", os.path.join("..", "..", "outside"), target_is_directory=True)

    result = run(root)

    assert excluded(result)["sub/up"].points_outside_root is True


def test_broken_symlink_is_excluded(make_tree, tmp_path, symlink):
    root = make_tree({"app.py": ""})
    symlink(root / "dangling", tmp_path / "does-not-exist")

    result = run(root)

    assert excluded(result)["dangling"].reason is ExclusionReason.SYMLINK


def test_symlink_loop_terminates(make_tree, symlink):
    root = make_tree({"a.py": ""})
    symlink(root / "self", root, target_is_directory=True)

    result = run(root)

    assert [f.relative_path for f in result.files] == ["a.py"]
    assert excluded(result)["self"].points_outside_root is False


class _FakeSymlinkEntry:
    """A DirEntry that reports itself as a symlink, as scandir does for real symlinks.

    Lets the symlink handling logic be verified on systems where creating real symlinks is
    not permitted (e.g. Windows without Developer Mode). ``stat`` deliberately claims a
    directory: a correct implementation must check is_symlink() first and never descend.
    """

    def __init__(self, entry):
        self.name = entry.name
        self.path = entry.path
        self._entry = entry

    def is_symlink(self):
        return True

    def stat(self, follow_symlinks=True):
        return self._entry.stat(follow_symlinks=False)


def _scandir_with_fake_symlink(real_scandir, link_name):
    class _Iterator:
        def __init__(self, path):
            with real_scandir(path) as it:
                self._entries = [_FakeSymlinkEntry(e) if e.name == link_name else e for e in it]

        def __iter__(self):
            return iter(self._entries)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    return _Iterator


def test_simulated_directory_symlink_to_outside_is_not_followed(make_tree, tmp_path, monkeypatch):
    root = make_tree({"dirlink": {"would_be_followed.py": ""}, "app.py": ""})
    outside = make_outside(tmp_path)
    monkeypatch.setattr(os, "scandir", _scandir_with_fake_symlink(os.scandir, "dirlink"))
    monkeypatch.setattr(os, "readlink", lambda _p: str(outside / "secret_dir"))

    result = run(root)
    entry = excluded(result)["dirlink"]

    assert entry.reason is ExclusionReason.SYMLINK
    assert entry.points_outside_root is True
    assert [f.relative_path for f in result.files] == ["app.py"]


def test_simulated_symlink_inside_root_is_classified_inside(make_tree, monkeypatch):
    root = make_tree({"pkg": {"m.py": ""}, "alias": {"m.py": ""}})
    monkeypatch.setattr(os, "scandir", _scandir_with_fake_symlink(os.scandir, "alias"))
    monkeypatch.setattr(os, "readlink", lambda _p: "pkg")  # relative target

    result = run(root)

    assert excluded(result)["alias"].points_outside_root is False
    assert [f.relative_path for f in result.files] == ["pkg/m.py"]


def test_simulated_symlink_with_unreadable_target_is_still_excluded(make_tree, monkeypatch):
    root = make_tree({"weird": {"x.py": ""}})

    def unreadable(_path):
        raise OSError("cannot read link")

    monkeypatch.setattr(os, "scandir", _scandir_with_fake_symlink(os.scandir, "weird"))
    monkeypatch.setattr(os, "readlink", unreadable)

    entry = excluded(run(root))["weird"]

    assert entry.reason is ExclusionReason.SYMLINK
    assert entry.points_outside_root is None


def test_root_given_as_junction_is_resolved_and_scanned(tmp_path, junction):
    real = tmp_path / "real"
    (real / "pkg").mkdir(parents=True)
    (real / "pkg" / "m.py").write_text("", encoding="utf-8")
    link = tmp_path / "link_root"
    junction(link, real)

    root = validate_target(link)

    assert root == real.resolve()
    assert [f.relative_path for f in inspect(root, ScanPolicy()).files] == ["pkg/m.py"]
