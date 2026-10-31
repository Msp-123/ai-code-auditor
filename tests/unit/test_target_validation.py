import pytest

from auditor.core.errors import TargetErrorCode, TargetPathError
from auditor.discovery.repository import validate_output_dir, validate_target


def test_valid_directory_is_resolved(tmp_path):
    target = tmp_path / "proj"
    target.mkdir()

    assert validate_target(str(target)) == target.resolve()


@pytest.mark.parametrize("name", ["with space", "çğıöşü İ", "a&b;c$d'(e)", "日本語_🚀"])
def test_unusual_but_valid_names_are_accepted(tmp_path, name):
    target = tmp_path / name
    target.mkdir()

    assert validate_target(target) == target.resolve()


def test_relative_path_is_resolved(tmp_path, monkeypatch):
    (tmp_path / "proj").mkdir()
    monkeypatch.chdir(tmp_path)

    assert validate_target("proj") == (tmp_path / "proj").resolve()


@pytest.mark.parametrize("raw", ["", "bad\x00path"])
def test_empty_or_nul_path_is_invalid(raw):
    with pytest.raises(TargetPathError) as info:
        validate_target(raw)
    assert info.value.code is TargetErrorCode.INVALID_PATH


def test_missing_path_is_not_found(tmp_path):
    with pytest.raises(TargetPathError) as info:
        validate_target(tmp_path / "missing")
    assert info.value.code is TargetErrorCode.NOT_FOUND


def test_file_is_not_a_directory(tmp_path):
    file = tmp_path / "file.py"
    file.write_text("x = 1\n", encoding="utf-8")

    with pytest.raises(TargetPathError) as info:
        validate_target(file)
    assert info.value.code is TargetErrorCode.NOT_A_DIRECTORY


def test_unreadable_root_is_permission_denied(tmp_path, monkeypatch):
    import auditor.discovery.repository as repository

    def deny(_path):
        raise PermissionError("denied")

    monkeypatch.setattr(repository.os, "scandir", deny)

    with pytest.raises(TargetPathError) as info:
        validate_target(tmp_path)
    assert info.value.code is TargetErrorCode.PERMISSION_DENIED


def test_output_dir_outside_target_is_accepted(tmp_path):
    root = tmp_path / "target"
    root.mkdir()

    assert validate_output_dir(tmp_path / "out", root.resolve()) == (tmp_path / "out").resolve()


@pytest.mark.parametrize("relative", [".", "reports", "deep/nested/reports"])
def test_output_dir_inside_target_is_refused(tmp_path, relative):
    root = (tmp_path / "target").resolve()
    root.mkdir()

    with pytest.raises(TargetPathError) as info:
        validate_output_dir(root / relative, root)
    assert info.value.code is TargetErrorCode.OUTPUT_INSIDE_TARGET


def test_output_dir_with_dotdot_escaping_back_into_target_is_refused(tmp_path):
    root = (tmp_path / "target").resolve()
    root.mkdir()

    with pytest.raises(TargetPathError) as info:
        validate_output_dir(tmp_path / "out" / ".." / "target" / "r", root)
    assert info.value.code is TargetErrorCode.OUTPUT_INSIDE_TARGET


def test_sibling_with_common_prefix_is_not_inside(tmp_path):
    root = (tmp_path / "target").resolve()
    root.mkdir()

    # "target-reports" shares a string prefix with "target" but is not inside it.
    assert validate_output_dir(tmp_path / "target-reports", root)


def test_output_dir_via_junction_into_target_is_refused(tmp_path, junction):
    root = (tmp_path / "target").resolve()
    root.mkdir()
    link = tmp_path / "sneaky"
    junction(link, root)

    with pytest.raises(TargetPathError) as info:
        validate_output_dir(link / "reports", root)
    assert info.value.code is TargetErrorCode.OUTPUT_INSIDE_TARGET
