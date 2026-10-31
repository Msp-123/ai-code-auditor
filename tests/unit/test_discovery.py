import os

import pytest

from auditor.core.models import ExclusionReason, FileCategory
from auditor.core.policy import ScanPolicy
from auditor.discovery.repository import inspect, validate_target


def run(root, **policy):
    return inspect(validate_target(root), ScanPolicy(**policy))


def paths(result):
    return [f.relative_path for f in result.files]


def excluded(result):
    return {e.relative_path: e.reason for e in result.excluded}


def test_sample_repository_inventory(sample_repo):
    result = run(sample_repo)

    assert paths(result) == [
        "README.md",
        "pyproject.toml",
        "requirements.txt",
        "setup.py",
        "src/app/__init__.py",
        "src/app/main.py",
        "tests/conftest.py",
        "tests/test_main.py",
    ]
    categories = {f.relative_path: f.category for f in result.files}
    assert categories["src/app/main.py"] is FileCategory.PYTHON_SOURCE
    assert categories["tests/test_main.py"] is FileCategory.TEST
    assert categories["tests/conftest.py"] is FileCategory.TEST
    assert categories["requirements.txt"] is FileCategory.DEPENDENCY_MANIFEST
    assert categories["setup.py"] is FileCategory.DEPENDENCY_MANIFEST
    assert categories["pyproject.toml"] is FileCategory.DEPENDENCY_MANIFEST
    assert categories["README.md"] is FileCategory.DOC
    assert excluded(result) == {
        ".git": ExclusionReason.VCS_METADATA,
        ".venv": ExclusionReason.VIRTUALENV,
        "__pycache__": ExclusionReason.EXCLUDED_DIR,
        "node_modules": ExclusionReason.EXCLUDED_DIR,
    }
    assert result.vcs_metadata == [".git"]
    assert result.incomplete_reasons == []


def test_excluded_directories_are_not_descended(sample_repo):
    result = run(sample_repo)

    for path in [*paths(result), *excluded(result)]:
        assert not path.startswith((".git/", ".venv/", "node_modules/", "__pycache__/"))


def test_case_variants_of_excluded_directories(make_tree):
    root = make_tree({"Node_Modules": {"a.js": ""}, "__PYCACHE__": {"x.pyc": ""}, "a.py": ""})

    result = run(root)

    assert paths(result) == ["a.py"]
    assert set(excluded(result).values()) == {ExclusionReason.EXCLUDED_DIR}


def test_virtualenv_with_custom_name_is_detected(make_tree):
    root = make_tree({"myenv312": {"pyvenv.cfg": "home = x\n", "lib.py": ""}, "app.py": ""})

    result = run(root)

    assert paths(result) == ["app.py"]
    assert excluded(result) == {"myenv312": ExclusionReason.VIRTUALENV}


def test_nested_excluded_directories(make_tree):
    root = make_tree({"pkg": {"sub": {"__pycache__": {"m.pyc": ""}, "m.py": ""}}})

    result = run(root)

    assert paths(result) == ["pkg/sub/m.py"]
    assert excluded(result) == {"pkg/sub/__pycache__": ExclusionReason.EXCLUDED_DIR}


def test_nested_git_dir_is_excluded_but_only_root_is_recorded_as_vcs(make_tree):
    root = make_tree({"vendor": {"lib": {".git": {"HEAD": ""}, "x.py": ""}}})

    result = run(root)

    assert excluded(result) == {"vendor/lib/.git": ExclusionReason.VCS_METADATA}
    assert result.vcs_metadata == []


def test_git_file_pointer_is_vcs_metadata(make_tree):
    root = make_tree({".git": "gitdir: ../.git/worktrees/x\n", "a.py": ""})

    result = run(root)

    assert paths(result) == ["a.py"]
    assert excluded(result) == {".git": ExclusionReason.VCS_METADATA}
    assert result.vcs_metadata == [".git"]


def test_sensitive_files_stay_in_inventory_with_flags(make_tree):
    root = make_tree({".env": "X=1\n", "certs": {"server.pem": "x"}, "app.py": ""})

    result = run(root)
    by_path = {f.relative_path: f for f in result.files}

    for path in (".env", "certs/server.pem"):
        entry = by_path[path]
        assert entry.is_sensitive
        assert not entry.ai_context_allowed
        assert entry.secret_scan_eligible  # never hidden from future secret scanning
    assert by_path["app.py"].ai_context_allowed
    assert ".env" not in excluded(result)


def test_oversized_file_is_listed_and_flagged(make_tree):
    root = make_tree({"big.bin": b"x" * 2048, "small.py": "x"})

    result = run(root, max_file_size_bytes=1024)
    by_path = {f.relative_path: f for f in result.files}

    assert by_path["big.bin"].oversized
    assert not by_path["big.bin"].ai_context_allowed
    assert by_path["big.bin"].size_bytes == 2048
    assert not by_path["small.py"].oversized
    assert result.incomplete_reasons == []  # oversized is a flag, not missing coverage


def test_empty_repository(tmp_path):
    (tmp_path / "empty").mkdir()

    result = run(tmp_path / "empty")

    assert result.files == []
    assert result.excluded == []
    assert result.incomplete_reasons == []


def test_relative_paths_use_forward_slashes(make_tree):
    root = make_tree({"a": {"b": {"c.py": ""}}})

    assert paths(run(root)) == ["a/b/c.py"]


def test_inventory_is_deterministic(sample_repo):
    first, second = run(sample_repo), run(sample_repo)

    assert first.files == second.files
    assert first.excluded == second.excluded


def test_unicode_file_names(make_tree):
    names = ["çalışma_ğüş.py", "İstanbul.py", "日本語.py", "🚀rocket.py", "naïve.py"]
    root = make_tree({name: "" for name in names})

    assert sorted(paths(run(root))) == sorted(names)


@pytest.mark.skipif(os.name == "nt", reason="FIFOs do not exist on Windows")
def test_special_files_are_excluded(tmp_path):
    root = tmp_path / "target"
    root.mkdir()
    os.mkfifo(root / "pipe")

    result = run(root)

    assert excluded(result) == {"pipe": ExclusionReason.SPECIAL_FILE}


@pytest.mark.skipif(os.name == "nt", reason="undecodable byte names are a POSIX concern")
def test_undecodable_file_name_is_escaped(tmp_path):
    root = tmp_path / "target"
    root.mkdir()
    (root / os.fsdecode(b"bad\xff.py")).write_text("", encoding="utf-8")

    result = run(root)

    assert paths(result) == ["bad\\udcff.py"]
    assert any("not valid Unicode" in w for w in result.warnings)
