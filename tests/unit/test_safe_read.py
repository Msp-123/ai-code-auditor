"""read_regular_file: the bytes of a regular file, or a reason why not (never a link)."""

import os

import pytest

import auditor.scanners.selection as selection
from auditor.core.models import NotAnalyzedReason
from auditor.discovery.repository import extended_length_path
from auditor.scanners.selection import read_regular_file


def test_reads_a_regular_file(tmp_path):
    path = tmp_path / "a.env"
    path.write_bytes(b"KEY=value\r\n")

    result = read_regular_file(str(path), limit=1024)

    assert result.data == b"KEY=value\r\n" and result.reason is None


def test_file_over_the_limit_is_not_read(tmp_path):
    path = tmp_path / "big.bin"
    path.write_bytes(b"x" * 2048)

    result = read_regular_file(str(path), limit=1024)

    assert result.data is None and result.reason is NotAnalyzedReason.SIZE_LIMIT


def test_missing_file_is_an_io_error(tmp_path):
    result = read_regular_file(str(tmp_path / "gone.txt"), limit=1024)

    assert result.data is None and result.reason is NotAnalyzedReason.IO_ERROR


def test_directory_junction_is_refused(tmp_path, junction):
    outside = tmp_path / "outside"
    outside.mkdir()
    junction(tmp_path / "link", outside)

    result = read_regular_file(str(tmp_path / "link"), limit=1024)

    assert result.data is None and result.reason is NotAnalyzedReason.CHANGED_BEFORE_SCAN


def test_file_symlink_is_refused(tmp_path, symlink):
    target = tmp_path / "secret.txt"
    target.write_text("outside", encoding="utf-8")
    symlink(tmp_path / "link.txt", target)

    result = read_regular_file(str(tmp_path / "link.txt"), limit=1024)

    assert result.data is None and result.reason is NotAnalyzedReason.CHANGED_BEFORE_SCAN


def test_file_that_changes_while_being_read_is_refused(tmp_path, monkeypatch):
    path = tmp_path / "a.py"
    path.write_bytes(b"x = 1\n")
    real_fstat = os.fstat
    calls = []

    def fstat(fd):
        st = real_fstat(fd)
        calls.append(1)
        if len(calls) == 2:  # the check after reading sees a different size
            return os.stat_result(
                (
                    st.st_mode,
                    st.st_ino,
                    st.st_dev,
                    st.st_nlink,
                    st.st_uid,
                    st.st_gid,
                    st.st_size + 5,
                    0,
                    st.st_mtime + 1,
                    0,
                )
            )
        return st

    monkeypatch.setattr(selection.os, "fstat", fstat)

    result = read_regular_file(str(path), limit=1024)

    assert result.data is None and result.reason is NotAnalyzedReason.CHANGED_BEFORE_SCAN
    assert "while reading" in result.detail


def test_short_read_is_refused(tmp_path, monkeypatch):
    path = tmp_path / "a.py"
    path.write_bytes(b"0123456789")
    monkeypatch.setattr(selection, "_read_all", lambda fd, n: b"01234")

    result = read_regular_file(str(path), limit=1024)

    assert result.data is None and result.reason is NotAnalyzedReason.CHANGED_BEFORE_SCAN


def test_path_beyond_max_path_is_read(tmp_path):
    deep = os.path.join(extended_length_path(str(tmp_path)), *(["directory_name_x"] * 16))
    os.makedirs(deep)
    with open(os.path.join(deep, "k.env"), "wb") as handle:
        handle.write(b"A=1\n")
    plain = os.path.join(str(tmp_path), *(["directory_name_x"] * 16), "k.env")
    assert len(plain) > 260

    result = read_regular_file(plain, limit=1024)

    assert result.data == b"A=1\n"


@pytest.mark.parametrize("size", [0, 1])
def test_empty_and_tiny_files(tmp_path, size):
    path = tmp_path / "f"
    path.write_bytes(b"z" * size)

    assert read_regular_file(str(path), limit=10).data == b"z" * size
