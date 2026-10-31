"""The target must be byte-for-byte identical before and after a full CLI scan."""

import hashlib
import os

from typer.testing import CliRunner

from auditor.cli import app


def snapshot(root):
    """Every entry under root (links not followed): type, size, mtime and content hash."""
    state = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in dirnames + filenames:
            path = os.path.join(dirpath, name)
            st = os.lstat(path)
            digest = None
            if os.path.isfile(path) and not os.path.islink(path):
                with open(path, "rb") as handle:
                    digest = hashlib.sha256(handle.read()).hexdigest()
            state[os.path.relpath(path, root)] = (st.st_mode, st.st_size, st.st_mtime_ns, digest)
    return state


def test_full_scan_leaves_target_unchanged(sample_repo, out_dir):
    (sample_repo / ".env").write_text("TOKEN=x\n", encoding="utf-8")
    before = snapshot(sample_repo)

    result = CliRunner().invoke(app, ["scan", str(sample_repo), "--output-dir", str(out_dir)])

    assert result.exit_code == 0, result.output
    assert snapshot(sample_repo) == before


def test_setup_py_is_never_executed(make_tree, out_dir, tmp_path):
    marker = tmp_path / "executed.marker"
    root = make_tree(
        {"setup.py": f"open({str(marker)!r}, 'w').close()\n", "conftest.py": "raise SystemExit"}
    )

    result = CliRunner().invoke(app, ["scan", str(root), "--output-dir", str(out_dir)])

    assert result.exit_code == 0, result.output
    assert not marker.exists()
