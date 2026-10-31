"""Secret values (in contents or in file names) must not reach any output."""

import secrets

from typer.testing import CliRunner

from auditor.cli import app


def outputs(result, out_dir):
    run_dir = next(out_dir.iterdir())
    return {
        "stdout+stderr": result.output,
        "inventory.json": (run_dir / "inventory.json").read_text(encoding="utf-8"),
        "report.md": (run_dir / "report.md").read_text(encoding="utf-8"),
    }


def test_secret_file_contents_never_appear_in_outputs(make_tree, out_dir):
    token = "FAKE" + secrets.token_hex(16)  # generated at runtime, never committed
    root = make_tree(
        {
            ".env": f"API_KEY={token}\n",
            "config.py": f"PASSWORD = '{token}'\n",
            "keys": {"server.pem": f"-----BEGIN FAKE-----\n{token}\n"},
        }
    )

    result = CliRunner().invoke(app, ["scan", str(root), "--output-dir", str(out_dir)])

    assert result.exit_code == 0, result.output
    for where, text in outputs(result, out_dir).items():
        assert token not in text, f"secret leaked into {where}"


def test_secret_looking_file_name_is_redacted_everywhere(make_tree, out_dir):
    fake_key_name = "AKIA" + "ABCDEFGHIJKLMNOP"  # split so no literal exists in the repo
    root = make_tree({f"{fake_key_name}.txt": "", "app.py": ""})

    result = CliRunner().invoke(app, ["scan", str(root), "--output-dir", str(out_dir)])

    assert result.exit_code == 0, result.output
    texts = outputs(result, out_dir)
    for where, text in texts.items():
        assert fake_key_name not in text, f"secret-like name leaked into {where}"
    assert "<redacted:" in texts["inventory.json"]
    assert "secret-looking names and are redacted" in texts["report.md"]


def test_sensitive_files_are_marked_not_for_ai_in_json(make_tree, out_dir):
    import json

    root = make_tree({".env.production": "X=1\n", "app.py": ""})

    CliRunner().invoke(app, ["scan", str(root), "--output-dir", str(out_dir)])
    data = json.loads((next(out_dir.iterdir()) / "inventory.json").read_text(encoding="utf-8"))
    env = next(f for f in data["files"] if f["relative_path"] == ".env.production")

    assert env["is_sensitive"] is True
    assert env["ai_context_allowed"] is False
    assert env["secret_scan_eligible"] is True
