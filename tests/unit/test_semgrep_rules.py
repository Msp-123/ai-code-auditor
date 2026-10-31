"""Ruleset loading and integrity checks (no Semgrep needed)."""

import json
import shutil

import pytest

from auditor.scanners.semgrep_rules import (
    RULES_DIR,
    RulesetError,
    build_manifest,
    load_ruleset,
    materialize,
)


@pytest.fixture
def rules_copy(tmp_path):
    target = tmp_path / "rules"
    shutil.copytree(RULES_DIR, target)
    return target


def test_shipped_manifest_matches_the_rule_files():
    # Fails when a rule is edited without regenerating MANIFEST.json.
    manifest = json.loads((RULES_DIR / "MANIFEST.json").read_text(encoding="utf-8"))

    assert build_manifest(RULES_DIR, manifest["ruleset_version"]) == manifest


def test_ruleset_loads_with_version_and_digest():
    ruleset = load_ruleset()

    assert ruleset.version
    assert len(ruleset.digest) == 64
    critical = {"command_injection.yaml", "sql_injection.yaml", "path_traversal.yaml", "ssrf.yaml"}
    assert critical <= set(ruleset.files)


def test_modified_rule_file_is_rejected(rules_copy):
    path = rules_copy / "ssrf.yaml"
    path.write_bytes(path.read_bytes().replace(b"severity: ERROR", b"severity: INFO"))

    with pytest.raises(RulesetError, match="ssrf.yaml"):
        load_ruleset(rules_copy)


def test_unexpected_rule_file_is_rejected(rules_copy):
    (rules_copy / "planted.yaml").write_text("rules: []\n", encoding="utf-8")

    with pytest.raises(RulesetError, match="planted.yaml"):
        load_ruleset(rules_copy)


def test_missing_rule_file_is_rejected(rules_copy):
    (rules_copy / "sql_injection.yaml").unlink()

    with pytest.raises(RulesetError, match="sql_injection.yaml"):
        load_ruleset(rules_copy)


def test_missing_manifest_is_rejected(rules_copy):
    (rules_copy / "MANIFEST.json").unlink()

    with pytest.raises(RulesetError, match="MANIFEST"):
        load_ruleset(rules_copy)


def test_materialized_copy_is_byte_identical_and_private(tmp_path):
    ruleset = load_ruleset()

    directory = materialize(ruleset, tmp_path / "work")

    assert directory.parent == tmp_path / "work"
    for name, content in ruleset.files.items():
        assert (directory / name).read_bytes() == content
    assert not (directory / "MANIFEST.json").exists()
