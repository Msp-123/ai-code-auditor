"""Release preparation: licence files and package metadata that ship with the public release.

The licence text must be the official Apache-2.0 text, unchanged; third-party notices must
name the copied Gitleaks rule files; pyproject declares the licence in SPDX form (PEP 639)
and lists the licence files so they land in the package metadata.
"""

import hashlib
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
# sha256 of https://www.apache.org/licenses/LICENSE-2.0.txt (official text, LF line endings)
APACHE_2_0_SHA256 = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"
GITLEAKS_RULE_COPIES = (
    "path-freemius-secret-key.toml",
    "path-hashicorp-tf-password.toml",
    "path-kubernetes-secret-yaml.toml",
    "path-nuget-config-password.toml",
)


def test_license_is_the_official_apache_2_0_text_unchanged():
    data = (ROOT / "LICENSE").read_bytes()
    assert hashlib.sha256(data).hexdigest() == APACHE_2_0_SHA256
    text = data.decode("utf-8")
    assert "Apache License" in text and "Version 2.0, January 2004" in text
    assert "[name of copyright owner]" in text  # the appendix placeholder, never filled in by us


def test_third_party_notices_cover_the_copied_gitleaks_rules():
    text = (ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
    assert "gitleaks" in text.lower() and "8.30.1" in text and "MIT License" in text
    for name in GITLEAKS_RULE_COPIES:
        assert name in text
    assert "Permission is hereby granted, free of charge" in text  # the MIT text itself
    # each copied rule file already names its origin (pinned Gitleaks 8.30.1 default config);
    # the files themselves are hash-pinned (D-043), so the licence text lives in the notices
    for name in GITLEAKS_RULE_COPIES:
        header = (ROOT / "src/auditor/rules/gitleaks" / name).read_text(encoding="utf-8")
        assert "gitleaks" in header.lower() and "8.30.1" in header and "verbatim copy" in header


def test_pyproject_declares_the_licence_in_spdx_form_with_licence_files():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    # PEP 639 expression, not a table. The published packages contain the project (Apache-2.0)
    # and the four copied Gitleaks rules (MIT), so the distribution is under both.
    assert project["license"] == "Apache-2.0 AND MIT"
    assert set(project["license-files"]) == {"LICENSE", "THIRD_PARTY_NOTICES.md"}
    assert "authors" not in project  # never invented; the user decides
    assert project["requires-python"] == ">=3.12"  # only the verified version is claimed
    classifiers = project["classifiers"]
    assert "Programming Language :: Python :: 3.12" in classifiers  # the verified version
    assert not any(c.startswith("License ::") for c in classifiers)  # PEP 639: expression only
    assert "urls" not in project  # no public repository exists yet


def test_hatchling_build_backend_supports_pep_639():
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert re.search(r'requires = \["hatchling>=1\.27', text), (
        "PEP 639 licence metadata needs hatchling >= 1.27"
    )


RELEASE_VERSION = "0.1.1"


def test_release_version_is_declared_once_and_documented():
    """pyproject.toml is the single version source; README and CHANGELOG follow it."""
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert project["version"] == RELEASE_VERSION
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert f"Version {RELEASE_VERSION}" in readme
    assert f"ai_code_auditor-{RELEASE_VERSION}-py3-none-any.whl" in readme
    assert "ai_code_auditor-0.1.0-py3-none-any.whl" not in readme
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert f"## {RELEASE_VERSION} " in changelog
    # the 0.1.0 entry is history and stays
    assert "## 0.1.0 " in changelog
    # the package reads the version from the installed metadata, never from a literal
    init = (ROOT / "src/auditor/__init__.py").read_text(encoding="utf-8")
    assert 'version("ai-code-auditor")' in init
    assert RELEASE_VERSION not in init
