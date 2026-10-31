import pytest

from auditor.core.models import ExclusionReason
from auditor.core.policy import ScanPolicy, normalize_name

policy = ScanPolicy()


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        (".git", ExclusionReason.VCS_METADATA),
        (".GIT", ExclusionReason.VCS_METADATA),
        (".hg", ExclusionReason.VCS_METADATA),
        (".venv", ExclusionReason.EXCLUDED_DIR),
        ("Node_Modules", ExclusionReason.EXCLUDED_DIR),
        ("__pycache__", ExclusionReason.EXCLUDED_DIR),
        ("my_pkg.egg-info", ExclusionReason.EXCLUDED_DIR),
        ("ｎｏｄｅ＿ｍｏｄｕｌｅｓ", ExclusionReason.EXCLUDED_DIR),  # full-width look-alike
        ("src", None),
        ("tests", None),
        ("environment", None),
    ],
)
def test_directory_exclusion(name, expected):
    assert policy.directory_exclusion(name) is expected


@pytest.mark.parametrize(
    "name",
    [
        ".env",
        ".ENV",
        ".env.local",
        ".env.production",
        "server.pem",
        "private.KEY",
        "id_rsa",
        "id_ed25519.pub",
        "credentials.json",
        "secrets.yaml",
        ".netrc",
        ".pypirc",
        ".e​nv",  # zero-width space inside the name
        "‮.env",  # bidi override prefix
        "．ｅｎｖ",  # full-width look-alike
    ],
)
def test_sensitive_names(name):
    assert policy.is_sensitive(name)


@pytest.mark.parametrize(
    "name", ["main.py", "environment.py", "envoy.py", "key_utils.py", "README.md", "env.py"]
)
def test_non_sensitive_names(name):
    assert not policy.is_sensitive(name)


def test_normalize_name_keeps_turkish_letters_comparable():
    assert normalize_name("ÇİĞÖŞÜ.py") == "çi̇ğöşü.py"


@pytest.mark.parametrize(
    "field",
    [
        "max_files",
        "max_entries_visited",
        "max_depth",
        "max_file_size_bytes",
        "max_duration_seconds",
    ],
)
@pytest.mark.parametrize("value", [0, -1])
def test_policy_rejects_non_positive_limits(field, value):
    with pytest.raises(ValueError, match=field):
        ScanPolicy(**{field: value})
