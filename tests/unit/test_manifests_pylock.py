"""pylock.toml (PEP 751) parsing and manifest discovery (Stage 5).

``pip-audit --locked`` is not used: measured in step 0, it reads the target directory itself and
reports a local ``directory`` package as "0 vulnerabilities".
"""

import pytest

from auditor.scanners.manifests import analyze_manifests, manifest_kind, parse_pylock

SHA = "0" * 64
TOKEN = "tok" + "en-" + "Zx81Q"  # assembled at runtime; must never be echoed


def wheel(name, version, host="https://files.pythonhosted.org/packages/x"):
    return (
        f'[[packages.wheels]]\nname = "{name}-{version}-py3-none-any.whl"\n'
        f'url = "{host}/{name}-{version}-py3-none-any.whl"\nhashes = {{sha256 = "{SHA}"}}\n'
    )


def lock(*packages, header='lock-version = "1.0"\ncreated-by = "test"\n'):
    return header + "\n" + "\n".join(packages)


def package(name, version=None, extra="", body=""):
    text = f'[[packages]]\nname = "{name}"\n'
    if version:
        text += f'version = "{version}"\n'
    return text + extra + body


def summary(result):
    pins = sorted((p.name, p.version, p.line, p.marker) for p in result.pins)
    gaps = sorted((g.reason, g.line) for g in result.gaps)
    return pins, gaps


def test_pypi_packages_are_pinned_with_markers_kept():
    text = lock(
        package("Jinja2", "2.10", body=wheel("jinja2", "2.10")),
        package(
            "urllib3",
            "1.24.1",
            "marker = \"sys_platform == 'linux'\"\n",
            wheel("urllib3", "1.24.1"),
        ),  # fmt: skip
        package(
            "pyyaml",
            "5.3",
            'index = "https://pypi.org/simple"\n',
            '[packages.sdist]\nname = "PyYAML-5.3.tar.gz"\n'
            'url = "https://files.pythonhosted.org/p/PyYAML-5.3.tar.gz"\n'
            f'hashes = {{sha256 = "{SHA}"}}\n',
        ),  # fmt: skip
    )

    pins, gaps = summary(parse_pylock(text, "pylock.toml"))

    assert pins == [
        ("jinja2", "2.10", 4, None),
        ("pyyaml", "5.3", 21, None),
        ("urllib3", "1.24.1", 12, "sys_platform == 'linux'"),
    ]
    assert gaps == []


@pytest.mark.parametrize(
    ("body", "reason"),
    [
        ('vcs = {type = "git", url = "https://example.invalid/x.git", commit-id = "abc"}\n', "VCS"),
        ('directory = {path = "."}\n', "DIRECTORY"),
        ('archive = {url = "https://example.invalid/x.zip", hashes = {sha256 = "0"}}\n', "ARCHIVE"),
        ('[packages.sdist]\npath = "dist/x-1.0.tar.gz"\nhashes = {sha256 = "0"}\n', "LOCAL_PATH"),
        (wheel("x", "1.0", host=f"https://user:{TOKEN}@private.invalid/p"), "NON_PYPI_SOURCE"),
        (
            f'index = "https://{TOKEN}@private.invalid/simple"\n' + wheel("x", "1.0"),
            "NON_PYPI_SOURCE",
        ),  # fmt: skip
        ("", "NO_SOURCE"),
    ],
)
def test_unverifiable_sources_are_gaps_never_pins(body, reason):
    text = lock(package("x", "1.0", body=body))

    result = parse_pylock(text, "pylock.toml")

    assert result.pins == []
    assert [(g.reason, g.line) for g in result.gaps] == [(reason, 4)]
    assert TOKEN not in repr(result) and "private.invalid" not in repr(result)


def test_package_without_version_is_a_gap():
    result = parse_pylock(lock(package("x", body=wheel("x", "1.0"))), "pylock.toml")

    assert [g.reason for g in result.gaps] == ["NO_VERSION"]


def test_same_package_in_two_versions_is_kept_twice():
    text = lock(
        package("jinja2", "2.10", "marker = \"python_version < '3.8'\"\n", wheel("jinja2", "2.10")),
        package(
            "jinja2", "3.1.4", "marker = \"python_version >= '3.8'\"\n", wheel("jinja2", "3.1.4")
        ),  # fmt: skip
    )

    pins, _ = summary(parse_pylock(text, "pylock.toml"))

    assert [(n, v) for n, v, _, _ in pins] == [("jinja2", "2.10"), ("jinja2", "3.1.4")]


def test_extras_and_dependency_groups_are_noted():
    header = (
        'lock-version = "1.0"\ncreated-by = "t"\nextras = ["socks"]\n'
        'dependency-groups = ["dev", "docs"]\ndefault-groups = ["dev"]\n'
    )
    text = lock(
        package("pysocks", "1.7.1", "marker = \"'socks' in extras\"\n", wheel("pysocks", "1.7.1")),
        header=header,
    )

    result = parse_pylock(text, "pylock.toml")

    assert result.pins[0].marker == "'socks' in extras"
    assert "lock file defines extras: socks" in result.notes
    assert "lock file defines dependency groups: dev, docs" in result.notes


@pytest.mark.parametrize(
    ("text", "reason"),
    [
        ("not = [valid", "INVALID_FILE"),
        ('lock-version = "2.0"\n', "UNSUPPORTED_VERSION"),
        ("created-by = 'x'\n", "UNSUPPORTED_VERSION"),
    ],  # fmt: skip
)
def test_broken_or_unsupported_lock_files_are_fatal(text, reason):
    result = parse_pylock(text, "pylock.toml")

    assert result.fatal and [g.reason for g in result.gaps] == [reason]


@pytest.mark.parametrize(
    ("path", "kind"),
    [
        ("requirements.txt", "requirements"),
        ("requirements-dev.txt", "requirements"),
        ("requirements.in", "requirements"),
        ("requirements/base.txt", "requirements"),
        ("constraints.txt", "constraints"),
        ("pylock.toml", "pylock"),
        ("pylock.prod.toml", "pylock"),
        ("sub/pyproject.toml", "pyproject"),
        ("setup.py", "setup.py"),
        ("setup.cfg", "setup.cfg"),
        ("poetry.lock", "unsupported"),
        ("uv.lock", "unsupported"),
        ("Pipfile.lock", "unsupported"),
        ("README.txt", None),
        ("docs/notes.txt", None),
    ],
)
def test_manifest_kinds(path, kind):
    assert manifest_kind(path) == kind


def test_discovery_reports_supported_unsupported_and_declaration_free_files(make_tree):
    files = {
        "requirements.txt": "jinja2==2.10\n",
        "constraints.txt": "jinja2==2.10\n",
        "pyproject.toml": "[tool.ruff]\nline-length = 100\n",  # tool config only
        "app": {"pyproject.toml": "[project]\nname = 'a'\ndependencies = ['requests>=2']\n"},
        "setup.py": "raise SystemExit('must never run')\n",
        "setup.cfg": "[options]\ninstall_requires =\n    click>=8\n",
        "poetry.lock": "[[package]]\nname = 'x'\nversion = '1'\n",
        "pylock.toml": lock(package("urllib3", "1.24.1", body=wheel("urllib3", "1.24.1"))),
    }
    root = make_tree(files)
    inventory = {"requirements.txt", "constraints.txt", "pyproject.toml", "app/pyproject.toml",
                 "setup.py", "setup.cfg", "poetry.lock", "pylock.toml"}  # fmt: skip

    results = {r.file: r for r in analyze_manifests(root, inventory)}

    assert set(results) == inventory - {"constraints.txt"}  # constraints only via -c
    assert [p.name for p in results["requirements.txt"].pins] == ["jinja2"]
    assert [p.name for p in results["pylock.toml"].pins] == ["urllib3"]
    assert not results["pyproject.toml"].fatal and results["pyproject.toml"].gaps == []
    for name, reason in (("app/pyproject.toml", "NOT_LOCKED"),
                         ("setup.cfg", "UNSUPPORTED_FORMAT"), ("setup.py", "NOT_EXECUTED"),
                         ("poetry.lock", "UNSUPPORTED_FORMAT")):  # fmt: skip
        assert results[name].fatal and [g.reason for g in results[name].gaps] == [reason], name
    assert (root / "setup.py").read_text(encoding="utf-8").startswith("raise")  # never run
