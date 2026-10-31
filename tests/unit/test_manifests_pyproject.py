"""pyproject.toml declarations checked against a pylock.toml next to it (Stage 5, D-045).

A declaration is "covered" only when it can be verified without evaluating anything about the
target environment: the same-directory lock pins the package from PyPI, the locked version
provably satisfies the declared range, and the lock installs it under the same condition.
Everything else stays a visible gap (PARTIAL), never a silent clean result.
"""

import pytest

from auditor.scanners.manifests import analyze_manifests, satisfies

SHA = "0" * 64


def locked(name, version, marker=None):
    text = f'[[packages]]\nname = "{name}"\nversion = "{version}"\n'
    if marker:
        text += f'marker = "{marker}"\n'
    return text + (
        f'[[packages.wheels]]\nname = "{name}-{version}-py3-none-any.whl"\n'
        f'url = "https://files.pythonhosted.org/p/{name}-{version}-py3-none-any.whl"\n'
        f'hashes = {{sha256 = "{SHA}"}}\n'
    )


def lockfile(*packages, header=""):
    return 'lock-version = "1.0"\ncreated-by = "test"\n' + header + "\n" + "\n".join(packages)


SELF = '[[packages]]\nname = "demo-app"\ndirectory = { path = ".", editable = true }\n'

PYPROJECT = """\
[project]
name = "demo-app"
version = "0.1"
dependencies = [
    "Jinja2>=2.10,<3",
    "urllib3==1.24.1",
    "tomli>=1; python_version < '3.11'",
]

[project.optional-dependencies]
yaml = ["pyyaml~=5.3"]

[dependency-groups]
dev = ["packaging==24.*", {include-group = "docs"}]
docs = []
"""

FULL_LOCK = lockfile(
    SELF,
    locked("jinja2", "2.10"),
    locked("urllib3", "1.24.1"),
    locked("tomli", "2.0.1", "python_version < '3.11'"),  # same condition as declared
    locked("pyyaml", "5.3", "'yaml' in extras"),
    locked("packaging", "24.2", "'dev' in dependency_groups"),
)


def analyze(make_tree, files):
    root = make_tree(files)
    paths = set()

    def collect(prefix, spec):
        for name, value in spec.items():
            if isinstance(value, dict):
                collect(f"{prefix}{name}/", value)
            else:
                paths.add(prefix + name)

    collect("", files)
    return {r.file: r for r in analyze_manifests(root, paths)}


def reasons(result):
    return sorted((g.reason, g.line) for g in result.gaps)


# ---------------------------------------------------------------- the three requested scenarios


def test_unpinned_declarations_without_a_lock_file_are_not_audited(make_tree):
    results = analyze(make_tree, {"pyproject.toml": PYPROJECT})

    project = results["pyproject.toml"]
    assert project.fatal and [g.reason for g in project.gaps] == ["NOT_LOCKED"]
    assert "pylock.toml" in project.gaps[0].detail


def test_declarations_fully_covered_by_the_lock_file_are_not_partial(make_tree):
    results = analyze(make_tree, {"pyproject.toml": PYPROJECT, "pylock.toml": FULL_LOCK})

    project, lock = results["pyproject.toml"], results["pylock.toml"]
    assert not project.fatal and project.gaps == []
    assert any("5 declared dependencies are locked" in n for n in project.notes)
    # the project itself (directory ".") is not a third-party dependency: no gap, a note
    assert lock.gaps == [] and any("the project itself" in n for n in lock.notes)
    assert sorted(p.name for p in lock.pins) == ["jinja2", "packaging", "pyyaml", "tomli",
                                                 "urllib3"]  # fmt: skip


def test_missing_and_conflicting_declarations_stay_visible(make_tree):
    lock = lockfile(
        SELF,
        locked("jinja2", "3.1.4"),  # conflicts with >=2.10,<3
        locked("tomli", "2.0.1", "python_version < '3.11'"),
        locked("pyyaml", "5.3", "'yaml' in extras"),
        locked("packaging", "24.2", "'dev' in dependency_groups"),
    )  # urllib3 is missing

    results = analyze(make_tree, {"pyproject.toml": PYPROJECT, "pylock.toml": lock})

    project = results["pyproject.toml"]
    assert not project.fatal  # the covered ones are still audited through the lock
    assert reasons(project) == [("LOCK_CONFLICT", 5), ("LOCK_MISSING", 6)]
    details = " ".join(g.detail for g in project.gaps)
    assert "(jinja2)" in details and "(urllib3)" in details


# ------------------------------------------------------------------ what cannot be verified


@pytest.mark.parametrize(
    ("declaration", "lock_entry", "reason"),
    [
        ('"jinja2>=2.10"', locked("jinja2", "2.10", "sys_platform == 'linux'"),
         "LOCK_CONDITION_UNVERIFIED"),  # lock installs it only on Linux
        ("\"jinja2>=2.10; python_version < '3.11'\"", locked("jinja2", "2.10"),
         "LOCK_CONDITION_UNVERIFIED"),  # declared conditionally, locked unconditionally
        ('"jinja2>=2.10"', locked("jinja2", "2.11.0rc1"), "LOCK_RANGE_UNVERIFIED"),
        ('"jinja2>=2.10.dev0"', locked("jinja2", "2.10"), "LOCK_RANGE_UNVERIFIED"),
        ('"jinja2===2.10"', locked("jinja2", "2.10"), "LOCK_RANGE_UNVERIFIED"),
        ('"jinja2 @ https://example.invalid/j.whl"', locked("jinja2", "2.10"), "URL"),
        ('"not a requirement!"', locked("jinja2", "2.10"), "INVALID"),
    ],
)  # fmt: skip
def test_unverifiable_coverage_is_a_gap(make_tree, declaration, lock_entry, reason):
    project = f"[project]\nname = 'x'\ndependencies = [\n  {declaration},\n]\n"
    results = analyze(make_tree, {"pyproject.toml": project, "pylock.toml": lockfile(lock_entry)})

    assert reasons(results["pyproject.toml"]) == [(reason, 4)]


def test_a_lock_restricted_to_declared_environments_is_not_full_coverage(make_tree):
    restricted = "environments = [\"sys_platform == 'linux'\"]\n"
    lock = lockfile(locked("jinja2", "2.10"), header=restricted)
    project = "[project]\nname = 'x'\ndependencies = ['jinja2>=2.10']\n"

    results = analyze(make_tree, {"pyproject.toml": project, "pylock.toml": lock})

    assert reasons(results["pyproject.toml"]) == [("LOCK_ENVIRONMENT_UNVERIFIED", None)]


def test_a_dependency_installed_only_for_a_group_does_not_cover_the_main_dependencies(make_tree):
    lock = lockfile(locked("jinja2", "2.10", "'dev' in dependency_groups"))
    project = "[project]\nname = 'x'\ndependencies = ['jinja2>=2.10']\n"

    results = analyze(make_tree, {"pyproject.toml": project, "pylock.toml": lock})

    assert [g.reason for g in results["pyproject.toml"].gaps] == ["LOCK_CONDITION_UNVERIFIED"]


def test_dynamic_dependencies_are_never_computed(make_tree):
    project = "[project]\nname = 'x'\ndynamic = ['dependencies']\n"
    results = analyze(make_tree, {"pyproject.toml": project, "pylock.toml": FULL_LOCK})

    assert results["pyproject.toml"].fatal
    assert [g.reason for g in results["pyproject.toml"].gaps] == ["DYNAMIC"]


@pytest.mark.parametrize(
    "files",
    [
        {"pyproject.toml": PYPROJECT, "sub": {"pylock.toml": FULL_LOCK}},  # other directory
        {"pyproject.toml": PYPROJECT, "pylock.toml": 'lock-version = "2.0"\n'},  # unusable
        {"pyproject.toml": PYPROJECT, "pylock.toml": "not = [toml\n"},
    ],
)
def test_only_a_valid_lock_in_the_same_directory_counts(make_tree, files):
    results = analyze(make_tree, files)

    assert results["pyproject.toml"].fatal
    assert [g.reason for g in results["pyproject.toml"].gaps] == ["NOT_LOCKED"]


def test_poetry_declarations_remain_unsupported_even_with_a_lock(make_tree):
    project = "[tool.poetry.dependencies]\npython = '^3.11'\njinja2 = '^2.10'\n"
    results = analyze(make_tree, {"pyproject.toml": project, "pylock.toml": FULL_LOCK})

    assert [g.reason for g in results["pyproject.toml"].gaps] == ["UNSUPPORTED_FORMAT"]


@pytest.mark.parametrize(
    "self_entry",
    [
        '[[packages]]\nname = "other-app"\ndirectory = { path = "." }\n',  # different name
        '[[packages]]\nname = "demo-app"\ndirectory = { path = "../elsewhere" }\n',
    ],
)
def test_only_the_project_itself_is_exempt_from_the_directory_gap(make_tree, self_entry):
    results = analyze(make_tree, {"pyproject.toml": "[project]\nname = 'demo-app'\n",
                                  "pylock.toml": lockfile(self_entry)})  # fmt: skip

    assert [g.reason for g in results["pylock.toml"].gaps] == ["DIRECTORY"]


def test_hostile_declaration_text_is_never_echoed(make_tree):
    token = "tok" + "en-" + "Qw81"
    project = (
        "[project]\nname = 'x'\ndependencies = [\n"
        f"  'pkg @ https://u:{token}@private.invalid/p.whl',\n  \"evil\\u001b[31m>=1\",\n]\n"
    )
    results = analyze(make_tree, {"pyproject.toml": project, "pylock.toml": lockfile()})

    text = repr(results["pyproject.toml"])
    assert token not in text and "private.invalid" not in text and "\x1b" not in text


# ------------------------------------------------------------- the version-range subset check


@pytest.mark.parametrize(
    ("version", "spec", "expected"),
    [
        ("2.10", "", True),
        ("2.10", ">=2.10,<3", True),
        ("3.0", ">=2.10,<3", False),
        ("2.10.0", "==2.10", True),  # zero padding
        ("2.10", "!=2.10.0", False),
        ("1.24.1", "==1.24.*", True),
        ("1.25", "==1.24.*", False),
        ("1.24", "!=1.24.*", False),
        ("1", "==1.0.*", True),
        ("5.3.1", "~=5.3", True),
        ("6.0", "~=5.3", False),
        ("5.3.2", "~=5.3.1", True),
        ("5.4", "~=5.3.1", False),
        ("24.2", "> 24.1", True),
        ("24.2", "(>=24)", True),
        ("2.10", ">=2.10.dev0", None),  # pre/dev/post/local/epoch: not in the subset
        ("2.11rc1", ">=2.10", None),
        ("2.10+local", ">=2.10", None),
        ("2.10", "===2.10", None),
        ("2.10", "~=2", None),  # invalid per PEP 440
        ("2.10", ">=2.*", None),
        ("3.0", ">=2.10.dev0,<3", False),  # a definite "no" wins over "not verifiable"
    ],
)
def test_satisfies_is_a_conservative_pep440_subset(version, spec, expected):
    assert satisfies(version, spec) is expected
