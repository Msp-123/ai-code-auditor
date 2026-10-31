"""H6: one path-based file context for every finding (production / test / docs / examples /
config / unknown), with the basis stated. Path-based: never a security proof (D-034)."""

import pytest

from auditor.core.models import FileContext
from auditor.discovery.classify import classify_context

CASES = [
    ("src/app/main.py", FileContext.PRODUCTION, "no test, docs, examples or config marker"),
    ("app.py", FileContext.PRODUCTION, "no test, docs, examples or config marker"),
    ("tests/test_main.py", FileContext.TEST, "directory 'tests'"),
    ("test/unit/helpers.py", FileContext.TEST, "directory 'test'"),
    ("src/pkg/test_helpers.py", FileContext.TEST, "file name 'test_*.py'"),
    ("src/pkg/helpers_test.py", FileContext.TEST, "file name '*_test.py'"),
    ("src/conftest.py", FileContext.TEST, "file name 'conftest.py'"),
    ("tests/fixtures/settings.toml", FileContext.TEST, "directory 'tests'"),  # any file type
    ("examples/tutorial/flaskr/__init__.py", FileContext.EXAMPLES, "directory 'examples'"),
    ("examples/tutorial/tests/conftest.py", FileContext.TEST, "directory 'tests'"),  # test wins
    ("docs/config.rst", FileContext.DOCS, "directory 'docs'"),
    ("CHANGES.rst", FileContext.DOCS, "file suffix '.rst'"),
    ("README.md", FileContext.DOCS, "file suffix '.md'"),
    ("pyproject.toml", FileContext.CONFIG, "file suffix '.toml'"),
    ("deploy/settings.yaml", FileContext.CONFIG, "file suffix '.yaml'"),
    ("docs/conf.py", FileContext.DOCS, "directory 'docs'"),  # docs directory beats suffix
    ("", FileContext.UNKNOWN, "empty path"),
]


@pytest.mark.parametrize(
    ("path", "context", "basis"), CASES, ids=[c[0] or "<empty>" for c in CASES]
)
def test_context_and_basis(path, context, basis):
    assert classify_context(path) == (context, basis)


@pytest.mark.parametrize(
    "path",
    [
        "mytests/app.py",
        "contest/app.py",
        "tests.py",
        "src/testing_tools.py",
        "latest/app.py",
        "documents/app.py",
        "exampleapp/main.py",
    ],  # fmt: skip
)
def test_only_exact_directory_names_and_file_patterns_count(path):
    """Substrings such as 'test' inside other words must not change the context."""
    assert classify_context(path)[0] is FileContext.PRODUCTION


def test_matching_is_case_and_lookalike_insensitive():
    assert classify_context("Tests/App.py")[0] is FileContext.TEST
    assert classify_context("DOCS/Guide.RST")[0] is FileContext.DOCS
    assert classify_context("te​sts/app.py")[0] is FileContext.TEST  # zero-width space


def test_windows_separators_are_accepted():
    assert classify_context("tests\\unit\\test_a.py")[0] is FileContext.TEST
