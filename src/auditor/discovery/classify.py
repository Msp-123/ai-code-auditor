"""File categorisation by name and location only (contents are never read)."""

from fnmatch import fnmatchcase
from pathlib import PurePosixPath

from auditor.core.models import FileCategory, FileContext
from auditor.core.policy import normalize_name

MANIFEST_NAMES = frozenset(
    {
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "pipfile",
        "pipfile.lock",
        "poetry.lock",
        "uv.lock",
    }
)
MANIFEST_PATTERNS = ("requirements*.txt", "requirements*.in", "constraints*.txt")
TEST_DIR_NAMES = frozenset({"tests", "test"})
PYTHON_SUFFIXES = (".py", ".pyi")
CONFIG_SUFFIXES = frozenset({".toml", ".cfg", ".ini", ".yaml", ".yml", ".json"})
DOC_SUFFIXES = frozenset({".md", ".rst", ".txt"})
# H6 context markers: exact directory names only ("mytests", "latest" never match).
EXAMPLE_DIR_NAMES = frozenset({"examples", "example", "samples", "sample", "demo", "demos"})
DOC_DIR_NAMES = frozenset({"docs", "doc", "documentation"})
CONTEXT_DOC_SUFFIXES = DOC_SUFFIXES | {".adoc"}
PRODUCTION_BASIS = "no test, docs, examples or config marker"


def classify_context(relative_path: str) -> tuple[FileContext, str]:
    """(context, basis) for any file, from directory names and file-name patterns only.

    Precedence: test directory or test file name > examples directory > docs directory >
    config suffix > docs suffix > production. Path-based, so it is never a security proof:
    production code placed under ``tests/`` is classified as test (same class of limit as
    D-034).
    """
    parts = [normalize_name(p) for p in relative_path.replace("\\", "/").split("/") if p]
    if not parts:
        return FileContext.UNKNOWN, "empty path"
    dirs, name = parts[:-1], parts[-1]
    for directory in dirs:
        if directory in TEST_DIR_NAMES:
            return FileContext.TEST, f"directory '{directory}'"
    if name.startswith("test_") and name.endswith(".py"):
        return FileContext.TEST, "file name 'test_*.py'"
    if name.endswith("_test.py"):
        return FileContext.TEST, "file name '*_test.py'"
    if name == "conftest.py":
        return FileContext.TEST, "file name 'conftest.py'"
    for directory in dirs:
        if directory in EXAMPLE_DIR_NAMES:
            return FileContext.EXAMPLES, f"directory '{directory}'"
    for directory in dirs:
        if directory in DOC_DIR_NAMES:
            return FileContext.DOCS, f"directory '{directory}'"
    suffix = PurePosixPath(name).suffix
    if suffix in CONFIG_SUFFIXES:
        return FileContext.CONFIG, f"file suffix '{suffix}'"
    if suffix in CONTEXT_DOC_SUFFIXES:
        return FileContext.DOCS, f"file suffix '{suffix}'"
    return FileContext.PRODUCTION, PRODUCTION_BASIS


def classify_file(parts: tuple[str, ...]) -> FileCategory:
    """Categorise a file from its path components relative to the scan root."""
    name = normalize_name(parts[-1])
    suffix = PurePosixPath(name).suffix

    if name in MANIFEST_NAMES or any(fnmatchcase(name, p) for p in MANIFEST_PATTERNS):
        return FileCategory.DEPENDENCY_MANIFEST
    if name.endswith(PYTHON_SUFFIXES):
        in_test_dir = any(normalize_name(part) in TEST_DIR_NAMES for part in parts[:-1])
        is_test_name = (
            name.startswith("test_") or name.endswith("_test.py") or name == "conftest.py"
        )
        return FileCategory.TEST if in_test_dir or is_test_name else FileCategory.PYTHON_SOURCE
    if suffix in CONFIG_SUFFIXES:
        return FileCategory.CONFIG
    if suffix in DOC_SUFFIXES:
        return FileCategory.DOC
    return FileCategory.OTHER
