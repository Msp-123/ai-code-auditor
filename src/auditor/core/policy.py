"""Scan policy: directory exclusions, sensitive-file patterns and resource limits."""

import unicodedata
from dataclasses import dataclass
from fnmatch import fnmatchcase

from auditor.core.models import ExclusionReason

DEFAULT_MAX_FILES = 50_000

VCS_DIR_NAMES = frozenset({".git", ".hg", ".svn"})

EXCLUDED_DIR_NAMES = frozenset(
    {
        ".venv",
        "venv",
        "env",
        "node_modules",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".nox",
        ".eggs",
        "dist",
        "build",
        "site-packages",
        "reports",
        ".idea",
    }
)
EXCLUDED_DIR_SUFFIXES = (".egg-info",)

# Sensitive files stay in the inventory (so secret scanning can still cover them) but are
# flagged as never allowed into AI context. Patterns are matched against normalize_name().
SENSITIVE_NAME_PATTERNS = (
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.jks",
    "*.keystore",
    "*.kdbx",
    "id_rsa*",
    "id_dsa*",
    "id_ecdsa*",
    "id_ed25519*",
    "credentials*.json",
    "secrets.*",
    ".netrc",
    "_netrc",
    ".pypirc",
    ".npmrc",
    ".htpasswd",
)


def normalize_name(name: str) -> str:
    """Matching key for a file name.

    Invisible format characters (zero-width, bidi controls) are dropped and NFKC + casefold
    applied, so look-alike names such as ``.E\\u200bNV`` or full-width ``．ｅｎｖ`` cannot
    dodge exclusion or sensitivity rules.
    """
    visible = "".join(ch for ch in name if unicodedata.category(ch) != "Cf")
    return unicodedata.normalize("NFKC", visible).casefold()


@dataclass(frozen=True)
class ScanPolicy:
    max_files: int = DEFAULT_MAX_FILES
    max_entries_visited: int = 200_000
    max_depth: int = 64
    max_file_size_bytes: int = 5 * 1024 * 1024
    max_duration_seconds: float = 120.0
    excluded_dir_names: frozenset[str] = EXCLUDED_DIR_NAMES
    sensitive_name_patterns: tuple[str, ...] = SENSITIVE_NAME_PATTERNS

    def __post_init__(self) -> None:
        for name in (
            "max_files",
            "max_entries_visited",
            "max_depth",
            "max_file_size_bytes",
            "max_duration_seconds",
        ):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be positive")

    def directory_exclusion(self, name: str) -> ExclusionReason | None:
        """Name-based exclusion for a directory (virtualenv detection is done by discovery)."""
        key = normalize_name(name)
        if key in VCS_DIR_NAMES:
            return ExclusionReason.VCS_METADATA
        if key in self.excluded_dir_names or key.endswith(EXCLUDED_DIR_SUFFIXES):
            return ExclusionReason.EXCLUDED_DIR
        return None

    def is_sensitive(self, name: str) -> bool:
        key = normalize_name(name)
        return any(fnmatchcase(key, pattern) for pattern in self.sensitive_name_patterns)
