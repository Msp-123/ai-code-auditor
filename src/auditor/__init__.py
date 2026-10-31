"""AI Code Auditor — evidence-based, read-only audit CLI for local Python projects."""

from importlib.metadata import version

# Single source of truth for the version is pyproject.toml.
__version__ = version("ai-code-auditor")
