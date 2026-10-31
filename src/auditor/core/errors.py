"""Typed errors raised by the auditor core."""

from enum import StrEnum


class AuditorError(Exception):
    """Base class for expected, user-facing auditor errors."""


class TargetErrorCode(StrEnum):
    INVALID_PATH = "INVALID_PATH"
    NOT_FOUND = "NOT_FOUND"
    NOT_A_DIRECTORY = "NOT_A_DIRECTORY"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    OUTPUT_INSIDE_TARGET = "OUTPUT_INSIDE_TARGET"
    UNSAFE_OUTPUT_DIR = "UNSAFE_OUTPUT_DIR"


class TargetPathError(AuditorError):
    """The scan target or the output location is unusable. Nothing has been written."""

    def __init__(self, code: TargetErrorCode, message: str) -> None:
        super().__init__(message)
        self.code = code


class ReportWriteError(AuditorError):
    """Reports could not be written completely. Partial output is never left looking complete."""
