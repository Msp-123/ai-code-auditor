"""Stable finding identity (master plan §8.6).

Location includes columns and the message, so two different findings on the same line (e.g.
two unused imports) are never collapsed into one.
"""

import hashlib


def compute_fingerprint(
    *,
    tool: str,
    rule_id: str,
    relative_path: str,
    start: tuple[int | None, int | None],
    end: tuple[int | None, int | None],
    message: str,
) -> str:
    parts = [tool, rule_id, relative_path, f"{start[0]}:{start[1]}", f"{end[0]}:{end[1]}", message]
    joined = "\x1f".join(parts)  # unit separator: cannot occur in the inputs' boundaries
    return hashlib.sha256(joined.encode("utf-8", "backslashreplace")).hexdigest()
