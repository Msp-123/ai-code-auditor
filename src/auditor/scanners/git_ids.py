"""Git object ids of content (no git process involved)."""

import hashlib


def git_blob_id(data: bytes, object_format: str) -> str:
    """The id git gives these bytes as a blob: hash of ``b"blob <size>\\0" + data``.

    ``object_format`` is the repository's: "sha1" (default) or "sha256".
    """
    if object_format not in ("sha1", "sha256"):
        raise ValueError(f"unknown object format {object_format!r}")
    algorithm = hashlib.sha256 if object_format == "sha256" else hashlib.sha1
    return algorithm(b"blob %d\0" % len(data) + data).hexdigest()
