"""Discovery must work from metadata alone: no file in the target is ever opened."""

import builtins
import io
import os

from auditor.core.policy import ScanPolicy
from auditor.discovery.repository import inspect, validate_target


def test_discovery_never_opens_files(sample_repo, monkeypatch):
    root = validate_target(sample_repo)
    opened = []

    def forbidden(*args, **kwargs):
        opened.append(args[0] if args else kwargs)
        raise AssertionError(f"discovery tried to open a file: {args[:1]}")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(io, "open", forbidden)
    monkeypatch.setattr(os, "open", forbidden)

    result = inspect(root, ScanPolicy())

    monkeypatch.undo()
    assert opened == []
    assert len(result.files) == 8
