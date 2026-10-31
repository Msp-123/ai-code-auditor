import hashlib
import secrets

import pytest

from auditor.core.redaction import (
    looks_like_secret,
    redact_path,
    redact_text,
    sanitize_for_display,
)
from auditor.reports.markdown_report import md_code

# Built at runtime so this repository never contains secret-like literals.
FAKE_AWS = "AKIA" + "ABCDEFGHIJKLMNOP"
FAKE_GITHUB = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"


@pytest.mark.parametrize(
    "segment",
    [
        FAKE_AWS,
        f"{FAKE_AWS}.txt",
        FAKE_GITHUB,
        "sk-" + "x" * 24,
        "backup_" + secrets.token_urlsafe(32) + ".json",
        hashlib.sha1(b"example", usedforsecurity=False).hexdigest(),  # 40-char hex
    ],
)
def test_secret_like_segments_are_detected(segment):
    assert looks_like_secret(segment)


@pytest.mark.parametrize(
    "segment",
    [
        "main.py",
        "test_discovery_handles_unicode_names_properly.py",
        "MyVeryLongClassNameForTestingPurposes.py",
        "requirements-dev.txt",
        "çalışma_dosyası_ğüşıöç_çok_uzun_bir_isim.py",
        "2026-10-28_meeting_notes_final_version.md",
    ],
)
def test_ordinary_names_are_not_redacted(segment):
    assert not looks_like_secret(segment)


def test_redact_path_replaces_only_the_secret_segment():
    path, redacted = redact_path(f"config/{FAKE_AWS}.txt")

    assert redacted
    assert path.startswith("config/<redacted:")
    assert FAKE_AWS not in path


def test_redaction_marker_is_stable():
    assert redact_path(FAKE_AWS) == redact_path(FAKE_AWS)


def test_redact_text_replaces_secret_tokens_inside_messages():
    fake_value = "kx9Qz2Lm8Vb4" + "Nc7Rt1Yw5Hs3" + "Jd6Fg0Pa"  # split: no literal in repo
    message = f'Probable insecure usage of temporary file or directory: "/tmp/{fake_value}"'

    redacted = redact_text(message)

    assert fake_value not in redacted
    assert redacted.startswith("Probable insecure usage of temporary file or directory:")
    assert "<redacted:" in redacted


def test_redact_text_keeps_ordinary_messages_intact():
    message = "`os` imported but unused; consider removing it"

    assert redact_text(message) == message


# --- Documented limitations: redaction is a heuristic safety net, not a guarantee. ---


@pytest.mark.parametrize("weak_secret", ["hunter2", "P@ssw0rd!", "company2024"])
def test_limitation_low_entropy_secrets_are_not_detected(weak_secret):
    # Short / low-entropy secrets look like ordinary words. This is why the auditor never
    # stores code text (fix edits) and why secret scanning (Gitleaks, Stage 4) is separate.
    assert redact_text(f'value: "/tmp/{weak_secret}"') == f'value: "/tmp/{weak_secret}"'


def test_limitation_split_secret_is_not_reassembled():
    # Two halves that are each too short are not recognised.
    left, right = "kx9Qz2Lm8Vb4", "Nc7Rt1Yw5Hs3"
    assert redact_text(f"{left} {right}") == f"{left} {right}"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("evil\nname.py", "evil\\u000aname.py"),
        ("\x1b[31mred.py", "\\u001b[31mred.py"),
        ("gpj.‮exe.py", "gpj.\\u202eexe.py"),
        ("zero​width.py", "zero\\u200bwidth.py"),
        ("bad\udcff.py", "bad\\udcff.py"),
        ("çğıöşü İ 日本語 🚀.py", "çğıöşü İ 日本語 🚀.py"),
    ],
)
def test_sanitize_for_display(raw, expected):
    assert sanitize_for_display(raw) == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("plain.py", "`plain.py`"),
        ("a`b.py", "``a`b.py``"),
        ("`edge`", "`` `edge` ``"),
        ("pipe|name.py", "`pipe|name.py`"),
    ],
)
def test_md_code_fences_backticks_safely(text, expected):
    assert md_code(text) == expected
