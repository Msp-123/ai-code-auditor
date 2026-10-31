# Deliberately vulnerable fixture for `semgrep --test`. Never executed, never imported.
import jwt


def decode_without_signature_check(token):
    # ruleid: auditor.python.jwt.signature-not-verified
    return jwt.decode(token, options={"verify_signature": False})


def decode_legacy_verify_false(token, key):
    # ruleid: auditor.python.jwt.signature-not-verified
    return jwt.decode(token, key, verify=False)


def decode_none_algorithm(token, key):
    # ruleid: auditor.python.jwt.signature-not-verified
    return jwt.decode(token, key, algorithms=["HS256", "none"])


def safe_decode(token, key):
    # ok: auditor.python.jwt.signature-not-verified
    return jwt.decode(token, key, algorithms=["HS256"])
