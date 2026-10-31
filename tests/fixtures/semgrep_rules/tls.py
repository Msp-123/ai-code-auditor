# Deliberately vulnerable fixture for `semgrep --test`. Never executed, never imported.
import ssl

import httpx
import requests


def requests_without_verification(url):
    # ruleid: auditor.python.tls.verification-disabled
    return requests.get(url, verify=False)


def httpx_client_without_verification():
    # ruleid: auditor.python.tls.verification-disabled
    return httpx.Client(verify=False)


def unverified_context():
    # ruleid: auditor.python.tls.verification-disabled
    return ssl._create_unverified_context()


def context_without_checks():
    ctx = ssl.create_default_context()
    # ruleid: auditor.python.tls.verification-disabled
    ctx.check_hostname = False
    # ruleid: auditor.python.tls.verification-disabled
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def safe_custom_ca(url):
    # ok: auditor.python.tls.verification-disabled
    return requests.get(url, verify="/etc/ssl/private-ca.pem")


def safe_default(url):
    # ok: auditor.python.tls.verification-disabled
    return requests.get(url, timeout=10)
