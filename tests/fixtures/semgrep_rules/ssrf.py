# Deliberately vulnerable fixture for `semgrep --test`. Never executed, never imported.
import urllib.request

import httpx
import requests
from flask import request


def fetch_user_url():
    url = request.args.get("url")
    # ruleid: auditor.python.ssrf.tainted-request-url
    return requests.get(url).text


def post_to_user_url():
    # ruleid: auditor.python.ssrf.tainted-request-url
    return requests.post(request.form["callback"], json={}).status_code


def generic_request_verb():
    # ruleid: auditor.python.ssrf.tainted-request-url
    return requests.request("GET", request.args["u"]).text


def urllib_open():
    target = input()
    # ruleid: auditor.python.ssrf.tainted-request-url
    return urllib.request.urlopen(target).read()


def httpx_user_host():
    host = request.args.get("host")
    # ruleid: auditor.python.ssrf.tainted-request-url
    return httpx.get("http://" + host + "/status").text


def django_view(request):
    # ruleid: auditor.python.ssrf.tainted-request-url
    return requests.get(request.GET["next"]).text


def safe_fixed_host_concatenation():
    item = request.args.get("id")
    # ok: auditor.python.ssrf.tainted-request-url
    return requests.get("https://api.example.com/items/" + item).text


def safe_constant_url():
    # ok: auditor.python.ssrf.tainted-request-url
    return requests.get("https://api.example.com/health").text


def safe_user_data_in_body_only():
    # ok: auditor.python.ssrf.tainted-request-url
    return requests.post("https://api.example.com/log", data=request.args["msg"]).status_code


def boundary_fixed_host_fstring():
    # Known false positive: an f-string with a fixed host is not recognised as safe
    # (only literal-prefix concatenation is).
    item = request.args.get("id")
    # todook: auditor.python.ssrf.tainted-request-url
    return requests.get(f"https://api.example.com/items/{item}").text


def boundary_allowlist_check():
    # Known false positive: allowlist validation in code is not recognised as a sanitizer.
    url = request.args.get("url")
    if url not in {"https://a.example.com/", "https://b.example.com/"}:
        raise ValueError("not allowed")
    # todook: auditor.python.ssrf.tainted-request-url
    return requests.get(url).text
