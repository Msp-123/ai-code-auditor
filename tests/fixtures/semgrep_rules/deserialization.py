# Deliberately vulnerable fixture for `semgrep --test`. Never executed, never imported.
import json
import pickle

import yaml
from flask import request


def unpickle_request_body():
    # ruleid: auditor.python.deserialization.tainted-pickle-load
    return pickle.loads(request.get_data())


def unpickle_form_value():
    blob = request.form["state"].encode()
    # ruleid: auditor.python.deserialization.tainted-pickle-load
    return pickle.loads(blob)


def safe_json_body():
    # ok: auditor.python.deserialization.tainted-pickle-load
    return json.loads(request.get_data())


def safe_unpickle_local_cache(path):
    # Data that does not come from a request: not reported by the taint rule.
    with open(path, "rb") as fh:
        # ok: auditor.python.deserialization.tainted-pickle-load
        return pickle.load(fh)


def yaml_default_loader(text):
    # ruleid: auditor.python.deserialization.yaml-unsafe-load
    return yaml.load(text)


def yaml_full_loader(text):
    # ruleid: auditor.python.deserialization.yaml-unsafe-load
    return yaml.load(text, Loader=yaml.FullLoader)


def yaml_unsafe(text):
    # ruleid: auditor.python.deserialization.yaml-unsafe-load
    return yaml.unsafe_load(text)


def yaml_safe_loader(text):
    # ok: auditor.python.deserialization.yaml-unsafe-load
    return yaml.load(text, Loader=yaml.SafeLoader)


def yaml_safe_load(text):
    # ok: auditor.python.deserialization.yaml-unsafe-load
    return yaml.safe_load(text)
