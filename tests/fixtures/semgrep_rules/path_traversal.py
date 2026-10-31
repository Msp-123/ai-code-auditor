# Deliberately vulnerable fixture for `semgrep --test`. Never executed, never imported.
import os
import shutil
from pathlib import Path

from flask import request, send_file, send_from_directory
from werkzeug.utils import secure_filename

BASE = "/srv/files"


def open_user_path():
    name = request.args.get("file")
    # ruleid: auditor.python.path-traversal.tainted-file-path
    return open(os.path.join(BASE, name)).read()


def pathlib_user_path():
    name = request.args.get("file")
    # ruleid: auditor.python.path-traversal.tainted-file-path
    return Path(BASE + "/" + name).read_text()


def send_user_file():
    # ruleid: auditor.python.path-traversal.tainted-file-path
    return send_file(request.args["path"])


def delete_from_input():
    target = input()
    # ruleid: auditor.python.path-traversal.tainted-file-path
    os.remove(target)


def django_upload(request):
    name = request.POST["name"]
    # ruleid: auditor.python.path-traversal.tainted-file-path
    shutil.copy(name, "/tmp/out")


def safe_basename():
    name = os.path.basename(request.args.get("file"))
    # ok: auditor.python.path-traversal.tainted-file-path
    return open(os.path.join(BASE, name)).read()


def safe_secure_filename():
    name = secure_filename(request.args.get("file"))
    # ok: auditor.python.path-traversal.tainted-file-path
    return open(os.path.join(BASE, name)).read()


def safe_send_from_directory():
    # send_from_directory uses a safe join internally: not a sink.
    # ok: auditor.python.path-traversal.tainted-file-path
    return send_from_directory(BASE, request.args["name"])


def safe_constant_path():
    # ok: auditor.python.path-traversal.tainted-file-path
    return open(os.path.join(BASE, "index.html")).read()


def boundary_realpath_check():
    # Known false positive: a correct resolve-and-check guard is not recognised as a sanitizer.
    path = os.path.realpath(os.path.join(BASE, request.args["file"]))
    if not path.startswith(BASE + os.sep):
        raise ValueError("outside base")
    # todook: auditor.python.path-traversal.tainted-file-path
    return open(path).read()
