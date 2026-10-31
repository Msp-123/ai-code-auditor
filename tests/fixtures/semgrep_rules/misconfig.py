# Deliberately vulnerable fixture for `semgrep --test`. Never executed, never imported.
import os

from flask import Flask

app = Flask(__name__)


def start_debug():
    # ruleid: auditor.python.misconfig.flask-debug-enabled
    app.run(host="0.0.0.0", debug=True)


def start_from_environment():
    # ok: auditor.python.misconfig.flask-debug-enabled
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")


def start_production():
    # ok: auditor.python.misconfig.flask-debug-enabled
    app.run(host="127.0.0.1")
