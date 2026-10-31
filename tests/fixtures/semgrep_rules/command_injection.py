# Deliberately vulnerable fixture for `semgrep --test`. Never executed, never imported.
import os
import shlex
import subprocess
import sys

from flask import request


def flask_arg_to_shell():
    cmd = request.args.get("cmd")
    # ruleid: auditor.python.command-injection.tainted-shell-command
    subprocess.run(cmd, shell=True)


def flask_form_concatenated():
    host = request.form["host"]
    # ruleid: auditor.python.command-injection.tainted-shell-command
    os.system("ping -c 1 " + host)


def input_in_fstring():
    name = input()
    # ruleid: auditor.python.command-injection.tainted-shell-command
    os.popen(f"ls {name}")


def argv_to_check_output():
    # ruleid: auditor.python.command-injection.tainted-shell-command
    subprocess.check_output("grep " + sys.argv[1] + " app.log", shell=True)


def django_view(request):
    target = request.GET["target"]
    # ruleid: auditor.python.command-injection.tainted-shell-command
    subprocess.getoutput("nslookup " + target)


def safe_argument_list():
    name = request.args.get("file")
    # ok: auditor.python.command-injection.tainted-shell-command
    subprocess.run(["ls", "-l", name])


def safe_posix_quoted():
    name = request.args.get("name")
    # ok: auditor.python.command-injection.tainted-shell-command
    subprocess.run("ls " + shlex.quote(name), shell=True)


def safe_numeric():
    count = int(request.args.get("n"))
    # ok: auditor.python.command-injection.tainted-shell-command
    os.system("head -n %d app.log" % count)


def safe_constant_command():
    # ok: auditor.python.command-injection.tainted-shell-command
    subprocess.run("ls -l", shell=True)


def boundary_cross_function_flow():
    # Known limitation (Semgrep CE taint is intraprocedural): the flow into the helper below
    # is not followed, so the sink inside _run_shell is not reported.
    _run_shell(request.args.get("cmd"))


def _run_shell(command):
    # todoruleid: auditor.python.command-injection.tainted-shell-command
    subprocess.run(command, shell=True)
