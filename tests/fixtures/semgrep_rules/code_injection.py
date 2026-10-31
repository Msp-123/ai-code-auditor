# Deliberately vulnerable fixture for `semgrep --test`. Never executed, never imported.
import ast
import sys

from flask import request


def eval_query_param():
    expr = request.args.get("expr")
    # ruleid: auditor.python.code-injection.tainted-eval-exec
    return eval(expr)


def exec_form_field():
    # ruleid: auditor.python.code-injection.tainted-eval-exec
    exec(request.form["code"])


def compile_argv():
    # ruleid: auditor.python.code-injection.tainted-eval-exec
    return compile(sys.argv[1], "<arg>", "exec")


def safe_literal_eval():
    # ok: auditor.python.code-injection.tainted-eval-exec
    return ast.literal_eval(request.args.get("value"))


def safe_constant_expression():
    # ok: auditor.python.code-injection.tainted-eval-exec
    return eval("1 + 1")
