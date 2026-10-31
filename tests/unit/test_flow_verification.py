"""H5: two-hop data-flow verification (request -> call argument -> parameter -> SQL text).

The verifier joins two Semgrep observations with a static, execution-free AST analysis of the
target's files. Every step must be resolved exactly; anything uncertain is NOT verified
(the finding then keeps its pattern-based MEDIUM severity). Nothing here is wired into the
scanners yet: this is the separate validation suite requested for H5.
"""

import textwrap

import pytest

from auditor.findings.flow_verification import (
    CallSite,
    SqlSink,
    VerifiedFlow,
    verify_two_hop,
)

VIEW = """
    from flask import Blueprint, request
    import libuser

    bp = Blueprint("u", __name__)

    @bp.route("/login", methods=["POST"])
    def do_login():
        username = request.form.get("username")
        password = request.form.get("password")
        return libuser.login(username, password)
"""
LIB = """
    import sqlite3

    def login(username, password):
        c = sqlite3.connect("db").cursor()
        q = "SELECT * FROM users WHERE u = '{}' and p = '{}'".format(username, password)
        return c.execute(q).fetchone()

    def userlist():
        c = sqlite3.connect("db").cursor()
        return c.execute("SELECT * FROM users").fetchall()
"""


def tree(tmp_path, files: dict[str, str]):
    for name, text in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(text).lstrip("\n"), encoding="utf-8")
    return tmp_path


def call(root, file: str, needle: str, occurrence: int = 1) -> CallSite:
    """CallSite of the argument expression `needle` (what Semgrep rule B reports)."""
    lines = (root / file).read_text("utf-8").splitlines()
    seen = 0
    for number, text in enumerate(lines, 1):
        start = 0
        while (col := text.find(needle, start)) != -1:
            seen += 1
            if seen == occurrence:
                return CallSite(file=file, line=number, column=col)
            start = col + 1
    raise AssertionError(f"{needle!r} not found in {file}")


def sink(root, file: str, needle: str) -> SqlSink:
    lines = (root / file).read_text("utf-8").splitlines()
    (number,) = [n for n, text in enumerate(lines, 1) if needle in text]
    return SqlSink(file=file, line=number)


# ----------------------------------------------------------------------------- positive cases


def test_request_argument_to_parameter_to_formatted_sql_is_verified(tmp_path):
    root = tree(tmp_path, {"mod_user.py": VIEW, "libuser.py": LIB})
    s = sink(root, "libuser.py", "c.execute(q)")

    flows = verify_two_hop(root, [s], [call(root, "mod_user.py", "username, password"),
                                       call(root, "mod_user.py", "password)")])  # fmt: skip

    assert flows == [
        VerifiedFlow(sink=s, function="login", parameter="username",
                     call_file="mod_user.py", call_line=10),
        VerifiedFlow(sink=s, function="login", parameter="password",
                     call_file="mod_user.py", call_line=10),
    ]  # fmt: skip


def test_keyword_arguments_map_to_the_named_parameter(tmp_path):
    root = tree(tmp_path, {
        "view.py": '''
            from flask import request
            import libuser
            def v():
                return libuser.login(password=request.form["p"], username="fixed")
        ''',
        "libuser.py": LIB,
    })  # fmt: skip
    s = sink(root, "libuser.py", "c.execute(q)")

    flows = verify_two_hop(root, [s], [call(root, "view.py", 'request.form["p"]')])

    assert [f.parameter for f in flows] == ["password"]


def test_import_alias_and_from_import_alias_are_resolved(tmp_path):
    root = tree(tmp_path, {
        "view.py": '''
            from flask import request
            import libuser as lu
            from libuser import login as do_login
            def a():
                return lu.login(request.args["u"], "x")
            def b():
                return do_login(request.args["v"], "x")
        ''',
        "libuser.py": LIB,
    })  # fmt: skip
    s = sink(root, "libuser.py", "c.execute(q)")

    flows = verify_two_hop(root, [s], [call(root, "view.py", 'request.args["u"]'),
                                       call(root, "view.py", 'request.args["v"]')])  # fmt: skip

    assert [(f.call_line, f.parameter) for f in flows] == [(5, "username"), (7, "username")]


def test_relative_import_inside_a_package_is_resolved(tmp_path):
    root = tree(tmp_path, {
        "app/__init__.py": "",
        "app/views.py": '''
            from flask import request
            from . import libuser
            def v():
                return libuser.login(request.form["u"], "x")
        ''',
        "app/libuser.py": LIB,
    })  # fmt: skip
    s = sink(root, "app/libuser.py", "c.execute(q)")

    flows = verify_two_hop(root, [s], [call(root, "app/views.py", 'request.form["u"]')])

    assert [f.parameter for f in flows] == ["username"]


def test_sql_formatted_directly_in_the_execute_call_is_verified(tmp_path):
    root = tree(tmp_path, {
        "view.py": '''
            from flask import request
            import lib
            def v():
                return lib.find(request.form["u"])
        ''',
        "lib.py": '''
            import sqlite3
            def find(name):
                c = sqlite3.connect("db").cursor()
                return c.execute("SELECT * FROM t WHERE n = '%s'" % name).fetchall()
        ''',
    })  # fmt: skip
    s = sink(root, "lib.py", "c.execute(")

    assert [
        f.parameter for f in verify_two_hop(root, [s], [call(root, "view.py", 'request.form["u"]')])
    ] == ["name"]


# ----------------------------------------------------------------------------- negative cases


def test_constant_call_paths_are_not_verified_only_the_request_path_is(tmp_path):
    root = tree(tmp_path, {
        "seed.py": '''
            import libuser
            def seed():
                libuser.login("admin", "fixed-value")
        ''',
        "mod_user.py": VIEW,
        "libuser.py": LIB,
    })  # fmt: skip
    s = sink(root, "libuser.py", "c.execute(q)")

    flows = verify_two_hop(root, [s], [call(root, "mod_user.py", "password)")])

    assert [(f.call_file, f.parameter) for f in flows] == [("mod_user.py", "password")]


def test_request_data_into_a_parameter_that_never_reaches_sql_is_not_verified(tmp_path):
    root = tree(tmp_path, {
        "view.py": '''
            from flask import request
            import lib
            def v():
                return lib.save(request.form["note"], "admin")
        ''',
        "lib.py": '''
            import sqlite3
            def save(note, user):
                c = sqlite3.connect("db").cursor()
                c.execute("INSERT INTO t (u) VALUES ('%s')" % user)
                return note
        ''',
    })  # fmt: skip
    s = sink(root, "lib.py", "c.execute(")

    assert verify_two_hop(root, [s], [call(root, "view.py", 'request.form["note"]')]) == []


def test_numeric_sanitizer_breaks_the_flow(tmp_path):
    root = tree(tmp_path, {
        "view.py": '''
            from flask import request
            import lib
            def v():
                return lib.find(request.form["n"])
        ''',
        "lib.py": '''
            import sqlite3
            def find(n):
                c = sqlite3.connect("db").cursor()
                return c.execute("SELECT * FROM t WHERE id = %d" % int(n)).fetchall()
        ''',
    })  # fmt: skip
    s = sink(root, "lib.py", "c.execute(")

    assert verify_two_hop(root, [s], [call(root, "view.py", 'request.form["n"]')]) == []


def test_same_function_name_in_another_module_is_not_confused(tmp_path):
    root = tree(tmp_path, {
        "view.py": '''
            from flask import request
            import safeuser
            def v():
                return safeuser.login(request.form["u"], "x")
        ''',
        "safeuser.py": '''
            import sqlite3
            def login(username, password):
                c = sqlite3.connect("db").cursor()
                return c.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        ''',
        "libuser.py": LIB,
    })  # fmt: skip
    s = sink(root, "libuser.py", "c.execute(q)")  # the vulnerable login lives elsewhere

    assert verify_two_hop(root, [s], [call(root, "view.py", 'request.form["u"]')]) == []


def test_two_candidate_modules_for_one_name_is_ambiguous(tmp_path):
    root = tree(tmp_path, {
        "pkg/__init__.py": "",
        "pkg/view.py": '''
            from flask import request
            import libuser
            def v():
                return libuser.login(request.form["u"], "x")
        ''',
        "pkg/libuser.py": LIB,
        "libuser.py": LIB,
    })  # fmt: skip
    sinks = [sink(root, "pkg/libuser.py", "c.execute(q)"), sink(root, "libuser.py", "c.execute(q)")]

    assert verify_two_hop(root, sinks, [call(root, "pkg/view.py", 'request.form["u"]')]) == []


def test_two_definitions_of_the_function_in_the_callee_is_ambiguous(tmp_path):
    root = tree(tmp_path, {
        "view.py": '''
            from flask import request
            import lib
            def v():
                return lib.find(request.form["u"])
        ''',
        "lib.py": '''
            import sqlite3
            if True:
                def find(name):
                    c = sqlite3.connect("db").cursor()
                    return c.execute("SELECT * FROM t WHERE n = '%s'" % name).fetchall()
            else:
                def find(name):
                    return None
        ''',
    })  # fmt: skip
    s = sink(root, "lib.py", "WHERE n")

    assert verify_two_hop(root, [s], [call(root, "view.py", 'request.form["u"]')]) == []


def test_rebound_or_dynamic_callees_are_not_resolved(tmp_path):
    root = tree(tmp_path, {
        "view.py": '''
            import importlib
            from flask import request
            import libuser
            import safeuser
            def a(flag):
                mod = libuser if flag else safeuser
                return mod.login(request.form["a"], "x")
            def b():
                return getattr(libuser, "login")(request.form["b"], "x")
            def c():
                return importlib.import_module("libuser").login(request.form["c"], "x")
            def d():
                libuser = safeuser
                return libuser.login(request.form["d"], "x")
        ''',
        "libuser.py": LIB,
        "safeuser.py": "def login(username, password):\n    return None\n",
    })  # fmt: skip
    s = sink(root, "libuser.py", "c.execute(q)")
    calls = [call(root, "view.py", f'request.form["{k}"]') for k in "abcd"]

    assert verify_two_hop(root, [s], calls) == []


def test_star_args_and_kwargs_cannot_be_mapped(tmp_path):
    root = tree(tmp_path, {
        "view.py": '''
            from flask import request
            import libuser
            def a():
                return libuser.login(*request.form.getlist("x"))
            def b():
                return libuser.login(**request.form)
            def c():
                return libuser.login("a", "b", request.form["extra"])
        ''',
        "libuser.py": '''
            import sqlite3
            def login(username, password, *rest, **more):
                c = sqlite3.connect("db").cursor()
                return c.execute("SELECT * FROM users WHERE u = '%s'" % username).fetchone()
        ''',
    })  # fmt: skip
    s = sink(root, "libuser.py", "c.execute(")
    calls = [call(root, "view.py", 'request.form.getlist("x")'),
             call(root, "view.py", "request.form)"),
             call(root, "view.py", 'request.form["extra"]')]  # fmt: skip

    assert verify_two_hop(root, [s], calls) == []


def test_sink_outside_the_called_function_does_not_count(tmp_path):
    root = tree(tmp_path, {
        "view.py": '''
            from flask import request
            import libuser
            def v():
                return libuser.userlist(request.form["u"])
        ''',
        "libuser.py": LIB,
    })  # fmt: skip
    s = sink(root, "libuser.py", "c.execute(q)")  # inside login, not userlist

    assert verify_two_hop(root, [s], [call(root, "view.py", 'request.form["u"]')]) == []


def test_unparsable_or_missing_files_never_verify_and_never_raise(tmp_path):
    root = tree(tmp_path, {
        "view.py": '''
            from flask import request
            import libuser
            def v():
                return libuser.login(request.form["u"], "x")
        ''',
        "libuser.py": "def login(username, password:\n    pass\n",  # syntax error
    })  # fmt: skip
    s = SqlSink(file="libuser.py", line=3)

    assert verify_two_hop(root, [s], [call(root, "view.py", 'request.form["u"]')]) == []
    assert verify_two_hop(root, [s], [CallSite(file="nope.py", line=1, column=0)]) == []
    assert verify_two_hop(root, [s], [CallSite(file="view.py", line=99, column=0)]) == []


@pytest.mark.parametrize("name", ["../outside.py", "/abs/outside.py", "C:/x/outside.py"])
def test_paths_outside_the_root_are_refused(tmp_path, name):
    root = tree(tmp_path, {"view.py": "x = 1\n"})

    assert (
        verify_two_hop(root, [SqlSink(file=name, line=1)], [CallSite(file=name, line=1, column=0)])
        == []
    )


def test_oversized_files_are_not_parsed(tmp_path):
    root = tree(tmp_path, {"mod_user.py": VIEW, "libuser.py": LIB})
    (root / "libuser.py").write_text(
        (root / "libuser.py").read_text("utf-8") + "# " + "x" * 3_000_000, "utf-8"
    )
    s = sink(root, "libuser.py", "c.execute(q)")

    assert verify_two_hop(root, [s], [call(root, "mod_user.py", "password)")]) == []
