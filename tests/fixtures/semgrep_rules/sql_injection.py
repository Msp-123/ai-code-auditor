# Deliberately vulnerable fixture for `semgrep --test`. Never executed, never imported.
import sqlalchemy
from flask import request


def flask_arg_in_fstring(cur):
    user = request.args.get("user")
    # ruleid: auditor.python.sql-injection.tainted-sql-query, auditor.python.sql-injection.formatted-sql-query
    cur.execute(f"SELECT * FROM users WHERE name = '{user}'")


def percent_formatting_via_variable(cur):
    user_id = request.form["id"]
    query = "DELETE FROM users WHERE id = %s" % user_id
    # ruleid: auditor.python.sql-injection.tainted-sql-query, auditor.python.sql-injection.formatted-sql-query
    cur.execute(query)


def sqlalchemy_text(conn):
    name = request.args.get("name")
    # ruleid: auditor.python.sql-injection.tainted-sql-query, auditor.python.sql-injection.formatted-sql-query
    conn.execute(sqlalchemy.text("SELECT * FROM t WHERE n = '" + name + "'"))


def django_raw(request, User):
    term = request.GET["q"]
    # ruleid: auditor.python.sql-injection.tainted-sql-query, auditor.python.sql-injection.formatted-sql-query
    User.objects.raw("SELECT * FROM auth_user WHERE username = '%s'" % term)


def formatted_from_parameter(cur, table):
    # Not provably user-controlled here, but formatted SQL from a non-constant value.
    # ruleid: auditor.python.sql-injection.formatted-sql-query
    cur.execute("SELECT * FROM {}".format(table))


def safe_parameterised(cur):
    user = request.args.get("user")
    # ok: auditor.python.sql-injection.tainted-sql-query, auditor.python.sql-injection.formatted-sql-query
    cur.execute("SELECT * FROM users WHERE name = ?", (user,))


def safe_numeric(cur):
    # The taint rule accepts int() as a sanitizer. The pattern-based formatted-sql rule cannot
    # see the conversion: known false positive of that rule (todook).
    limit = int(request.args.get("limit"))
    # ok: auditor.python.sql-injection.tainted-sql-query
    # todook: auditor.python.sql-injection.formatted-sql-query
    cur.execute("SELECT * FROM logs LIMIT %d" % limit)


def safe_constant(cur):
    # ok: auditor.python.sql-injection.tainted-sql-query, auditor.python.sql-injection.formatted-sql-query
    cur.execute("SELECT * FROM users WHERE active = " + "1")


def boundary_escaping_is_not_a_sanitizer(cur, escape):
    # Quoting/escaping helpers are deliberately NOT accepted as SQL sanitizers.
    name = escape(request.args.get("name"))
    # ruleid: auditor.python.sql-injection.tainted-sql-query, auditor.python.sql-injection.formatted-sql-query
    cur.execute("SELECT * FROM users WHERE name = '%s'" % name)


def boundary_constant_table_name(cur):
    # Known false positive: formatting a constant from a module-level allowlist is still
    # reported by the formatted-sql rule (it cannot prove the value is constant).
    table = ALLOWED_TABLES["users"]
    # todook: auditor.python.sql-injection.formatted-sql-query
    cur.execute("SELECT COUNT(*) FROM %s" % table)


ALLOWED_TABLES = {"users": "users"}
