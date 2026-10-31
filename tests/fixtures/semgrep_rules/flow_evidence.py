"""Fixture for the H5 evidence rules (observations, never findings). Deliberately unsafe."""

import sqlite3

from flask import request

import libuser


def login(conn, username, password):
    # exec_driver_sql is a sink of the evidence rule only, so this fixture does not also
    # produce formatted-sql-query findings (those have their own fixture).
    # ruleid: auditor.python.flow-evidence.param-to-sql-text
    return conn.exec_driver_sql("SELECT * FROM u WHERE n = '%s' AND p = '%s'" % (username, password))


def by_id(conn, ident):
    # ok: auditor.python.flow-evidence.param-to-sql-text
    return conn.exec_driver_sql("SELECT * FROM u WHERE id = %d" % int(ident))


def view():
    # ruleid: auditor.python.flow-evidence.request-to-call-arg
    return libuser.login(request.form["u"], "fixed")


def view_sanitised():
    # ok: auditor.python.flow-evidence.request-to-call-arg
    return libuser.by_id(int(request.form["id"]))
