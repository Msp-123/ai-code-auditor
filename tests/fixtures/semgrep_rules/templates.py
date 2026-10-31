# Deliberately vulnerable fixture for `semgrep --test`. Never executed, never imported.
import jinja2
from flask import render_template, render_template_string, request


def ssti_render_string():
    # ruleid: auditor.python.template-injection.tainted-template-source
    return render_template_string("<h1>Hello " + request.args.get("name") + "</h1>")


def ssti_jinja_template():
    # ruleid: auditor.python.template-injection.tainted-template-source
    return jinja2.Template(request.form["tpl"]).render()


def safe_fixed_template():
    # ok: auditor.python.template-injection.tainted-template-source
    return render_template("hello.html", name=request.args.get("name"))


def safe_render_string_with_variable():
    # ok: auditor.python.template-injection.tainted-template-source
    return render_template_string("<h1>Hello {{ name }}</h1>", name=request.args.get("name"))


def env_autoescape_off():
    # ruleid: auditor.python.template-injection.jinja2-autoescape-disabled
    return jinja2.Environment(loader=jinja2.FileSystemLoader("t"), autoescape=False)


def env_autoescape_default():
    # ruleid: auditor.python.template-injection.jinja2-autoescape-disabled
    return jinja2.Environment(loader=jinja2.FileSystemLoader("t"))


def env_autoescape_on():
    # ok: auditor.python.template-injection.jinja2-autoescape-disabled
    return jinja2.Environment(autoescape=True)


def env_select_autoescape():
    # ok: auditor.python.template-injection.jinja2-autoescape-disabled
    return jinja2.Environment(autoescape=jinja2.select_autoescape(["html"]))
