"""requirements*.txt parsing (Stage 5): only exact, verifiable pins are ever audited.

Measured in step 0: pip-audit itself silently drops ``-r`` includes, ignores ``-c``, evaluates
markers against the auditor's own interpreter and aborts on one unpinned or duplicated line.
So all of this is the auditor's job, tested here.
"""

import pytest

from auditor.scanners.manifests import Gap, Pin, normalize_name, parse_requirements

CRED = "user:" + "s3cr" + "etTOKEN" + "x9"  # assembled at runtime; must never be echoed


def parse(make_tree, files, top="requirements.txt"):
    root = make_tree(files)
    inventory = set()
    stack = [((), files)]
    while stack:
        prefix, node = stack.pop()
        for name, value in node.items():
            if isinstance(value, dict):
                stack.append(((*prefix, name), value))
            else:
                inventory.add("/".join((*prefix, name)))
    return parse_requirements(root, top, inventory)


def pins(result):
    return sorted((p.name, p.version, p.file, p.line) for p in result.pins)


def gaps(result):
    return sorted((g.reason, g.file, g.line) for g in result.gaps)


def everything(result):
    return repr(result.pins) + repr(result.gaps) + repr(result.notes)


def test_exact_pins_are_normalized_with_file_and_line(make_tree):
    result = parse(make_tree, {"requirements.txt": "Jinja2==2.10\n\n# c\nrequests_OAuth===1.0\n"})

    assert pins(result) == [
        ("jinja2", "2.10", "requirements.txt", 1),
        ("requests-oauth", "1.0", "requirements.txt", 4),
    ]
    assert result.gaps == [] and not result.fatal


@pytest.mark.parametrize(
    "line",
    ["jinja2", "jinja2>=2.10", "jinja2~=2.10", "jinja2==2.*", "jinja2==2.10,!=2.10.1", "jinja2<3"],
)
def test_anything_but_one_exact_pin_is_not_analyzed(make_tree, line):
    result = parse(make_tree, {"requirements.txt": line + "\n"})

    assert result.pins == []
    assert gaps(result) == [("UNPINNED", "requirements.txt", 1)]


def test_markers_extras_hashes_and_continuations(make_tree):
    text = (
        'jinja2==2.10 ; python_version < "3.0"\n'
        "requests[socks,security]==2.19.0\n"
        "urllib3==\\\n1.24.1 \\\n    --hash=sha256:" + "0" * 64 + "\n"
        "pyyaml==5.3  # trailing comment\n"
    )
    result = parse(make_tree, {"requirements.txt": text})
    by_name = {p.name: p for p in result.pins}

    assert pins(result) == [
        ("jinja2", "2.10", "requirements.txt", 1),
        ("pyyaml", "5.3", "requirements.txt", 6),  # the continuation spans lines 3-5
        ("requests", "2.19.0", "requirements.txt", 2),
        ("urllib3", "1.24.1", "requirements.txt", 3),  # first line of the logical line
    ]
    # the marker is kept, never evaluated against the auditor's own interpreter
    assert by_name["jinja2"].marker == 'python_version < "3.0"'
    assert by_name["requests"].extras == ("security", "socks")
    assert by_name["urllib3"].marker is None


@pytest.mark.parametrize(
    ("line", "reason"),
    [
        (f"pkg @ https://{CRED}@example.invalid/pkg-1.0-py3-none-any.whl", "URL"),
        (f"git+https://{CRED}@example.invalid/x/y.git#egg=y", "VCS"),
        ("-e .", "EDITABLE"),
        ("--editable ./lib", "EDITABLE"),
        ("./vendor/pkg-1.0.tar.gz", "LOCAL_PATH"),
        ("C:\\wheels\\pkg-1.0-py3-none-any.whl", "LOCAL_PATH"),
        ("file:../pkg", "LOCAL_PATH"),
        ("jinja2==not a version", "INVALID"),
        ("==1.0", "INVALID"),
    ],
)
def test_unverifiable_sources_are_gaps_and_never_echo_values(make_tree, line, reason):
    result = parse(make_tree, {"requirements.txt": line + "\n"})

    assert result.pins == []
    assert gaps(result) == [(reason, "requirements.txt", 1)]
    assert CRED not in everything(result) and "example.invalid" not in everything(result)


def test_pip_options_are_noted_by_name_only(make_tree):
    text = f"--extra-index-url https://{CRED}@private.invalid/simple\n-i https://x\njinja2==2.10\n"

    result = parse(make_tree, {"requirements.txt": text})

    assert pins(result) == [("jinja2", "2.10", "requirements.txt", 3)]
    assert any("--extra-index-url" in n for n in result.notes)
    assert any("custom package index" in n for n in result.notes)
    assert CRED not in everything(result) and "private.invalid" not in everything(result)


def test_includes_are_followed_inside_root_and_inventory_only(make_tree):
    files = {
        "requirements.txt": "-r requirements/base.txt\n-r ../outside.txt\n-r missing.txt\n"
        "-r https://example.invalid/r.txt\n",
        "requirements": {"base.txt": "jinja2==2.10\n-r ../common.txt\n"},
        "common.txt": "urllib3==1.24.1\n",
    }

    result = parse(make_tree, files)

    assert pins(result) == [
        ("jinja2", "2.10", "requirements/base.txt", 1),
        ("urllib3", "1.24.1", "common.txt", 1),
    ]
    assert gaps(result) == [
        ("INCLUDE_NOT_IN_INVENTORY", "requirements.txt", 3),
        ("INCLUDE_OUTSIDE_ROOT", "requirements.txt", 2),
        ("INCLUDE_REMOTE", "requirements.txt", 4),
    ]


def test_include_cycles_are_reported_and_terminate(make_tree):
    files = {"requirements.txt": "-r a.txt\njinja2==2.10\n", "a.txt": "-r requirements.txt\n"}

    result = parse(make_tree, files)

    assert pins(result) == [("jinja2", "2.10", "requirements.txt", 2)]
    assert gaps(result) == [("INCLUDE_CYCLE", "a.txt", 1)]


def test_constraints_pin_only_what_is_required(make_tree):
    files = {
        "requirements.txt": "-c constraints.txt\njinja2\nrequests>=2\n",
        "constraints.txt": "jinja2==2.10\nrequests==2.19.0\nurllib3==1.24.1\n",
    }

    result = parse(make_tree, files)
    by_name = {p.name: p for p in result.pins}

    # urllib3 is only constrained, never required: a constraint alone is no dependency
    assert pins(result) == [
        ("jinja2", "2.10", "requirements.txt", 2),
        ("requests", "2.19.0", "requirements.txt", 3),
    ]
    assert by_name["jinja2"].via_constraint == "constraints.txt:1"
    # requests had its own range: whether the constraint satisfies it is not verified
    assert gaps(result) == [("CONSTRAINT_UNVERIFIED", "requirements.txt", 3)]


def test_conflicting_pins_are_both_audited_and_reported(make_tree):
    files = {
        "requirements.txt": "jinja2==2.10\n-c c.txt\n-r more.txt\n",
        "more.txt": "jinja2==2.11\n",
        "c.txt": "jinja2==2.9\n",
    }

    result = parse(make_tree, files)

    assert pins(result) == [
        ("jinja2", "2.10", "requirements.txt", 1),
        ("jinja2", "2.11", "more.txt", 1),
    ]
    assert ("CONFLICT", "requirements.txt", 1) in gaps(result)


def test_unreadable_and_non_utf8_files_are_fatal(make_tree):
    result = parse(make_tree, {"requirements.txt": b"jinja2==2.10\n\xff\xfe\x00bad"})

    assert result.fatal and result.pins == []
    assert gaps(result) == [("UNREADABLE", "requirements.txt", None)]


def test_bom_and_crlf_are_handled(make_tree):
    result = parse(make_tree, {"requirements.txt": b"\xef\xbb\xbfjinja2==2.10\r\nurllib3==1.24.1"})

    assert pins(result) == [
        ("jinja2", "2.10", "requirements.txt", 1),
        ("urllib3", "1.24.1", "requirements.txt", 2),
    ]


def test_name_normalization_is_pep_503():
    assert normalize_name("Foo.Bar__baz-QUX") == "foo-bar-baz-qux"


def test_records_are_value_objects():
    assert Pin("a", "1", "r.txt", 1, None, (), None) == Pin("a", "1", "r.txt", 1, None, (), None)
    assert Gap("r.txt", 1, "UNPINNED", "x").reason == "UNPINNED"
