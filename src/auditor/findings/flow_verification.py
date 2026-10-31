"""Two-hop data-flow verification for SQL injection (H5, pilot 01 finding P1).

Semgrep CE taint tracking stays inside one function, so the common web-app layout
``view (request data) -> helper module (formatted SQL)`` is only ever reported by the
pattern rule ``formatted-sql-query`` (MEDIUM: the source is unknown). This module joins two
intra-procedural Semgrep observations with a static analysis of the target's own files:

1. a *call site*: request data reaches an argument of a call ``m.f(...)`` (Semgrep rule B);
2. an *SQL sink*: a function parameter reaches the text of an SQL query (Semgrep rule A).

The join is accepted only when every step resolves exactly:

- the call argument is a plain positional or keyword argument (no ``*args`` / ``**kwargs``);
- the callee name is bound by exactly one ``import`` / ``from ... import`` in the caller file
  and never re-bound anywhere in that file;
- the module resolves to exactly one file inside the scan root (caller directory or root;
  relative imports from the caller's package); re-exports are not followed;
- the callee file defines the function exactly once at module level and never re-binds it;
- the mapped parameter reaches the SQL text of a sink on the reported line, through at most
  three simple local assignments, and not only through ``int()`` / ``float()``.

Anything else is *not verified* and the pattern finding keeps its MEDIUM severity: a missed
upgrade is preferred to a wrong HIGH. Only ``ast.parse`` is used: no import, no execution,
no code object is ever created. Files are read with the scanner's link-refusing reader and a
size limit. Target text is data; nothing in it is interpreted as an instruction.
"""

from __future__ import annotations

import ast
import os
import stat
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath

from auditor.core.models import Confidence, Evidence, Finding, Severity
from auditor.core.redaction import sanitize_for_display
from auditor.scanners.base import FlowObservation
from auditor.scanners.selection import read_regular_file

__all__ = [
    "CallSite",
    "FlowObservation",
    "SqlSink",
    "VerifiedFlow",
    "apply_flow_evidence",
    "safe_name",
    "safe_path",
    "verify_two_hop",
]

# Pattern findings that a verified flow upgrades: the Semgrep formatted-SQL rule and Ruff S608.
UPGRADABLE_RULES = frozenset({"auditor.python.sql-injection.formatted-sql-query", "S608"})
EVIDENCE_KIND = "verified_data_flow"
FLOW_TAG = "verified-data-flow"
MAX_REFERENCE_PATH = 200
MAX_NAME = 100


def safe_name(name: str) -> str:
    """A function or parameter name for the evidence text: identifiers only, bounded."""
    return name if name.isidentifier() and len(name) <= MAX_NAME else "<non-identifier>"


def safe_path(path: str) -> str:
    """A target-relative path for the evidence text: control/bidi/zero-width characters are
    made visible, the length is bounded. Markdown/HTML syntax is escaped by the renderers."""
    text = sanitize_for_display(path)
    return text if len(text) <= MAX_REFERENCE_PATH else "…" + text[-MAX_REFERENCE_PATH:]


MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_ASSIGNMENT_DEPTH = 3
SQL_SINK_METHODS = frozenset(
    {"execute", "executemany", "executescript", "exec_driver_sql", "text", "raw", "read_sql"}
)
NUMERIC_SANITIZERS = frozenset({"int", "float"})
_BLOCKS = (ast.If, ast.Try, ast.With, ast.For, ast.While)


@dataclass(frozen=True)
class CallSite:
    """Argument expression into which request data flows (0-based column of its first char)."""

    file: str
    line: int
    column: int


@dataclass(frozen=True)
class SqlSink:
    """Line of an SQL sink whose query text is reached by a function parameter."""

    file: str
    line: int


@dataclass(frozen=True)
class VerifiedFlow:
    sink: SqlSink
    function: str
    parameter: str
    call_file: str
    call_line: int


@dataclass(frozen=True)
class _Binding:
    module: str | None  # dotted module, None for ``from . import name``
    level: int  # relative import level (0 = absolute)
    function: str | None  # ``from m import f [as alias]``: the original function name


def verify_two_hop(
    root: Path | str, sinks: Iterable[SqlSink], calls: Iterable[CallSite]
) -> list[VerifiedFlow]:
    """Flows whose every step is resolved; order follows ``calls``, duplicates dropped."""
    base = Path(root).resolve()
    cache: dict[str, ast.Module | None] = {}
    sink_lines: dict[str, list[SqlSink]] = defaultdict(list)
    for sink in sinks:
        rel = _safe_relative(sink.file)
        if rel is not None:
            sink_lines[rel].append(sink)
    flows: list[VerifiedFlow] = []
    for call in calls:
        for flow in _flows_for_call(base, call, sink_lines, cache):
            if flow not in flows:
                flows.append(flow)
    return flows


def apply_flow_evidence(
    root: Path | str, findings: list[Finding], observations: Iterable[FlowObservation]
) -> tuple[list[Finding], int]:
    """Raise formatted-SQL findings at verified sink locations to HIGH, with the proof attached.

    Returns the same findings (same count, same order, same fingerprints) and the number of
    verified locations. Unverified findings are returned unchanged; nothing is created or
    dropped. The verification status stays NEEDS_REVIEW: a static proof of reachability is
    not a confirmed exploit. Evidence holds locations and names only, never code text.
    """
    sinks = [SqlSink(o.relative_path, o.line) for o in observations if o.kind == "sql_sink"]
    calls = [
        CallSite(o.relative_path, o.line, max(0, o.column - 1))
        for o in observations
        if o.kind == "request_call"
    ]
    if not sinks or not calls:
        return list(findings), 0
    flows_at: dict[tuple[str, int], list[VerifiedFlow]] = defaultdict(list)
    for flow in verify_two_hop(root, sinks, calls):
        flows_at[(flow.sink.file, flow.sink.line)].append(flow)
    upgraded, raised_at = [], set()
    for finding in findings:
        where = (_safe_relative(finding.relative_path) or "", finding.start_line or 0)
        flows = flows_at.get(where)
        if not flows or finding.rule_id not in UPGRADABLE_RULES or finding.path_redacted:
            upgraded.append(finding)
            continue
        raised_at.add(where)
        evidence = list(finding.evidence) + [
            Evidence(
                kind=EVIDENCE_KIND,
                reference=f"{safe_path(f.call_file)}:{f.call_line} request data -> "
                f"{safe_name(f.function)}({safe_name(f.parameter)}) -> "
                f"{safe_path(f.sink.file)}:{f.sink.line} SQL text",
            )
            for f in flows
        ]
        tags = list(finding.tags) + ([FLOW_TAG] if FLOW_TAG not in finding.tags else [])
        upgraded.append(
            finding.model_copy(
                update={
                    "severity": Severity.HIGH,
                    "confidence": Confidence.HIGH,
                    "evidence": evidence,
                    "tags": tags,
                }
            )
        )
    return upgraded, len(raised_at)


# ------------------------------------------------------------------------------ one call site


def _flows_for_call(base, call, sink_lines, cache) -> list[VerifiedFlow]:
    caller_rel = _safe_relative(call.file)
    caller = _parse(base, caller_rel, cache) if caller_rel else None
    if caller is None:
        return []
    located = _call_at(caller, call.line, call.column)
    if located is None:
        return []
    node, slot = located
    if slot is None:
        return []
    resolved = _resolve_callee(base, caller, caller_rel, node)
    if resolved is None:
        return []
    module_rel, function_name = resolved
    candidates = sink_lines.get(module_rel)
    if not candidates:
        return []
    callee = _parse(base, module_rel, cache)
    function = _single_definition(callee, function_name) if callee else None
    if function is None:
        return []
    parameter = _parameter_for_slot(function, slot)
    if parameter is None:
        return []
    end = function.end_lineno or function.lineno
    return [
        VerifiedFlow(sink, function_name, parameter, caller_rel, call.line)
        for sink in candidates
        if function.lineno <= sink.line <= end
        and parameter in _parameters_reaching_sql(function, sink.line)
    ]


# ---------------------------------------------------------------------------- files and paths


def _safe_relative(file: str) -> str | None:
    """Normalised POSIX path inside the root, or None (absolute, drive, UNC, '..')."""
    text = file.replace("\\", "/")
    if not text or PurePosixPath(text).is_absolute() or PureWindowsPath(text).is_absolute():
        return None
    parts = [p for p in text.split("/") if p not in ("", ".")]
    if not parts or any(p == ".." for p in parts) or ":" in text:
        return None
    return "/".join(parts)


def _parse(base: Path, rel: str, cache: dict) -> ast.Module | None:
    if rel not in cache:
        cache[rel] = None
        read = read_regular_file(str(base / rel), MAX_SOURCE_BYTES)
        if read.data is not None:
            try:
                cache[rel] = ast.parse(read.data, filename="<target>")
            except (SyntaxError, ValueError, RecursionError, MemoryError):
                cache[rel] = None
    return cache[rel]


def _is_regular_file(path: Path) -> bool:
    try:
        return stat.S_ISREG(os.lstat(path).st_mode)
    except OSError:
        return False


def _module_file(base: Path, caller_rel: str, binding: _Binding, name: str | None) -> str | None:
    """Exactly one existing file for the module, else None. ``name`` completes
    ``from <pkg> import <name>`` when the imported name is itself a module."""
    caller_dir = PurePosixPath(caller_rel).parent
    dotted = [p for p in (binding.module or "").split(".") if p] + ([name] if name else [])
    if not dotted:
        return None
    if binding.level:
        anchor = caller_dir
        for _ in range(binding.level - 1):
            if anchor == PurePosixPath("."):
                return None
            anchor = anchor.parent
        bases = [anchor]
    else:
        bases = list(dict.fromkeys([caller_dir, PurePosixPath(".")]))
    found = []
    for folder in bases:
        for candidate in (
            folder.joinpath(*dotted).with_suffix(".py"),
            folder.joinpath(*dotted, "__init__.py"),
        ):
            rel = str(candidate).removeprefix("./")
            if _safe_relative(rel) == rel and _is_regular_file(base / rel):
                found.append(rel)
    return found[0] if len(set(found)) == 1 else None


# ----------------------------------------------------------------------------- AST resolution


def _call_at(tree: ast.Module, line: int, column: int):
    """(Call, slot) for the argument starting at line/column; slot None = cannot be mapped."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for index, arg in enumerate(node.args):
            target = arg.value if isinstance(arg, ast.Starred) else arg
            if (arg.lineno, arg.col_offset) == (line, column) or (
                target.lineno,
                target.col_offset,
            ) == (line, column):
                return node, (None if isinstance(arg, ast.Starred) else index)
        for keyword in node.keywords:
            if (keyword.value.lineno, keyword.value.col_offset) == (line, column):
                return node, keyword.arg  # None for **kwargs
    return None


def _bindings(tree: ast.Module) -> tuple[dict[str, list[_Binding]], set[str], bool]:
    """Import bindings per local name, names re-bound by assignment, star-import present."""
    bindings: dict[str, list[_Binding]] = defaultdict(list)
    rebound: set[str] = set()
    star = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".")[0]
                module = alias.name if alias.asname else alias.name.split(".")[0]
                bindings[local].append(_Binding(module, 0, None))
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == "*":
                    star = True
                    continue
                bindings[alias.asname or alias.name].append(
                    _Binding(node.module, node.level, alias.name)
                )
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store | ast.Del):
            rebound.add(node.id)
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            rebound.add(node.name)
        elif isinstance(node, ast.arg):
            rebound.add(node.arg)
    return bindings, rebound, star


def _resolve_callee(base, caller, caller_rel, call: ast.Call) -> tuple[str, str] | None:
    bindings, rebound, star = _bindings(caller)
    func = call.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        alias, function_name, via_module = func.value.id, func.attr, True
    elif isinstance(func, ast.Name):
        alias, function_name, via_module = func.id, None, False
    else:
        return None  # getattr(...)(...), call chains, deeper attribute chains
    if star or alias in rebound or len(bindings.get(alias, [])) != 1:
        return None
    (binding,) = bindings[alias]
    if via_module:
        # ``import m`` / ``import m as a`` / ``from pkg import m``: the alias is a module
        name = binding.function if binding.function else None
        module_rel = _module_file(base, caller_rel, binding, name)
        return (module_rel, function_name) if module_rel else None
    # ``from m import f [as alias]``: the alias is the function itself
    if binding.function is None:
        return None
    module_rel = _module_file(base, caller_rel, binding, None)
    return (module_rel, binding.function) if module_rel else None


def _module_level(tree: ast.Module):
    """Statements at module level, descending into if/try/with/for/while but not into defs."""
    stack = list(tree.body)
    while stack:
        node = stack.pop(0)
        yield node
        if isinstance(node, _BLOCKS):
            for field in ("body", "orelse", "finalbody", "handlers"):
                for child in getattr(node, field, []) or []:
                    stack.extend(child.body if isinstance(child, ast.ExceptHandler) else [child])


def _single_definition(tree: ast.Module, name: str):
    definitions = []
    for node in _module_level(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name == name:
            definitions.append(node)
        elif isinstance(node, ast.Assign | ast.AnnAssign | ast.AugAssign):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(t, ast.Name) and t.id == name for t in targets):
                return None  # re-bound at module level
    return definitions[0] if len(definitions) == 1 else None


def _parameter_for_slot(function, slot: int | str) -> str | None:
    args = function.args
    positional = [a.arg for a in args.posonlyargs + args.args]
    if isinstance(slot, int):
        return positional[slot] if slot < len(positional) else None  # beyond: *args
    named = positional + [a.arg for a in args.kwonlyargs]
    return slot if slot in named else None  # unknown keyword: **kwargs


def _names_in(expr: ast.AST) -> set[str]:
    """Names loaded in ``expr``, skipping anything that only passes through int()/float()."""
    names: set[str] = set()
    stack = [expr]
    while stack:
        node = stack.pop()
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                and node.func.id in NUMERIC_SANITIZERS:  # fmt: skip
            continue
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            names.add(node.id)
        stack.extend(ast.iter_child_nodes(node))
    return names


def _parameters_reaching_sql(function, line: int) -> set[str]:
    """Parameters whose value reaches the query text of a sink call on ``line``."""
    params = {
        a.arg for a in function.args.posonlyargs + function.args.args + function.args.kwonlyargs
    }
    assigned: dict[str, list[ast.AST]] = defaultdict(list)
    sinks = []
    for node in ast.walk(function):
        if isinstance(node, ast.Assign | ast.AugAssign | ast.AnnAssign) and node.value is not None:
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    assigned[target.id].append(node.value)
        if (isinstance(node, ast.Call) and node.lineno == line and node.args
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in SQL_SINK_METHODS):  # fmt: skip
            sinks.append(node.args[0])
    reached: set[str] = set()
    frontier = [(expr, 0) for expr in sinks]
    seen: set[tuple[str, int]] = set()
    while frontier:
        expr, depth = frontier.pop()
        for name in _names_in(expr):
            if name in params:
                reached.add(name)
            elif name in assigned and depth < MAX_ASSIGNMENT_DEPTH and (name, depth) not in seen:
                seen.add((name, depth))
                frontier.extend((value, depth + 1) for value in assigned[name])
    return reached
