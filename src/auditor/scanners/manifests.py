"""Dependency manifests: the auditor's own parsers (Stage 5, D-044).

Measured in step 0 (pip-audit 2.10.1 with ``--disable-pip --no-deps``): ``-r`` includes are
silently dropped (a false "no vulnerabilities"), ``-c`` is ignored, environment markers are
evaluated against the *auditor's* interpreter, and one unpinned or duplicated line aborts the
whole audit. Therefore pip-audit only ever receives plain ``name==version`` lines produced
here, and everything that cannot be pinned with certainty is reported as a gap.

Principles:

- Nothing in the target is executed or installed; files are only read (no links followed).
- Only one exact pin (``==`` without wildcard, or ``===``) counts. Ranges, URLs, VCS, local
  paths and editables are gaps, never assumed safe.
- Markers are kept as text and never evaluated: the auditor's Python/OS is not the target's.
- pyproject.toml declarations (ranges) are never audited themselves; they count as covered
  only when a pylock.toml in the same directory provably pins each of them (D-045).
- Values that may hold credentials (URLs, index options) are never copied anywhere; gaps and
  notes carry fixed texts, option names and validated package names only.
"""

import posixpath
import re
import tomllib
from collections.abc import Collection
from dataclasses import dataclass, field
from pathlib import Path

from auditor.scanners.selection import read_regular_file

MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_INCLUDE_DEPTH = 16
_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")
_REQUIREMENT = re.compile(
    r"^(?P<name>[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*"
    r"(?:\[(?P<extras>[^\]]*)\])?\s*(?P<spec>[^;]*?)\s*(?:;\s*(?P<marker>.*?))?\s*$"
)
# PEP 440 version (public + local), case-insensitive.
_VERSION = re.compile(
    r"^v?(?:\d+!)?\d+(?:\.\d+)*(?:[-_.]?(?:a|b|c|rc|alpha|beta|pre|preview)[-_.]?\d*)?"
    r"(?:-\d+|[-_.]?(?:post|rev|r)[-_.]?\d*)?(?:[-_.]?dev[-_.]?\d*)?"
    r"(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?$",
    re.IGNORECASE,
)
_ARBITRARY = re.compile(r"^[A-Za-z0-9._+!-]{1,64}$")
_COMMENT = re.compile(r"(^|\s)#.*$")
_TRAILING_OPTIONS = re.compile(r"\s--?[A-Za-z].*$")
_OPTION_NAME = re.compile(r"^--?[A-Za-z][A-Za-z0-9-]*")
_DRIVE = re.compile(r"^[A-Za-z]:[\\/]")
INDEX_OPTIONS = frozenset(
    {"-i", "--index-url", "--extra-index-url", "--no-index", "-f", "--find-links"}
)
_ALIASES = {"-i": "--index-url", "-f": "--find-links"}

GAP_TEXT = {
    "UNPINNED": "not pinned to one exact version; the installed version is unknown",
    "URL": "direct URL requirement; not a versioned index package",
    "VCS": "version-control requirement; not a versioned index package",
    "EDITABLE": "editable requirement; not a versioned index package",
    "LOCAL_PATH": "local file or directory requirement; not a versioned index package",
    "INVALID": "could not be parsed as an exact requirement",
    "INCLUDE_OUTSIDE_ROOT": "included file is outside the project root; not read",
    "INCLUDE_NOT_IN_INVENTORY": "included file is missing or not in the inventory; not read",
    "INCLUDE_REMOTE": "included file is a URL; never fetched",
    "INCLUDE_CYCLE": "include cycle; not followed again",
    "INCLUDE_TOO_DEEP": "include nesting too deep; not followed",
    "INCLUDE_UNREADABLE": "included file could not be read",
    "CONSTRAINT_UNVERIFIED": "version taken from a constraints file; whether it satisfies the "
    "requirement's own range was not verified",
    "CONFLICT": "conflicting exact versions for this package in the same requirement set; "
    "each version is audited separately",
    "CUSTOM_INDEX": "a custom package index is configured: packages may not come from PyPI, "
    "so OSV results by name may not apply",
    "UNREADABLE": "file could not be read or is not valid UTF-8",
    "INVALID_FILE": "file could not be parsed",
    "UNSUPPORTED_VERSION": "unsupported lock file version",
    "NO_VERSION": "package has no version in the lock file",
    "NO_SOURCE": "package source is not stated; it may not be a PyPI package",
    "ARCHIVE": "archive source; not a versioned index package",
    "DIRECTORY": "local directory source; not a versioned index package",
    "NON_PYPI_SOURCE": "source is not the public PyPI index; OSV results by name may not apply",
    "UNSUPPORTED_FORMAT": "dependency declarations in this format are not audited (supported: "
    "requirements*.txt, pylock.toml)",
    "NOT_EXECUTED": "setup.py is never executed, so its dependencies are not known",
    "NOT_LOCKED": "dependencies are declared, but no valid pylock.toml in the same directory "
    "locks them; the installed versions are unknown",
    "DYNAMIC": "dependencies are dynamic (computed by the build backend, which is never run); "
    "they are not known",
    "LOCK_MISSING": "declared dependency is not pinned by the lock file next to it; not audited",
    "LOCK_CONFLICT": "the locked version does not satisfy the declared requirement (the lock "
    "file is out of date); only the locked version is audited",
    "LOCK_RANGE_UNVERIFIED": "whether the locked version satisfies the declared range could not "
    "be verified (only plain release versions with ==, !=, <, <=, >, >=, ~= are checked)",
    "LOCK_CONDITION_UNVERIFIED": "the lock file installs this dependency under a different "
    "environment marker than declared; markers are never evaluated",
    "LOCK_ENVIRONMENT_UNVERIFIED": "the lock file is restricted to declared environments; "
    "whether the target environment is one of them was not verified",
}


def normalize_name(name: str) -> str:
    """PEP 503 normalised project name."""
    return re.sub(r"[-_.]+", "-", name).lower()


@dataclass(frozen=True)
class Pin:
    name: str  # PEP 503 normalised
    version: str
    file: str  # inventory-relative path, "/" separated
    line: int | None
    marker: str | None  # kept as written, never evaluated
    extras: tuple[str, ...]
    via_constraint: str | None  # "constraints.txt:3" if the version came from a -c file


@dataclass(frozen=True)
class Gap:
    file: str
    line: int | None
    reason: str  # key of GAP_TEXT
    detail: str  # fixed text (plus a validated package name at most)


@dataclass
class ManifestResult:
    file: str
    kind: str  # "requirements", "pylock", "unsupported"
    pins: list[Pin] = field(default_factory=list)
    gaps: list[Gap] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    fatal: bool = False
    files_read: set[str] = field(default_factory=set)
    # pylock only: packages whose source is the lock file's own directory ("."), and whether
    # the lock is restricted to declared environments
    local_roots: dict[str, int | None] = field(default_factory=dict)
    environments: bool = False

    def gap(self, file: str, line: int | None, reason: str, name: str | None = None) -> None:
        detail = GAP_TEXT[reason] + (f" ({name})" if name else "")
        item = Gap(file, line, reason, detail)
        if item not in self.gaps:
            self.gaps.append(item)

    def note(self, text: str) -> None:
        if text not in self.notes:
            self.notes.append(text)


def read_text(root: Path, relative: str) -> str | None:
    """A manifest's text (UTF-8, BOM allowed), or None if it cannot be read safely."""
    path = str(Path(root, *relative.split("/")))
    data = read_regular_file(path, MAX_MANIFEST_BYTES).data
    if data is None:
        return None
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return None


# ----------------------------------------------------------------------- requirements*.txt


@dataclass(frozen=True)
class _Entry:
    name: str
    version: str | None
    ranged: bool  # had a specifier that is not one exact pin
    marker: str | None
    extras: tuple[str, ...]
    file: str
    line: int


def _logical_lines(text: str):
    """(first physical line number, text) with backslash continuations joined."""
    start, parts = None, []
    for number, raw in enumerate(text.splitlines(), 1):
        if start is None:
            start = number
        if raw.endswith("\\"):
            parts.append(raw[:-1])
            continue
        parts.append(raw)
        yield start, _COMMENT.sub("", "".join(parts)).strip()
        start, parts = None, []
    if parts:
        yield start, _COMMENT.sub("", "".join(parts)).strip()


def _option(line: str) -> tuple[str, str | None]:
    """(canonical option name, value) for '-r x', '-rx', '--requirement=x' and the like."""
    match = _OPTION_NAME.match(line)
    name = match.group(0) if match else line.split()[0]
    rest = line[len(name) :]
    if name.startswith("--") and rest.startswith("="):
        value = rest[1:].strip()
    elif not name.startswith("--") and len(name) > 2:  # "-rfile"
        name, value = name[:2], name[2:] + rest
    else:
        value = rest.strip()
    value = value.strip().strip("\"'") or None
    return _ALIASES.get(name, name), value


def _source_kind(text: str) -> str | None:
    lowered = text.lower()
    if lowered.startswith(("git+", "hg+", "svn+", "bzr+")) or "git+" in lowered.split("@", 1)[-1]:
        return "VCS"
    if lowered.startswith("file:"):
        return "LOCAL_PATH"
    if "://" in lowered:
        return "URL"
    if text.startswith((".", "/", "\\", "~")) or _DRIVE.match(text):
        return "LOCAL_PATH"
    if "/" in text or "\\" in text:
        return "LOCAL_PATH"
    return None


def _requirement(text: str, file: str, number: int, result: ManifestResult) -> _Entry | None:
    requirement = _TRAILING_OPTIONS.sub("", text).strip()  # e.g. "--hash=..." after the spec
    kind = _source_kind(requirement.split(";", 1)[0].strip())
    match = _REQUIREMENT.match(requirement)
    if kind is None and match and match.group("spec").startswith("@"):
        kind = "URL"
    if kind is not None:
        result.gap(file, number, kind)
        return None
    if not match:
        result.gap(file, number, "INVALID")
        return None
    name = normalize_name(match.group("name"))
    raw_extras = (e.strip() for e in (match.group("extras") or "").split(","))
    extras = tuple(sorted({normalize_name(e) for e in raw_extras if _NAME.match(e)}))
    marker = (match.group("marker") or "").strip() or None
    spec = re.sub(r"\s+", "", match.group("spec") or "")
    if not spec:
        return _Entry(name, None, False, marker, extras, file, number)
    if spec[0] not in "<>=!~":
        result.gap(file, number, "INVALID", name)
        return None
    clauses = spec.split(",")
    if len(clauses) == 1 and clauses[0].startswith("==="):
        version = clauses[0][3:]
        if not _ARBITRARY.match(version):
            result.gap(file, number, "INVALID", name)
            return None
        return _Entry(name, version, False, marker, extras, file, number)
    if len(clauses) == 1 and clauses[0].startswith("==") and "*" not in clauses[0]:
        version = clauses[0][2:]
        if not _VERSION.match(version):
            result.gap(file, number, "INVALID", name)
            return None
        return _Entry(name, version, False, marker, extras, file, number)
    return _Entry(name, None, True, marker, extras, file, number)


def _resolve_include(current: str, value: str, inventory: dict[str, str]) -> tuple[str | None, str]:
    if "://" in value:
        return None, "INCLUDE_REMOTE"
    value = value.replace("\\", "/")
    if value.startswith("/") or _DRIVE.match(value):
        return None, "INCLUDE_OUTSIDE_ROOT"
    joined = posixpath.normpath(posixpath.join(posixpath.dirname(current), value))
    if joined == ".." or joined.startswith("../"):
        return None, "INCLUDE_OUTSIDE_ROOT"
    found = inventory.get(joined) or inventory.get(joined.casefold())
    return (found, "") if found else (None, "INCLUDE_NOT_IN_INVENTORY")


def parse_requirements(root: Path, top: str, inventory_paths: Collection[str]) -> ManifestResult:
    """Parse one requirement set: ``top`` with its ``-r`` and ``-c`` files (root-confined)."""
    requirement_set = _RequirementSet(root, top, inventory_paths)
    requirement_set.walk(top, (top,), False, None)
    requirement_set.resolve()
    return requirement_set.result


class _RequirementSet:
    def __init__(self, root: Path, top: str, inventory_paths: Collection[str]) -> None:
        self.root = root
        self.inventory = {p: p for p in inventory_paths} | {
            p.casefold(): p for p in inventory_paths
        }
        self.result = ManifestResult(file=top, kind="requirements")
        self.entries: list[_Entry] = []
        self.constraints: dict[str, list[tuple[str, str]]] = {}
        self.visited: set[tuple[str, bool]] = set()

    def walk(self, file: str, stack: tuple[str, ...], constraint: bool, origin) -> None:
        if (file, constraint) in self.visited:
            return
        self.visited.add((file, constraint))
        text = read_text(self.root, file)
        if text is None:
            if origin is None:
                self.result.fatal = True
                self.result.gap(file, None, "UNREADABLE")
            else:
                self.result.gap(origin[0], origin[1], "INCLUDE_UNREADABLE")
            return
        self.result.files_read.add(file)
        for number, line in _logical_lines(text):
            if line.startswith("-"):
                self._option_line(file, number, line, stack, constraint)
            elif line:
                self._requirement_line(file, number, line, constraint)

    def _option_line(self, file, number, line, stack, constraint) -> None:
        option, value = _option(line)
        if option in ("-r", "--requirement", "-c", "--constraint"):
            if constraint and option in ("-r", "--requirement"):
                self.result.note("an -r line inside a constraints file was ignored")
                return
            nested = constraint or option in ("-c", "--constraint")
            self._include(file, number, value or "", stack, nested)
        elif option in ("-e", "--editable"):
            if not constraint:
                self.result.gap(file, number, "EDITABLE")
        else:
            shown = option if _OPTION_NAME.fullmatch(option) else "an unrecognised option"
            self.result.note(f"pip option ignored: {shown}")
            if option in INDEX_OPTIONS:
                self.result.note(GAP_TEXT["CUSTOM_INDEX"])
                self.result.gap(file, number, "CUSTOM_INDEX")

    def _include(self, file, number, value, stack, constraint) -> None:
        target, problem = _resolve_include(file, value, self.inventory)
        if target in stack:
            self.result.gap(file, number, "INCLUDE_CYCLE")
        elif len(stack) >= MAX_INCLUDE_DEPTH:
            self.result.gap(file, number, "INCLUDE_TOO_DEEP")
        elif target is None:
            self.result.gap(file, number, problem)
        else:
            self.walk(target, (*stack, target), constraint, (file, number))

    def _requirement_line(self, file, number, line, constraint) -> None:
        entry = _requirement(line, file, number, self.result)
        if entry is None:
            return
        if not constraint:
            self.entries.append(entry)
        elif entry.version is not None:  # a constraint alone never creates a dependency
            self.constraints.setdefault(entry.name, []).append((entry.version, f"{file}:{number}"))

    def resolve(self) -> None:
        for entry in self.entries:
            self._resolve_entry(entry)
        self._flag_multiple_versions()
        self.result.pins = list(dict.fromkeys(self.result.pins))

    def _resolve_entry(self, e: _Entry) -> None:
        result = self.result
        pinned = self.constraints.get(e.name, [])
        versions = {v for v, _ in pinned}
        if e.version is not None:
            if versions and versions != {e.version}:
                result.gap(e.file, e.line, "CONFLICT", e.name)
            result.pins.append(Pin(e.name, e.version, e.file, e.line, e.marker, e.extras, None))
        elif len(versions) == 1:
            version, where = pinned[0]
            if e.ranged:
                result.gap(e.file, e.line, "CONSTRAINT_UNVERIFIED", e.name)
            result.pins.append(Pin(e.name, version, e.file, e.line, e.marker, e.extras, where))
        elif len(versions) > 1:
            result.gap(e.file, e.line, "CONFLICT", e.name)
        else:
            result.gap(e.file, e.line, "UNPINNED", e.name)

    def _flag_multiple_versions(self) -> None:
        by_name: dict[str, list[Pin]] = {}
        for pin in self.result.pins:
            by_name.setdefault(pin.name, []).append(pin)
        for name, group in by_name.items():
            if len({p.version for p in group}) > 1:
                self.result.gap(group[0].file, group[0].line, "CONFLICT", name)


# ------------------------------------------------------------------------------ pylock.toml

PYPI_HOSTS = ("https://files.pythonhosted.org/", "https://pypi.org/")
PYPI_INDEX = ("https://pypi.org/simple", "https://pypi.org/simple/")


def _package_lines(text: str) -> list[int]:
    return [n for n, line in enumerate(text.splitlines(), 1) if line.strip() == "[[packages]]"]


def _source_problem(package: dict) -> str | None:
    kinds = [k for k in ("vcs", "directory", "archive", "sdist", "wheels") if k in package]
    if not kinds:
        return "NO_SOURCE"
    if "vcs" in kinds:
        return "VCS"
    if "directory" in kinds:
        return "DIRECTORY"
    if "archive" in kinds:
        return "ARCHIVE"
    files = ([package["sdist"]] if "sdist" in package else []) + list(package.get("wheels", []))
    if not files or not all(isinstance(f, dict) for f in files):
        return "NO_SOURCE"
    for item in files:
        url = item.get("url")
        if not isinstance(url, str):
            return "LOCAL_PATH"  # "path" only: a local file
        if not url.startswith(PYPI_HOSTS):
            return "NON_PYPI_SOURCE"
    index = package.get("index")
    if index is not None and index not in PYPI_INDEX:
        return "NON_PYPI_SOURCE"
    return None


def _is_own_directory(source: object) -> bool:
    return isinstance(source, dict) and source.get("path") in (".", "./")


def parse_pylock(text: str, file: str) -> ManifestResult:
    """PEP 751 lock file; only versioned packages from the public PyPI index are pinned."""
    result = ManifestResult(file=file, kind="pylock")
    result.files_read.add(file)
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        result.fatal = True
        result.gap(file, None, "INVALID_FILE")
        return result
    version = data.get("lock-version")
    if not isinstance(version, str) or not version.startswith("1."):
        result.fatal = True
        result.gap(file, None, "UNSUPPORTED_VERSION")
        return result
    for key, label in (("extras", "extras"), ("dependency-groups", "dependency groups"),
                       ("default-groups", "default groups")):  # fmt: skip
        names = [n for n in data.get(key, []) if isinstance(n, str) and _NAME.match(n)]
        if names:
            result.note(f"lock file defines {label}: {', '.join(sorted(names))}")
    if data.get("environments"):
        result.environments = True
        result.note("lock file is restricted to declared environments (never evaluated)")
    lines = _package_lines(text)
    packages = data.get("packages", [])
    if not isinstance(packages, list):
        result.fatal = True
        result.gap(file, None, "INVALID_FILE")
        return result
    for index, package in enumerate(packages):
        line = lines[index] if index < len(lines) else None
        if not isinstance(package, dict) or not _NAME.match(str(package.get("name", ""))):
            result.gap(file, line, "INVALID")
            continue
        name = normalize_name(package["name"])
        marker = package.get("marker") if isinstance(package.get("marker"), str) else None
        version = package.get("version")
        problem = _source_problem(package)
        if problem == "DIRECTORY" and _is_own_directory(package["directory"]):
            result.local_roots[name] = line
        if problem is not None:
            result.gap(file, line, problem, name)
        elif not isinstance(version, str) or not _VERSION.match(version):
            result.gap(file, line, "NO_VERSION", name)
        else:
            result.pins.append(Pin(name, version, file, line, marker, (), None))
    return result


# ------------------------------------------------------------------------ manifest discovery

UNSUPPORTED_NAMES = frozenset(
    {
        "pipfile",
        "pipfile.lock",
        "poetry.lock",
        "uv.lock",
        "pdm.lock",
        "environment.yml",
        "environment.yaml",
    }  # fmt: skip
)


def manifest_kind(relative_path: str) -> str | None:
    """'requirements', 'constraints', 'pylock', 'pyproject', 'setup.cfg', 'setup.py',
    'unsupported' or None (not a dependency manifest)."""
    parts = relative_path.casefold().split("/")
    name = parts[-1]
    if name == "pylock.toml" or (name.startswith("pylock.") and name.endswith(".toml")):
        return "pylock"
    if name.endswith((".txt", ".in")):
        if name.startswith("constraints"):
            return "constraints"
        if name.startswith("requirements") or (len(parts) > 1 and parts[-2] == "requirements"):
            return "requirements"
        return None
    if name == "pyproject.toml":
        return "pyproject"
    if name == "setup.cfg":
        return "setup.cfg"
    if name == "setup.py":
        return "setup.py"
    if name in UNSUPPORTED_NAMES:
        return "unsupported"
    return None


def _declares_dependencies_setup_cfg(text: str) -> bool | None:
    import configparser

    parser = configparser.ConfigParser(interpolation=None, strict=False)
    try:
        parser.read_string(text)
    except configparser.Error:
        return None
    return parser.has_option("options", "install_requires") or parser.has_section(
        "options.extras_require"
    )


def analyze_manifests(root: Path, inventory_paths: Collection[str]) -> list[ManifestResult]:
    """One result per dependency manifest of the inventory (constraints only as -c targets)."""
    results: list[ManifestResult] = []
    projects: list[tuple[ManifestResult, _Project]] = []
    for relative in sorted(inventory_paths):
        kind = manifest_kind(relative)
        if kind is None or kind == "constraints":
            continue
        if kind == "requirements":
            results.append(parse_requirements(root, relative, inventory_paths))
            continue
        result, project = _analyze_file(root, relative, kind)
        results.append(result)
        if project is not None:
            projects.append((result, project))
    for result, project in projects:
        folder = posixpath.dirname(result.file)
        locks = [
            r
            for r in results
            if r.kind == "pylock" and not r.fatal and posixpath.dirname(r.file) == folder
        ]
        _check_lock_coverage(result, project, locks)
    return results


def _analyze_file(root: Path, relative: str, kind: str) -> tuple[ManifestResult, "_Project | None"]:
    result = ManifestResult(file=relative, kind=kind)
    if kind in ("setup.py", "unsupported"):
        result.fatal = True
        result.gap(relative, None, "NOT_EXECUTED" if kind == "setup.py" else "UNSUPPORTED_FORMAT")
        return result, None
    text = read_text(root, relative)
    if text is None:
        result.fatal = True
        result.gap(relative, None, "UNREADABLE")
        return result, None
    if kind == "pylock":
        return parse_pylock(text, relative), None
    result.files_read.add(relative)
    if kind == "pyproject":
        return result, _analyze_pyproject(text, result)
    declares = _declares_dependencies_setup_cfg(text)
    if declares is None:
        result.fatal = True
        result.gap(relative, None, "INVALID_FILE")
    elif declares:
        result.fatal = True
        result.gap(relative, None, "UNSUPPORTED_FORMAT")
    else:
        result.note("no dependency declarations")
    return result, None


# ------------------------------------------------------------- pyproject.toml + pylock.toml
#
# PEP 621 / PEP 735 declarations are ranges, so they are never audited themselves. They count
# as covered only if a valid pylock.toml in the same directory provably pins each of them
# (D-045). The check is deliberately conservative: anything it cannot verify without
# evaluating the target environment stays a gap.


@dataclass(frozen=True)
class _Declaration:
    text: str
    group_marker: str | None  # "'dev' in dependency_groups": a lock marker that also covers it


@dataclass(frozen=True)
class _Project:
    name: str | None  # PEP 503 normalised [project].name
    text: str
    declarations: list[_Declaration] | None  # None: not checked (already reported as a gap)


def _analyze_pyproject(text: str, result: ManifestResult) -> _Project | None:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        result.fatal = True
        result.gap(result.file, None, "INVALID_FILE")
        return None
    project = data.get("project") if isinstance(data.get("project"), dict) else {}
    name = project.get("name")
    name = normalize_name(name) if isinstance(name, str) and _NAME.match(name) else None
    dynamic = project.get("dynamic") if isinstance(project.get("dynamic"), list) else []
    if _poetry_declares(data):
        result.fatal = True
        result.gap(result.file, None, "UNSUPPORTED_FORMAT")
        return _Project(name, text, None)
    if {"dependencies", "optional-dependencies"} & {str(d) for d in dynamic}:
        result.fatal = True
        result.gap(result.file, None, "DYNAMIC")
        return _Project(name, text, None)
    try:
        declarations = _declarations(data, project)
    except ValueError:
        result.fatal = True
        result.gap(result.file, None, "INVALID_FILE")
        return None
    if not declarations:
        result.note("no dependency declarations")
    return _Project(name, text, declarations)


def _poetry_declares(data: dict) -> bool:
    tool = data.get("tool")
    poetry = tool.get("poetry") if isinstance(tool, dict) else None
    if not isinstance(poetry, dict):
        return False
    dependencies = poetry.get("dependencies")
    return bool((isinstance(dependencies, dict) and set(dependencies) - {"python"})
                or poetry.get("group"))  # fmt: skip


def _strings(items: object, tables: bool = False) -> list[str]:
    if not isinstance(items, list):
        raise ValueError
    out = []
    for item in items:
        if isinstance(item, str):
            out.append(item)
        elif not (tables and isinstance(item, dict) and "include-group" in item):
            raise ValueError  # an included group is checked as a group of its own
    return out


def _declarations(data: dict, project: dict) -> list[_Declaration]:
    extras = project.get("optional-dependencies", {})
    groups = data.get("dependency-groups", {})
    if not isinstance(extras, dict) or not isinstance(groups, dict):
        raise ValueError
    out = [_Declaration(t, None) for t in _strings(project.get("dependencies", []))]
    for extra, items in extras.items():
        marker = f"'{normalize_name(str(extra))}' in extras"
        out += [_Declaration(t, marker) for t in _strings(items)]
    for group, items in groups.items():
        marker = f"'{normalize_name(str(group))}' in dependency_groups"
        out += [_Declaration(t, marker) for t in _strings(items, tables=True)]
    return out


def _check_lock_coverage(result: ManifestResult, project: _Project, locks: list) -> None:
    for lock in locks:
        if project.name in lock.local_roots:
            _exempt_own_directory(lock, project.name)
    if not project.declarations:
        return
    if not locks:
        result.fatal = True
        result.gap(result.file, None, "NOT_LOCKED")
        return
    if any(lock.environments for lock in locks):
        result.gap(result.file, None, "LOCK_ENVIRONMENT_UNVERIFIED")
    pins = [pin for lock in locks for pin in lock.pins]
    lines = project.text.splitlines()
    for declaration in project.declarations:
        reason, name = _coverage_problem(declaration, pins)
        if reason is not None:
            result.gap(result.file, _line_of(lines, declaration.text), reason, name)
    if not result.gaps:
        count = len(project.declarations)
        result.note(
            f"{count} declared dependenc{'y is' if count == 1 else 'ies are'} locked in "
            f"{', '.join(sorted(lock.file for lock in locks))} with a matching version and "
            "condition; transitive dependencies are audited as listed in the lock file"
        )


def _exempt_own_directory(lock: ManifestResult, name: str) -> None:
    line = lock.local_roots.pop(name)
    lock.gaps = [
        g
        for g in lock.gaps
        if not (g.reason == "DIRECTORY" and g.line == line and g.detail.endswith(f"({name})"))
    ]
    lock.note(
        "the project itself (directory '.') is not a third-party dependency and is not sent "
        "to OSV; its code is covered by the other scanners"
    )


def _coverage_problem(declaration: _Declaration, pins: list[Pin]) -> tuple[str | None, str | None]:
    text = declaration.text.strip()
    match = _REQUIREMENT.match(text)
    kind = _source_kind(text.split(";", 1)[0].strip())
    if kind is None and match and match.group("spec").startswith("@"):
        kind = "URL"
    if kind is not None:
        return kind, None
    if not match:
        return "INVALID", None
    name = normalize_name(match.group("name"))
    spec = match.group("spec") or ""
    if spec and spec.lstrip("(")[:1] not in ("<", ">", "=", "!", "~"):
        return "INVALID", name
    locked = [p for p in pins if p.name == name]
    if not locked:
        return "LOCK_MISSING", name
    verdicts = {satisfies(p.version, spec) for p in locked}
    if False in verdicts:
        return "LOCK_CONFLICT", name
    marker = _normalized_marker(match.group("marker"))
    accepted = {marker} if marker else {None, declaration.group_marker}
    if any(_normalized_marker(p.marker) not in accepted for p in locked):
        return "LOCK_CONDITION_UNVERIFIED", name
    if None in verdicts:
        return "LOCK_RANGE_UNVERIFIED", name
    return None, None


def _normalized_marker(marker: str | None) -> str | None:
    """Text form for comparison only (quotes and whitespace); markers are never evaluated."""
    if not marker or not marker.strip():
        return None
    return re.sub(r"\s+", " ", marker.replace('"', "'")).strip()


def _line_of(lines: list[str], text: str) -> int | None:
    needles = (f'"{text}"', f"'{text}'")
    for number, line in enumerate(lines, 1):
        if any(needle in line for needle in needles):
            return number
    return None


_RELEASE = re.compile(r"^\d+(?:\.\d+)*$")
_CLAUSE = re.compile(r"^(~=|==|!=|<=|>=|<|>)(\d+(?:\.\d+)*)(\.\*)?$")


def _release(text: str) -> tuple[int, ...]:
    return tuple(int(part) for part in text.split("."))


def _clause_holds(version: tuple[int, ...], operator: str, target: tuple[int, ...],
                  wildcard: bool) -> bool | None:  # fmt: skip
    if wildcard:
        if operator not in ("==", "!="):
            return None
        prefix = (version + (0,) * len(target))[: len(target)]
        return (prefix == target) == (operator == "==")
    if operator == "~=":
        if len(target) < 2:
            return None
        return bool(_clause_holds(version, ">=", target, False)
                    and _clause_holds(version, "==", target[:-1], True))  # fmt: skip
    width = max(len(version), len(target))
    left, right = version + (0,) * (width - len(version)), target + (0,) * (width - len(target))
    return {"==": left == right, "!=": left != right, "<=": left <= right,
            ">=": left >= right, "<": left < right, ">": left > right}[operator]  # fmt: skip


def satisfies(version: str, spec: str) -> bool | None:
    """Whether release ``version`` satisfies ``spec``; None when this cannot be verified here.

    A deliberate subset of PEP 440 (no new dependency): plain release versions (``1.2.3``) on
    both sides and ==, !=, <, <=, >, >=, ~= (== and != also with ``.*``). Pre-, post- and
    dev-releases, epochs, local versions and ``===`` are "not verifiable", never assumed.
    """
    spec = re.sub(r"\s+", "", spec).removeprefix("(").removesuffix(")")
    if not spec:
        return True
    if not _RELEASE.match(version):
        return None
    verdicts = set()
    for clause in spec.split(","):
        match = _CLAUSE.match(clause)
        if not match:
            verdicts.add(None)
            continue
        verdicts.add(_clause_holds(_release(version), match[1], _release(match[2]),
                                   bool(match[3])))  # fmt: skip
    if False in verdicts:
        return False
    return None if None in verdicts else True
