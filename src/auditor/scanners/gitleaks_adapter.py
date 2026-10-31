"""Gitleaks secret adapter (Gitleaks 8.30.1, official release binary; Stage 4a, D-043).

Method (user decision K1 = S, based on the step-0 measurements):

- Every inventory file is read by the auditor itself (no links followed, identity, size and
  mtime re-checked after reading: ``selection.read_regular_file``) and handed to its **own**
  ``gitleaks stdin`` process through a pipe. The report comes back through a pipe as well.
  Nothing derived from the target's content is ever written to disk (no mirror copies).
- Batched stdin is not used: a key split over two files matched as one (measured). ``gitleaks
  dir`` on the target is not used: the target's root ``.gitleaksignore`` is always applied,
  whatever ``--gitleaks-ignore-path`` says (measured).
- ``--config`` is one of the auditor's own, hash-verified files (all extend the pinned default
  rules); target ``.gitleaks.toml``, ``GITLEAKS_CONFIG*`` variables, ``.gitleaksignore`` and
  inline ``gitleaks:allow`` comments have no effect (measured; the working directory is an
  empty private directory and the environment is minimal).
- ``--redact=100`` and ``--log-level error`` are fixed: at debug/trace level Gitleaks writes the
  full secret to stderr even with ``--redact=100`` (measured). ``-v`` is never used. stderr is
  drained and discarded (only its size is known), never stored or shown.
- Only ``RuleID`` and ``StartLine`` are read from the report (an ``object_hook`` drops every
  other key while parsing). Secret, Match, Line, Fingerprint, Entropy, commit metadata and the
  tool's messages are never modelled. Columns are not kept either (they reveal length).
- **Path-conditioned rules** (D-043, revision): on stdin Gitleaks has no file name, so its four
  path-conditioned content rules never fire. For a file whose relative path matches one of
  those path regexes, the auditor selects a config that adds a verbatim, path-less copy of
  exactly that rule (``path-<rule>.toml``). Applying the copies to *all* files and filtering
  afterwards was measured to lose findings (Gitleaks drops a generic finding that overlaps a
  more specific rule's match), so a copy is only ever used where the original would apply.
  The path-only rule ``pkcs12-file`` is applied by the auditor from the file name and is
  reported as a *potentially sensitive file*, never as a detected secret value.
- **Proof of reading** (end marker): after the file's bytes, eight empty lines and a random,
  runtime-generated fake token are appended to the stdin stream. A file counts as scanned only
  if Gitleaks reports that token on its expected line; it is then removed from the results.
  This proves that the process read the stream to its end and that its rules were active, for
  small files too (exit 0 alone was not enough: a pipe buffer can swallow a small input). A
  self-check with known fake values runs before any target file is scanned.
"""

import base64
import hashlib
import json
import os
import re
import secrets
import string
import threading
import time
from collections import Counter
from collections.abc import Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from auditor.core.models import (
    Confidence,
    Evidence,
    FileCategory,
    FileEntry,
    Finding,
    FindingCategory,
    LimitedFile,
    NotAnalyzedFile,
    NotAnalyzedReason,
    Severity,
    ToolExecution,
    ToolStatus,
    VerificationStatus,
)
from auditor.core.policy import normalize_name
from auditor.core.safe_fs import PRIVATE_DIR_MODE, create_private_file
from auditor.findings.fingerprint import compute_fingerprint
from auditor.scanners.base import ScanContext, ScanOutcome
from auditor.scanners.executables import (
    GITLEAKS_VERSION,
    gitleaks_executable,
    pinned_gitleaks_sha256,
    resolves_inside,
    sha256_of,
)
from auditor.scanners.git_ids import git_blob_id
from auditor.scanners.runner import minimal_env, run_tool_stdin
from auditor.scanners.selection import read_regular_file

TOOL = "gitleaks"
RULE_PREFIX = "gitleaks."
CONFIG_DIR = Path(__file__).resolve().parent.parent / "rules" / "gitleaks"
BASE_CONFIG = "gitleaks.toml"
CONFIG_PATH = CONFIG_DIR / BASE_CONFIG
CONFIG_HASHES = {
    "gitleaks.toml": "41454b4a7bbb785083203a33c9f0ce3ad985a0a29cbece9fc7619bc022daf43d",
    "path-kubernetes-secret-yaml.toml": (
        "48a8cccad69675cea02785cd7757aa632da9889e8e3209a8d3650c0f0732cb76"
    ),
    "path-hashicorp-tf-password.toml": (
        "ffd5df029bcbe7041fbdab16b37281d8042a37b6196e52abd3cffa414fa3abaa"
    ),
    "path-nuget-config-password.toml": (
        "0523e17dcdc2922cf1f23f60c01b71e62a47bd119a55eca765c13f714dec828e"
    ),
    "path-freemius-secret-key.toml": (
        "cfe586c75a815c2dea102f828d7025ab300ad23acc4ce59dc26b984d8927e984"
    ),
}
PATHLESS_PREFIX = "auditor-pathless-"
DEFAULT_WORKERS = 4
MAX_WORKERS = 16

# argv after the executable; "{config}" and "{ignore}" are filled with private paths.
ARGV_TEMPLATE = (
    "stdin",
    "--config", "{config}",
    "--gitleaks-ignore-path", "{ignore}",
    "--ignore-gitleaks-allow",
    "--redact=100",
    "--log-level", "error",
    "--no-banner",
    "--no-color",
    "--exit-code", "0",
    "--report-format", "json",
    "--report-path", "-",
    "--max-archive-depth", "0",
)  # fmt: skip
FORBIDDEN_ARGS = ("-v", "--verbose", "--diagnostics", "--baseline-path", "--enable-rule")
# Only these keys ever leave the JSON parser: rule id and position. Secret, Match, Line,
# Fingerprint, Entropy and git metadata are dropped while parsing (object hook).
_ALLOWED_KEYS = ("RuleID", "StartLine", "StartColumn", "EndColumn")
_RULE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,79}$")


@dataclass(frozen=True)
class PathRule:
    rule: str
    path: str  # the path regex exactly as in the pinned default config
    config: str | None  # per-rule config with a path-less copy; None: applied by the auditor


# Every path-conditioned rule of the pinned Gitleaks 8.30.1 default config (a test compares
# this table with the config embedded in the binary).
PATH_RULES = (
    PathRule("kubernetes-secret-yaml", r"(?i)\.ya?ml$", "path-kubernetes-secret-yaml.toml"),
    PathRule("hashicorp-tf-password", r"(?i)\.(?:tf|hcl)$", "path-hashicorp-tf-password.toml"),
    PathRule("nuget-config-password", r"(?i)nuget\.config$", "path-nuget-config-password.toml"),
    PathRule("freemius-secret-key", r"(?i)\.php$", "path-freemius-secret-key.toml"),
    PathRule("pkcs12-file", r"(?i)(?:^|\/)[^\/]+\.p(?:12|fx)$", None),
)
_PATH_REGEX = {p.rule: re.compile(p.path) for p in PATH_RULES}
# Path allowlists of the default config that stdin cannot apply (more findings, never fewer).
PATH_ALLOWLISTS_NOT_APPLIED = (
    "global path allowlist (lockfiles, images, fonts, office documents, vendored code, ...)",
    "generic-api-key: .bb/.bbappend/.bbclass/.inc files",
    "github-pat, github-app-token: @octokit/auth-token/README.md",
)
END_MARKER_GAP = 8  # measured: breaks bounded multi-line matches between file and marker
END_MARKER_RULE = "github-pat"

CRITICAL_RULES = frozenset({"private-key"})
GENERIC_RULES = {"generic-api-key": Confidence.LOW, "jwt": Confidence.MEDIUM,
                 "jwt-base64": Confidence.MEDIUM}  # fmt: skip
UNDECODED = re.compile(
    r"(?i)\.(?:zip|jar|war|ear|whl|egg|tar|tgz|gz|bz2|xz|7z|rar|apk|nupkg|"
    r"docx|xlsx|pptx|odt|ods|odp|pdf)$"
)
# Formats the pinned Gitleaks does not scan as text (measured: no end marker is reported for
# input starting with these headers). A missing marker on such input is a known format gap
# (SKIPPED_BY_TOOL), not a tool failure. Re-measured by a test on every Gitleaks upgrade.
SKIPPED_FORMATS: dict[bytes, str] = {
    b"PK\x03\x04": "zip archive",
    b"PK\x05\x06": "zip archive (empty)",
    b"\x1f\x8b": "gzip archive",
    b"%PDF": "PDF document",
    b"7z\xbc\xaf\x27\x1c": "7-Zip archive",
    b"Rar!\x1a\x07": "RAR archive",
    b"BZh": "bzip2 archive",
    b"SQLite format 3\x00": "SQLite database",
}
ARCHIVE_MAGIC = tuple(SKIPPED_FORMATS)


def skipped_format(data: bytes, name: str | None = None) -> str | None:
    """Name of the format Gitleaks is known not to scan, from the header (or the file name)."""
    for magic, label in SKIPPED_FORMATS.items():
        if data.startswith(magic):
            return label
    if name is not None and UNDECODED.search(normalize_name(name)):
        return "archive or compressed format (by file name)"
    return None


TARGET_GITLEAKS_FILES = (".gitleaks.toml", ".gitleaksignore")
RECOMMENDATION = (
    "Treat the value as exposed: revoke or rotate it at its issuer, remove it from the file "
    "(and from version-control history), and load it at runtime from a secret manager or the "
    "environment. If it is test data, replace it with an obviously fake placeholder."
)
PKCS12_RECOMMENDATION = (
    "Check whether the container holds a private key. If it does, remove it from the "
    "repository (and its history) and replace the key; keep key material out of source control."
)


@dataclass(frozen=True)
class GitleaksOptions:
    workers: int = DEFAULT_WORKERS
    file_timeout: float = 60.0
    total_timeout: float = 900.0
    max_file_bytes: int = 10 * 1024 * 1024
    max_output_bytes: int = 2 * 1024 * 1024
    config_dir: Path = CONFIG_DIR
    config_hashes: Mapping[str, str] = field(default_factory=lambda: dict(CONFIG_HASHES))

    def __post_init__(self) -> None:
        if not 1 <= self.workers <= MAX_WORKERS:
            raise ValueError(f"workers must be between 1 and {MAX_WORKERS}")


@dataclass
class _Run:
    findings: list[Finding] = field(default_factory=list)
    not_analyzed: list[NotAnalyzedFile] = field(default_factory=list)
    limited: list[LimitedFile] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    exit_codes: set[int] = field(default_factory=set)
    analyzed: int = 0
    inline_allows: int = 0
    seen_ids: set[str] = field(default_factory=set)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def warn(self, message: str) -> None:
        if message not in self.warnings:
            self.warnings.append(message)

    def skip(self, entry: FileEntry, reason: NotAnalyzedReason, detail: str | None) -> None:
        self.not_analyzed.append(
            NotAnalyzedFile(relative_path=entry.relative_path, reason=reason, detail=detail)
        )

    def finding_id(self, fingerprint: str) -> str:
        finding_id, suffix = f"{TOOL}-{fingerprint[:16]}", 2
        while finding_id in self.seen_ids:
            finding_id, suffix = f"{TOOL}-{fingerprint[:16]}-{suffix}", suffix + 1
        self.seen_ids.add(finding_id)
        return finding_id


def _keep_allowed(obj: dict) -> dict:
    return {key: obj[key] for key in _ALLOWED_KEYS if key in obj}


@dataclass(frozen=True)
class Hit:
    """One Gitleaks result reduced to rule id and position (never the value)."""

    rule: object
    line: object
    start_column: int | None = None
    end_column: int | None = None


def _column(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 1 else None


def parse_hits(stdout: bytes) -> list[Hit]:
    """Hits from a Gitleaks JSON report; other keys never leave the parser."""
    text = stdout.decode("utf-8").strip()
    if not text:
        raise ValueError("no report")
    data = json.loads(text, object_hook=_keep_allowed)
    if not isinstance(data, list) or not all(isinstance(item, dict) for item in data):
        raise TypeError("unexpected report format")
    return [
        Hit(item.get("RuleID"), item.get("StartLine"), _column(item.get("StartColumn")),
            _column(item.get("EndColumn")))
        for item in data
    ]  # fmt: skip


def parse_report(stdout: bytes) -> list[tuple[str, object]]:
    """[(RuleID, StartLine)] from a Gitleaks JSON report (used by the history scan)."""
    return [(hit.rule, hit.line) for hit in parse_hits(stdout)]


def end_marker() -> bytes:
    """A random fake token in a format the default rules detect (never a real secret)."""
    alphabet = string.ascii_letters + string.digits
    return ("ghp_" + "".join(secrets.choice(alphabet) for _ in range(36))).encode("ascii")


def with_end_marker(data: bytes, marker: bytes) -> tuple[bytes, int]:
    """(stdin payload, line Gitleaks must report the marker on)."""
    prefix = data if (not data or data.endswith(b"\n")) else data + b"\n"
    return prefix + b"\n" * END_MARKER_GAP + marker + b"\n", prefix.count(
        b"\n"
    ) + END_MARKER_GAP + 1


def config_for(relative_path: str) -> tuple[str, str | None]:
    """(config file, path rule applied through it) for a file, decided by its path alone."""
    name = normalize_name(relative_path)
    matching = [p for p in PATH_RULES if p.config and _PATH_REGEX[p.rule].search(name)]
    if len(matching) == 1:
        return matching[0].config, matching[0].rule
    return BASE_CONFIG, None


class GitleaksAdapter:
    name = TOOL

    def __init__(
        self,
        options: GitleaksOptions | None = None,
        command: Sequence[str] | None = None,
        tools_base: Path | None = None,
    ):
        self.options = options or GitleaksOptions()
        self.pinned: str | None = None
        if command is None:
            executable = gitleaks_executable(tools_base)
            command = [str(executable)] if executable else None
            self.pinned = "required"
        self.command = list(command) if command else None
        self.settings = {
            "method": "one `gitleaks stdin` process per file; no copies of file content on disk",
            "workers": str(self.options.workers),
            "config": "auditor's own (extends the pinned default rules), SHA-256 verified",
            "redaction": "--redact=100; only rule id and line are kept, never the value",
            "log_level": "error (fixed; debug/trace would print secrets)",
            "target_config": "target .gitleaks.toml, .gitleaksignore, gitleaks:allow and "
            "GITLEAKS_* variables are ignored",
            "input_check": "end marker per file (proves the whole input was read) and a "
            "self-check with known fake values before the scan",
            "path_rules": "applied: content on stdin, path condition by the auditor "
            "(kubernetes-secret-yaml, hashicorp-tf-password, nuget-config-password, "
            "freemius-secret-key); pkcs12-file from the file name only",
            "path_allowlists": "not applied on stdin, may add false positives: "
            + "; ".join(PATH_ALLOWLISTS_NOT_APPLIED),
            "scope_git_history": "NOT_SCANNED (Stage 4b: separate scan, needs explicit permission)",
            "network": "not used (local rules only)",
        }

    def scan(self, context: ScanContext) -> ScanOutcome:
        outcome = self._scan_impl(context)
        applicable = [f.relative_path for f in _eligible(context.files)]
        return ScanOutcome(outcome.execution, outcome.findings, applicable)

    def _scan_impl(self, context: ScanContext) -> ScanOutcome:
        started = time.monotonic()
        eligible = _eligible(context.files)

        def stop(status: ToolStatus, reason: str, version: str | None = None) -> ScanOutcome:
            return ScanOutcome(
                ToolExecution(
                    tool=TOOL,
                    version=version,
                    status=status,
                    reason=reason,
                    duration_seconds=round(time.monotonic() - started, 3),
                    files_requested=len(eligible),
                    settings={**self.settings, "scope_working_tree": "NOT_SCANNED (did not run)"},
                ),
                [],
            )

        refusal = self._refusal(context.root)
        if refusal is not None:
            return stop(*refusal)
        if not eligible:
            return stop(ToolStatus.SKIPPED, "No files in the inventory")
        configs = self._verified_configs()  # the bytes written are the bytes that are verified
        if configs is None:
            return stop(ToolStatus.ERROR, "Gitleaks configuration integrity check failed")

        argv, cwd, env = self._prepare(context.workspace, configs)
        version = read_gitleaks_version(self.command, cwd, env)
        problem = _self_check(argv, cwd, env, self.options.file_timeout)
        if problem is not None:
            return stop(ToolStatus.ERROR, f"Gitleaks self-check failed: {problem}", version)
        run = _Run()
        if version != GITLEAKS_VERSION:
            run.warn(
                f"Gitleaks {version or 'unknown'} differs from the pinned {GITLEAKS_VERSION}; "
                "rules and output format may differ."
            )
        deadline = started + self.options.total_timeout
        timed_out = threading.Event()

        def task(entry: FileEntry) -> None:
            if _PATH_REGEX["pkcs12-file"].search(normalize_name(entry.relative_path)):
                with run.lock:
                    _add_pkcs12(entry, run)  # needs no content
            if time.monotonic() >= deadline:
                timed_out.set()
                with run.lock:
                    run.skip(entry, NotAnalyzedReason.TIMED_OUT, "total time limit reached")
                return
            self._scan_file(context.root, entry, argv, cwd, env, deadline, run, timed_out)

        with ThreadPoolExecutor(max_workers=self.options.workers) as pool:
            list(pool.map(task, eligible))

        return self._finish(context, eligible, run, version, started, timed_out.is_set())

    def _prepare(self, work: Path, configs: dict[str, bytes]):
        """Private cwd/HOME/TEMP, the verified configs and one argv per config."""
        cwd, home, tmp, config_dir = work / "cwd", work / "home", work / "tmp", work / "config"
        for directory in (cwd, home, tmp, config_dir):
            directory.mkdir(mode=PRIVATE_DIR_MODE)
        ignore = work / "empty.gitleaksignore"
        create_private_file(ignore, "")
        argv = {}
        for name, data in configs.items():
            create_private_file(config_dir / name, data.decode("utf-8"))
            argv[name] = [
                *self.command,
                *(a.format(config=config_dir / name, ignore=ignore) for a in ARGV_TEMPLATE),
            ]
        env = minimal_env(tmp, extra={"HOME": str(home), "USERPROFILE": str(home)})
        return argv, cwd, env

    def _verified_configs(self) -> dict[str, bytes] | None:
        configs = {}
        for name, expected in self.options.config_hashes.items():
            try:
                data = (self.options.config_dir / name).read_bytes()
            except OSError:
                return None
            if hashlib.sha256(data).hexdigest() != expected:
                return None
            configs[name] = data
        needed = {BASE_CONFIG, *(p.config for p in PATH_RULES if p.config)}
        return configs if needed <= set(configs) else None

    def _finish(self, context, eligible, run: _Run, version, started, timed_out) -> ScanOutcome:
        """Warnings, overall status and the ToolExecution of a completed run."""
        targets = [e for e in context.files if _name(e) in TARGET_GITLEAKS_FILES]
        if targets:
            run.warn(
                f"{len(targets)} Gitleaks configuration/ignore file(s) found in the target "
                "(.gitleaks.toml/.gitleaksignore); they were ignored."
            )
        if run.inline_allows:
            run.warn(
                f"{run.inline_allows} inline 'gitleaks:allow' comment(s) found; they were "
                "ignored and the findings are still reported."
            )
        attempted = len(eligible) - sum(
            1 for n in run.not_analyzed if n.reason is NotAnalyzedReason.SIZE_LIMIT
        )
        if timed_out:
            status, reason = ToolStatus.TIMED_OUT, "Gitleaks did not finish within the time limit"
        elif attempted and run.analyzed == 0 and run.not_analyzed:
            status, reason = ToolStatus.ERROR, "Gitleaks failed for every file"
        else:
            status = ToolStatus.SUCCESS
            reason = f"Completed; {run.analyzed} of {len(eligible)} files analyzed"
        order = {e.relative_path: i for i, e in enumerate(eligible)}
        run.not_analyzed.sort(key=lambda n: order[n.relative_path])
        run.limited.sort(key=lambda n: order[n.relative_path])
        run.findings.sort(key=lambda f: (order[f.relative_path], f.start_line or 0, f.rule_id))
        execution = ToolExecution(
            tool=TOOL,
            version=version,
            status=status,
            reason=reason,
            exit_codes=sorted(run.exit_codes),
            duration_seconds=round(time.monotonic() - started, 3),
            files_requested=len(eligible),
            files_analyzed=run.analyzed,
            not_analyzed=run.not_analyzed,
            settings={**self.settings, "scope_working_tree": _working_tree_scope(run, eligible)},
            command_summary="gitleaks stdin (one process per file)",
            stderr_excerpt=None,
            warnings=run.warnings,
            coverage_limitations=run.limited,
        )
        return ScanOutcome(execution, run.findings)

    def _refusal(self, root: Path) -> tuple[ToolStatus, str] | None:
        """Why Gitleaks must not run at all (missing, untrusted, unverified), or None."""
        if self.command is None:
            return (
                ToolStatus.NOT_INSTALLED,
                f"Gitleaks {GITLEAKS_VERSION} not found in the auditor's tool directory "
                "(<tools>/gitleaks)",
            )
        executable = Path(self.command[0])
        if resolves_inside(executable, root):
            return (
                ToolStatus.ERROR,
                "Gitleaks executable resolves inside the scan target; refused (untrusted)",
            )
        if self.pinned is not None:
            expected = pinned_gitleaks_sha256()
            if expected is None:
                return ToolStatus.ERROR, "There is no pinned Gitleaks hash for this platform"
            if sha256_of(executable) != expected:
                return (
                    ToolStatus.ERROR,
                    f"Gitleaks executable SHA-256 does not match the pinned {GITLEAKS_VERSION} "
                    "release; refused",
                )
        return None

    def _scan_file(self, root, entry, argv, cwd, env, deadline, run, timed_out) -> None:
        path = os.path.join(os.fspath(root), *entry.relative_path.split("/"))
        read = read_regular_file(path, self.options.max_file_bytes)
        if read.data is None:
            with run.lock:
                run.skip(entry, read.reason, read.detail)
            return
        config, path_rule = config_for(entry.relative_path)
        marker = end_marker()
        payload, marker_line = with_end_marker(read.data, marker)
        lines = read.data.count(b"\n") + 1
        # Stage 6 (R2): git blob ids of exactly these bytes (before the end marker); kept in
        # memory only (Finding.content_ids is never serialised). Detection is unaffected.
        content_ids = {fmt: git_blob_id(read.data, fmt) for fmt in ("sha1", "sha256")}
        allows = read.data.count(b"gitleaks:allow")
        known_skip = skipped_format(read.data, entry.relative_path)
        remaining = deadline - time.monotonic()
        result = run_tool_stdin(
            argv[config],
            data=payload,
            cwd=cwd,
            env=env,
            timeout=max(0.1, min(self.options.file_timeout, remaining)),
            stdout_limit=self.options.max_output_bytes,
        )
        del payload, read, marker  # the content is not kept beyond this point
        if result.timed_out and time.monotonic() >= deadline:
            timed_out.set()
        failure, hits = _classify(result)
        if failure is None and not any(
            (h.rule, h.line) == (END_MARKER_RULE, marker_line) for h in hits
        ):
            failure = (
                # measured per format (SKIPPED_FORMATS): such input is not scanned as text
                (
                    NotAnalyzedReason.SKIPPED_BY_TOOL,
                    f"{known_skip}: not scanned by Gitleaks (binary format; contents are not "
                    "extracted)",
                )
                if known_skip
                else (
                    NotAnalyzedReason.TOOL_ERROR,
                    "Gitleaks did not confirm reading the whole input (end marker not reported)",
                )
            )
        with run.lock:
            if result.exit_code is not None:
                run.exit_codes.add(result.exit_code)
            if failure is not None:
                run.skip(entry, *failure)
                return
            marker = next(h for h in hits if (h.rule, h.line) == (END_MARKER_RULE, marker_line))
            hits.remove(marker)
            run.analyzed += 1
            run.inline_allows += allows
            if UNDECODED.search(normalize_name(entry.relative_path)):
                run.limited.append(
                    LimitedFile(
                        relative_path=entry.relative_path,
                        reason="CONTENT_NOT_DECODED",
                        detail="archive or compressed document: contents were not extracted",
                    )
                )
            # P9: identities must not depend on Gitleaks' per-file result order, which is not
            # stable between runs. Sort by position; number only exact duplicates (same rule,
            # line and columns), and mark them, so nothing is guessed from the order.
            positions = Counter((h.rule, h.line, h.start_column, h.end_column) for h in hits)
            seen: Counter = Counter()
            for hit in sorted(hits, key=_position_key):
                where = (hit.rule, hit.line, hit.start_column, hit.end_column)
                _map(entry, hit, lines, seen[where], positions[where] > 1, path_rule, run,
                     content_ids)  # fmt: skip
                seen[where] += 1


def _self_check(argv: dict, cwd: Path, env: dict, timeout: float) -> str | None:
    """Known fake values must be found before any target file is trusted to be scanned."""
    alphabet = string.ascii_letters + string.digits
    value = base64.b64encode("".join(secrets.choice(alphabet) for _ in range(24)).encode()).decode()
    k8s = f"apiVersion: v1\nkind: Secret\ndata:\n  password: {value}\n".encode()
    cases = (
        (BASE_CONFIG, b"x = 1\n", None),
        ("path-kubernetes-secret-yaml.toml", k8s, PATHLESS_PREFIX + "kubernetes-secret-yaml"),
    )
    for config, data, expected_rule in cases:
        payload, marker_line = with_end_marker(data, end_marker())
        result = run_tool_stdin(
            argv[config], data=payload, cwd=cwd, env=env, timeout=timeout, stdout_limit=65536
        )
        failure, items = _classify(result)
        if failure is not None:
            return failure[1]
        if not any((h.rule, h.line) == (END_MARKER_RULE, marker_line) for h in items):
            return "a known test token was not detected"
        if expected_rule and not any(h.rule == expected_rule for h in items):
            return "the path-rule configuration did not detect a known test value"
    return None


def _add_pkcs12(entry: FileEntry, run: _Run) -> None:
    """``pkcs12-file`` is a file-name rule: a potentially sensitive file, not a secret value."""
    rule_id = RULE_PREFIX + "pkcs12-file"
    fingerprint = compute_fingerprint(
        tool=TOOL,
        rule_id=rule_id,
        relative_path=entry.relative_path,
        start=(None, None),
        end=(None, None),
        message="file name",
    )
    tags = ["POTENTIALLY_SENSITIVE_FILE", "file-name-only"]
    tags += ["test-path"] if entry.category is FileCategory.TEST else []
    run.findings.append(
        Finding(
            finding_id=run.finding_id(fingerprint),
            fingerprint=fingerprint,
            source_tool=TOOL,
            rule_id=rule_id,
            title="Potentially sensitive file (PKCS#12 key/certificate container)",
            description=(
                "Reported from the file name only (Gitleaks rule 'pkcs12-file', applied by the "
                "auditor). Such containers often bundle private keys. No secret value was "
                "detected or read for this finding."
            ),
            category=FindingCategory.SECURITY,
            severity=Severity.MEDIUM,
            confidence=Confidence.LOW,
            verification_status=VerificationStatus.NEEDS_REVIEW,
            relative_path=entry.relative_path,
            evidence=[Evidence(kind="file-name", reference=entry.relative_path)],
            recommendation=PKCS12_RECOMMENDATION,
            tags=tags,
        )
    )


def _position_key(hit: Hit) -> tuple:
    return (str(hit.rule), hit.line if isinstance(hit.line, int) else -1,
            hit.start_column or 0, hit.end_column or 0)  # fmt: skip


def _map(entry, hit: Hit, lines, occurrence, duplicate, path_rule, run: _Run,
         content_ids=None) -> None:  # fmt: skip
    rule, line = hit.rule, hit.line
    if not isinstance(rule, str) or not _RULE_ID.match(rule):
        run.warn("A result with an unexpected rule id was dropped.")
        return
    tags = ["secret"]
    if rule.startswith(PATHLESS_PREFIX):
        rule = rule.removeprefix(PATHLESS_PREFIX)
        if rule != path_rule:  # defensive: copies are only configured where the path matches
            run.warn("A path-rule result for a non-matching file was dropped.")
            return
        tags.append("path-rule-applied-by-auditor")
    if not isinstance(line, int) or isinstance(line, bool) or not 1 <= line <= lines:
        run.warn("A result with an invalid line number was dropped.")
        return
    rule_id = RULE_PREFIX + rule
    # Identity = tool, rule, path, line and columns (location metadata only; never the value).
    # `match N` numbers exact duplicates that no safe metadata can tell apart; such findings
    # are tagged so the ambiguity is visible instead of being resolved by guessing.
    fingerprint = compute_fingerprint(
        tool=TOOL,
        rule_id=rule_id,
        relative_path=entry.relative_path,
        start=(line, hit.start_column),
        end=(line, hit.end_column),
        message=f"match {occurrence}",
    )
    tags += ["test-path"] if entry.category is FileCategory.TEST else []
    tags += ["duplicate-match"] if duplicate else []
    run.findings.append(
        Finding(
            finding_id=run.finding_id(fingerprint),
            fingerprint=fingerprint,
            source_tool=TOOL,
            rule_id=rule_id,
            title=f"Potential secret ({rule})",
            description=(
                f"Gitleaks rule '{rule}' matched on this line. The matched value is never "
                "stored or shown; review the line locally."
            ),
            category=FindingCategory.SECURITY,
            severity=Severity.CRITICAL
            if rule in CRITICAL_RULES
            else Severity.MEDIUM
            if rule in GENERIC_RULES
            else Severity.HIGH,
            original_severity=None,
            confidence=GENERIC_RULES.get(rule, Confidence.HIGH),
            verification_status=VerificationStatus.NEEDS_REVIEW,
            relative_path=entry.relative_path,
            start_line=line,
            start_column=hit.start_column,
            end_line=line,
            end_column=hit.end_column,
            evidence=[
                Evidence(
                    kind="secret-location",
                    reference=f"{entry.relative_path}:{line}",
                    redacted=True,
                )
            ],
            recommendation=RECOMMENDATION,
            tags=tags,
            content_ids=content_ids or {},
        )
    )


def _working_tree_scope(run: _Run, eligible: Sequence[FileEntry]) -> str:
    if run.analyzed == 0:
        return "NOT_SCANNED (no file could be analyzed)"
    if run.not_analyzed:
        return f"PARTIALLY_SCANNED ({run.analyzed} of {len(eligible)} files)"
    if run.limited:
        return f"SCANNED ({len(run.limited)} file(s) with limitations)"
    return "SCANNED (all inventory files)"


def _classify(result) -> tuple[tuple[NotAnalyzedReason, str] | None, list]:
    """(failure, items): exit code 0, full input and a JSON array are all required."""
    if result.launch_error is not None:
        return (NotAnalyzedReason.TOOL_ERROR, "Gitleaks could not be started"), []
    if result.timed_out:
        return (NotAnalyzedReason.TIMED_OUT, "Gitleaks timed out on this file"), []
    if result.exit_code != 0:
        return (NotAnalyzedReason.TOOL_ERROR, f"exit code {result.exit_code}"), []
    if not result.input_complete:
        return (NotAnalyzedReason.TOOL_ERROR, "input not fully consumed by Gitleaks"), []
    if result.stdout_truncated:
        return (NotAnalyzedReason.TOOL_ERROR, "output too large"), []
    try:
        return None, parse_hits(result.stdout)
    except UnicodeDecodeError:
        return (NotAnalyzedReason.TOOL_ERROR, "invalid JSON (not UTF-8)"), []
    except ValueError as exc:
        detail = "no report" if str(exc) == "no report" else "invalid JSON"
        return (NotAnalyzedReason.TOOL_ERROR, detail), []
    except TypeError:
        return (NotAnalyzedReason.TOOL_ERROR, "unexpected report format"), []


def read_gitleaks_version(
    command: Sequence[str], cwd: Path, env: dict[str, str] | None = None
) -> str | None:
    env = env if env is not None else minimal_env(cwd, extra={"HOME": str(cwd)})
    result = run_tool_stdin(
        [*command, "version"], data=b"", cwd=cwd, env=env, timeout=30, stdout_limit=256
    )
    if result.exit_code != 0 or result.timed_out:
        return None
    text = result.stdout.decode("ascii", "replace").strip()
    return text if re.fullmatch(r"v?\d+\.\d+\.\d+", text) else None


def config_is_intact(
    directory: Path = CONFIG_DIR, hashes: Mapping[str, str] = CONFIG_HASHES
) -> bool:
    try:
        return all(
            hashlib.sha256((directory / name).read_bytes()).hexdigest() == digest
            for name, digest in hashes.items()
        )
    except OSError:
        return False


def _name(entry: FileEntry) -> str:
    return entry.relative_path.rsplit("/", 1)[-1]


def _eligible(files: Sequence[FileEntry]) -> list[FileEntry]:
    return [f for f in files if f.secret_scan_eligible]
