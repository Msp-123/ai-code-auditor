"""Command-line interface.

Commands: ``--help``, ``--version``, ``doctor`` and ``scan`` (discovery, Ruff, Semgrep and
Gitleaks).
Commands that are not implemented yet (``report``) are intentionally absent rather than
stubbed.
"""

import contextlib
import platform
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

import typer

from auditor import __version__
from auditor.application.audit_service import IMPLEMENTED_SCANNERS, run_audit
from auditor.core.config import default_reports_base, default_tools_base
from auditor.core.errors import ReportWriteError, TargetPathError
from auditor.core.policy import DEFAULT_MAX_FILES, ScanPolicy
from auditor.core.redaction import sanitize_for_display
from auditor.findings.gate import (
    EXIT_INTERNAL_ERROR,
    EXIT_INVALID_INPUT,
    FAIL_ON_CHOICES,
    UNRATED_CHOICES,
    decide_exit,
    parse_policy,
)
from auditor.reports.loader import ReportLoadError, load_report
from auditor.reports.markdown_report import render_markdown
from auditor.reports.terminal_summary import summary
from auditor.reports.writer import render_report_json
from auditor.scanners.executables import (
    PIP_AUDIT_VERSION,
    gitleaks_executable,
    pinned_gitleaks_sha256,
    pip_audit_python,
    semgrep_executable,
    sha256_of,
)
from auditor.scanners.git_history import find_git
from auditor.scanners.git_history_adapter import GitHistoryOptions
from auditor.scanners.gitleaks_adapter import (
    DEFAULT_WORKERS,
    MAX_WORKERS,
    GitleaksOptions,
    config_is_intact,
    read_gitleaks_version,
)
from auditor.scanners.pip_audit_adapter import PipAuditOptions
from auditor.scanners.ruff_adapter import (
    DEFAULT_TARGET_PYTHON,
    SUPPORTED_PYTHON,
    RuffOptions,
    find_ruff_executable,
    read_version,
    to_ruff_target,
)
from auditor.scanners.runner import minimal_env, run_tool
from auditor.scanners.semgrep_adapter import read_semgrep_version, short_temp_base
from auditor.scanners.semgrep_rules import RulesetError, load_ruleset

MIN_PYTHON = (3, 12)  # the only verified version (release policy, D-052)

app = typer.Typer(
    name="auditor",
    help="AI Code Auditor: evidence-based, read-only audit of local Python projects.",
    no_args_is_help=True,
    add_completion=False,
    # Tracebacks must never dump local variables (paths, data) to the terminal.
    pretty_exceptions_show_locals=False,
)


def check_python_version(version_info: Sequence[int]) -> tuple[bool, str]:
    """Return whether the given interpreter version meets the minimum requirement."""
    current = ".".join(str(part) for part in version_info[:3])
    required = ".".join(str(part) for part in MIN_PYTHON)
    if tuple(version_info[:2]) >= MIN_PYTHON:
        return True, f"Python {current} (>= {required} required)"
    return False, f"Python {current} is not supported; Python >= {required} is required"


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"auditor {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        help="Show the version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    """AI Code Auditor: evidence-based, read-only audit of local Python projects."""


@app.command()
def doctor() -> None:
    """Check the auditor's environment (its own Ruff, Semgrep and Gitleaks are queried)."""
    ok, message = check_python_version(sys.version_info)
    in_venv = sys.prefix != sys.base_prefix

    typer.echo(f"auditor     {__version__}")
    typer.echo(f"platform    {platform.platform()}")
    typer.echo(f"python      {message}")
    typer.echo(f"executable  {sys.executable}")
    typer.echo(f"venv        {'yes' if in_venv else 'no (an isolated environment is recommended)'}")

    problems = [] if ok else [message]
    executable = find_ruff_executable()
    version = None
    if executable is not None:
        with tempfile.TemporaryDirectory(prefix="auditor-doctor-") as workspace:
            version = read_version([str(executable)], Path(workspace))
    if version:
        typer.echo(f"ruff        {version} ({executable})")
    else:
        typer.echo("ruff        NOT FOUND in the auditor's environment")
        problems.append("Ruff is not installed in the auditor's environment")

    semgrep = semgrep_executable()
    semgrep_version = None
    if semgrep is not None:
        # Short private scratch: Semgrep writes HOME/.semgrep even for --version.
        short_base = short_temp_base()
        short_base.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="d-", dir=short_base) as scratch:
            semgrep_version = read_semgrep_version([str(semgrep)], Path(scratch))
    if semgrep_version:
        typer.echo(f"semgrep     {semgrep_version} ({semgrep})")
    else:
        typer.echo(f"semgrep     NOT FOUND at {default_tools_base() / 'semgrep'} (scans: PARTIAL)")
        problems.append("Semgrep is not installed in the auditor's tool environment")
    try:
        ruleset = load_ruleset()
        typer.echo(f"ruleset     {ruleset.version} (sha256 {ruleset.digest[:16]}..., verified)")
    except RulesetError as exc:
        typer.echo("ruleset     INTEGRITY CHECK FAILED")
        problems.append(f"Semgrep ruleset: {exc}")

    problems += _doctor_gitleaks()
    problems += _doctor_pip_audit()
    git = find_git()
    typer.echo(f"git         {git} (used only with --scan-git-history)" if git else
               "git         NOT FOUND (needed only for --scan-git-history)")  # fmt: skip
    if problems:
        for problem in problems:
            typer.echo(f"ERROR: {problem}", err=True)
        raise typer.Exit(code=1)
    typer.echo("status      OK")


def _doctor_gitleaks() -> list[str]:
    problems = []
    gitleaks = gitleaks_executable()
    if gitleaks is None:
        typer.echo(f"gitleaks    NOT FOUND at {default_tools_base() / 'gitleaks'} (scans: PARTIAL)")
        problems.append("Gitleaks is not installed in the auditor's tool directory")
    elif sha256_of(gitleaks) != pinned_gitleaks_sha256():
        typer.echo(f"gitleaks    SHA-256 MISMATCH ({gitleaks}); it will not be run")
        problems.append("Gitleaks executable does not match the pinned release hash")
    else:
        with tempfile.TemporaryDirectory(prefix="auditor-doctor-") as workspace:
            version = read_gitleaks_version([str(gitleaks)], Path(workspace))
        typer.echo(f"gitleaks    {version or 'unknown'} ({gitleaks}, SHA-256 verified)")
        if version is None:
            problems.append("Gitleaks did not report its version")
    if config_is_intact():
        typer.echo("gitleaks    config verified (extends the pinned default rules)")
    else:
        typer.echo("gitleaks    config INTEGRITY CHECK FAILED")
        problems.append("Gitleaks configuration integrity check failed")
    return problems


_HOME_VARIABLES = ("HOME", "USERPROFILE", "LOCALAPPDATA", "APPDATA")


def _doctor_pip_audit() -> list[str]:
    python = pip_audit_python()
    if python is None:
        typer.echo(f"pip-audit   NOT FOUND at {default_tools_base() / 'pip-audit'} "
                   "(dependency audits: PARTIAL)")  # fmt: skip
        return ["pip-audit is not installed in the auditor's tool directory"]
    with tempfile.TemporaryDirectory(prefix="auditor-doctor-") as workspace:
        result = run_tool(
            [str(python), "-I", "-m", "pip_audit", "--version"],
            cwd=Path(workspace),
            timeout=60,
            env=minimal_env(Path(workspace), extra=dict.fromkeys(_HOME_VARIABLES, workspace)),
            stdout_limit=256,
        )
    version = result.stdout.strip().removeprefix("pip-audit ")
    if result.exit_code != 0 or not version:
        typer.echo("pip-audit   did not report its version")
        return ["pip-audit did not report its version"]
    note = "" if version == PIP_AUDIT_VERSION else f" (pinned: {PIP_AUDIT_VERSION})"
    typer.echo(f"pip-audit   {version} ({python}){note}; network only with --allow-network")
    return []


def _validate_choice(option: str, choices: Sequence[str]):
    def check(value: str) -> str:
        if value.lower() not in choices:
            raise typer.BadParameter(f"{option} must be one of {', '.join(choices)}")
        return value.lower()

    return check


def _validate_disabled(values: list[str] | None) -> list[str] | None:
    for value in values or []:
        if value not in IMPLEMENTED_SCANNERS:
            raise typer.BadParameter(
                f"unknown scanner {value!r}; choose from {', '.join(IMPLEMENTED_SCANNERS)}"
            )
    return values


def _validate_target_python(value: str | None) -> str | None:
    if value is not None:
        try:
            to_ruff_target(value)
        except ValueError as exc:
            raise typer.BadParameter(str(exc)) from None
    return value


def _make_console_safe() -> None:
    """Never crash on characters the console encoding (e.g. cp1254) cannot represent."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            with contextlib.suppress(ValueError, OSError):
                reconfigure(errors="backslashreplace")


@app.command()
def scan(
    path: str = typer.Argument(..., help="Local project directory to inventory (read-only)."),
    output_dir: Path | None = typer.Option(
        None,
        "--output-dir",
        help="Where to write reports (a <run_id> folder is created inside). Must be outside "
        "the target. Default: per-user data directory.",
    ),
    max_files: int = typer.Option(
        DEFAULT_MAX_FILES, "--max-files", min=1, help="Stop after this many files."
    ),
    target_python: str | None = typer.Option(
        None,
        "--target-python",
        callback=_validate_target_python,
        help=f"Python version the project targets ({SUPPORTED_PYTHON[0]}-{SUPPORTED_PYTHON[-1]}). "
        f"Default: {DEFAULT_TARGET_PYTHON} (assumed, shown in the report).",
    ),
    disable_scanner: list[str] | None = typer.Option(
        None,
        "--disable-scanner",
        callback=_validate_disabled,
        help="Do not run this scanner (ruff, semgrep or gitleaks; repeatable). The report "
        "then states that its coverage is missing.",
    ),
    gitleaks_workers: int = typer.Option(
        DEFAULT_WORKERS,
        "--gitleaks-workers",
        min=1,
        max=MAX_WORKERS,
        help=f"Parallel Gitleaks processes (one per file; 1-{MAX_WORKERS}).",
    ),
    allow_network: bool = typer.Option(
        False,
        "--allow-network",
        help="Allow the dependency audit (pip-audit): exact package names and versions from "
        "the target's manifests are sent to api.osv.dev, including private or internal package "
        "names (nothing is filtered). Without it, dependencies are not checked and the scan is "
        "partial.",
    ),
    scan_git_history: bool = typer.Option(
        False,
        "--scan-git-history",
        help="Also scan every blob and commit message reachable in the git history for "
        "secrets (Gitleaks, offline). git never runs on the target's own .git: objects and "
        "refs are copied into a private workspace first. Off by default.",
    ),
    fail_on: str = typer.Option(
        "none",
        "--fail-on",
        callback=_validate_choice("--fail-on", FAIL_ON_CHOICES),
        help="Quality gate: exit with 4 if a finding has this severity or higher "
        f"({'|'.join(FAIL_ON_CHOICES)}). Default none: findings do not change the exit code.",
    ),
    unrated_as: str = typer.Option(
        "high",
        "--unrated-as",
        callback=_validate_choice("--unrated-as", UNRATED_CHOICES),
        help="How the gate counts findings without a severity (pip-audit): "
        f"{'|'.join(UNRATED_CHOICES)}. The finding itself stays UNRATED.",
    ),
    quiet: bool = typer.Option(False, "--quiet", help="Print only the summary lines."),
) -> None:
    """Read-only audit of a local project: discovery, Ruff (quality), Semgrep (security),
    Gitleaks (secrets; values are never shown) and, with permission, pip-audit and git history.

    Exit codes: 0 complete (and gate passed or not evaluated), 1 internal or report-writing
    error, 2 invalid input, 3 partial coverage, 4 quality gate failed (takes precedence over 3).
    COMPLETE describes coverage only; it never means that the project is safe.
    """
    _make_console_safe()
    policy = parse_policy(fail_on, unrated_as)
    try:
        run = run_audit(
            path,
            output_dir,
            ScanPolicy(max_files=max_files),
            RuffOptions(target_python=target_python),
            gitleaks_options=GitleaksOptions(workers=gitleaks_workers),
            pip_audit_options=PipAuditOptions(allow_network=allow_network),
            git_history_options=GitHistoryOptions() if scan_git_history else None,
            gate=policy,
            disabled=set(disable_scanner or ()),
        )
    except TargetPathError as exc:
        typer.echo(f"ERROR [{exc.code.value}]: {sanitize_for_display(str(exc))}", err=True)
        raise typer.Exit(code=EXIT_INVALID_INPUT) from None
    except ReportWriteError as exc:
        typer.echo(f"ERROR [REPORT_WRITE]: {sanitize_for_display(str(exc))}", err=True)
        raise typer.Exit(code=EXIT_INTERNAL_ERROR) from None
    except Exception as exc:
        typer.echo(f"INTERNAL ERROR: {type(exc).__name__}", err=True)
        raise typer.Exit(code=EXIT_INTERNAL_ERROR) from None

    out, err = summary(run.audit, run.reports, quiet=quiet)
    for line in out:
        typer.echo(line)
    for line in err:
        typer.echo(line, err=True)
    code = decide_exit(run.audit.coverage.status, run.audit.gate.status)
    if code:
        raise typer.Exit(code=code)


@app.command()
def report(
    run_id: str = typer.Argument(..., help="Run id: the name of the run's report folder."),
    reports_dir: Path | None = typer.Option(
        None, "--reports-dir", help="Report base directory. Default: per-user data directory."
    ),
    output_format: str = typer.Option(
        "summary",
        "--format",
        callback=_validate_choice("--format", ("summary", "markdown", "json")),
        help="summary, markdown or json (the canonical report.json, validated).",
    ),
) -> None:
    """Show a stored report again. Read-only: no scanner, git or network is started.

    The run folder must carry a matching SHA256SUMS.json (an integrity record, not a
    signature). Exit codes: 0 shown, 2 invalid run id, missing, changed or unsupported report.
    """
    _make_console_safe()
    base = reports_dir if reports_dir is not None else default_reports_base()
    try:
        audit = load_report(run_id, base)
    except ReportLoadError as exc:
        typer.echo(f"ERROR [REPORT_LOAD]: {exc}", err=True)
        raise typer.Exit(code=EXIT_INVALID_INPUT) from None
    if output_format == "json":
        typer.echo(render_report_json(audit), nl=False)
    elif output_format == "markdown":
        typer.echo(render_markdown(audit))
    else:
        out, err = summary(audit)
        for line in out:
            typer.echo(line)
        for line in err:
            typer.echo(line, err=True)
