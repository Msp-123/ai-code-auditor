"""pip-audit dependency adapter (pip-audit 2.10.1, hash-locked tool environment; Stage 5, D-044).

Behaviour measured in step 0 and covered by tests:

- Network use only with ``--allow-network``; otherwise pip-audit is not even started and the
  dependency audit is reported as not performed (the audit becomes PARTIAL, user decision P1).
- pip-audit receives only plain ``name==version`` lines written by the auditor
  (``manifests.py``): it would silently drop ``-r`` includes, ignore ``-c``, evaluate markers
  against the auditor's own interpreter and abort on unpinned or duplicated lines. Versions
  of the same package go to separate runs.
- ``--disable-pip --no-deps -s osv``: no dependency resolution, nothing installed, nothing
  from the target executed; the fixed service is OSV (api.osv.dev). The only subprocess
  pip-audit starts is ``python -m pip --version`` in its own tool environment (pip-api), a
  documented, narrow exception.
- Status comes from the JSON, not the exit code: exit 1 with a valid report means
  vulnerabilities were found (kept); exit 1 without one is an error. stderr is never stored
  (it can contain the proxy host name); errors are reported as fixed categories.
- Advisory text is untrusted external data: identifiers are validated, text is flattened and
  truncated. OSV returning nothing proves neither that a package exists nor that it is safe;
  pip-audit gives no severity, so findings are MEDIUM and marked UNRATED.
"""

import json
import os
import re
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from auditor.core.models import (
    Confidence,
    Evidence,
    Finding,
    FindingCategory,
    FindingIdentifiers,
    LimitedFile,
    NotAnalyzedFile,
    NotAnalyzedReason,
    Severity,
    ToolExecution,
    ToolStatus,
    VerificationStatus,
)
from auditor.core.safe_fs import PRIVATE_DIR_MODE, create_private_file
from auditor.findings.fingerprint import compute_fingerprint
from auditor.scanners.base import ScanContext, ScanOutcome
from auditor.scanners.executables import PIP_AUDIT_VERSION, pip_audit_python, resolves_inside
from auditor.scanners.manifests import (
    _VERSION,
    ManifestResult,
    Pin,
    analyze_manifests,
    normalize_name,
)
from auditor.scanners.runner import ProcessResult, minimal_env, run_tool

TOOL = "pip-audit"
FORBIDDEN_ARGS = ("--fix", "--locked", "-v", "--verbose", "--index-url", "--extra-index-url",
                  "-l", "--local", "--path", "-S", "--strict")  # fmt: skip
NETWORK_VARIABLES = ("HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy",
                     "no_proxy", "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "SSL_CERT_DIR",
                     "CURL_CA_BUNDLE")  # fmt: skip
_VULN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,80}$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f  ‪-‮⁦-⁩]+")
MAX_ADVISORY_TEXT = 300
_ERROR_CATEGORIES = (
    ("ProxyError", "proxy error"),
    ("SSLError", "TLS error"),
    ("Timeout", "network timeout"),
    ("ConnectionError", "network error"),
)


@dataclass(frozen=True)
class PipAuditOptions:
    allow_network: bool = False
    batch_timeout: float = 120.0
    total_timeout: float = 600.0
    request_timeout: int = 15
    max_batch: int = 250
    max_output_bytes: int = 16 * 1024 * 1024
    osv_url: str | None = None  # tests only (local mock OSV server); the CLI never sets it


@dataclass
class _Run:
    findings: list[Finding] = field(default_factory=list)
    failed: dict[tuple[str, str], str] = field(default_factory=dict)  # (name, version) -> why
    warnings: list[str] = field(default_factory=list)
    exit_codes: set[int] = field(default_factory=set)
    clean: int = 0
    errors: list[str] = field(default_factory=list)
    vulns: dict[tuple[str, str], list] = field(default_factory=dict)
    timed_out: bool = False
    seen_ids: set[str] = field(default_factory=set)

    def warn(self, message: str) -> None:
        if message not in self.warnings:
            self.warnings.append(message)


def flatten(text: object, limit: int = MAX_ADVISORY_TEXT) -> str:
    """Untrusted text as one short, inert line."""
    value = _CONTROL.sub(" ", str(text or ""))
    value = re.sub(r"\s+", " ", value).strip()
    return value if len(value) <= limit else value[: limit - 1] + "…"


class PipAuditAdapter:
    name = TOOL

    def __init__(
        self,
        options: PipAuditOptions | None = None,
        command: Sequence[str] | None = None,
        tools_base: Path | None = None,
    ):
        self.options = options or PipAuditOptions()
        if command is None:
            python = pip_audit_python(tools_base)
            command = [str(python), "-I", "-m", "pip_audit"] if python else None
        self.command = list(command) if command else None
        self.settings = {
            "service": "OSV (api.osv.dev), fixed",
            "method": "auditor's own parser -> exact name==version lists; pip-audit "
            "--disable-pip --no-deps (nothing resolved, installed or executed)",
            "markers": "kept on the finding, never evaluated: the auditor's Python/OS is not "
            "assumed to be the target's",
            "severity": "UNRATED: pip-audit gives no severity; MEDIUM is a placeholder",
            "result_wording": "no finding means no known vulnerability in OSV for that exact "
            "version; it is not a guarantee",
        }

    def scan(self, context: ScanContext) -> ScanOutcome:
        inventory = [f.relative_path for f in context.files]
        manifests = analyze_manifests(context.root, inventory)
        applicable = sorted({f for m in manifests for f in {m.file, *m.files_read}})
        execution, findings = self._scan_impl(context, manifests)
        return ScanOutcome(execution, findings, applicable)

    def _scan_impl(self, context, manifests: list[ManifestResult]):
        started = time.monotonic()
        pins = _unique_pins(manifests)
        settings = {**self.settings, **_counts(manifests, pins)}
        settings["network"] = (
            "allowed (--allow-network): exact package names and versions are sent to "
            "api.osv.dev, including private or internal package names; nothing else"
            if self.options.allow_network
            else "NOT granted: no network use, pip-audit was not started"
        )
        refusal = self._refusal(context, manifests)
        if refusal is not None:
            status = refusal[0]
            # H3: skipped means "installed but not run"; the pinned version is known without
            # starting any process. Not installed stays version-less.
            version = PIP_AUDIT_VERSION if status is ToolStatus.SKIPPED and self.command else None
            return self._execution(started, manifests, settings, *refusal, version=version), []
        run, version = self._audit(context.workspace, pins, settings, started)
        status, reason = _overall(run, pins)
        not_analyzed = _structural_gaps(manifests) + _failed_files(pins, run.failed)
        execution = self._execution(
            started, manifests, settings, status, reason, not_analyzed, run, version
        )
        return execution, run.findings

    def _refusal(self, context, manifests) -> tuple | None:
        """(status, reason, not analyzed) when pip-audit must not or cannot run at all."""
        if not manifests:
            return ToolStatus.SKIPPED, "No dependency manifests in the inventory", []
        if not self.options.allow_network:
            missing = [
                NotAnalyzedFile(
                    relative_path=m.file,
                    reason=NotAnalyzedReason.NETWORK_NOT_ALLOWED,
                    detail="dependency vulnerabilities were not checked: network permission "
                    "not granted (--allow-network)",
                )
                for m in manifests
            ]
            reason = (
                "Network permission not granted (--allow-network): dependency "
                "vulnerabilities were NOT checked"
            )
            return ToolStatus.SKIPPED, reason, missing
        if self.command is None:
            reason = (
                f"pip-audit {PIP_AUDIT_VERSION} not found in the auditor's tool directory "
                "(<tools>/pip-audit)"
            )
            return ToolStatus.NOT_INSTALLED, reason, _structural_gaps(manifests)
        if resolves_inside(Path(self.command[0]), context.root):
            reason = "pip-audit interpreter resolves inside the scan target; refused (untrusted)"
            return ToolStatus.ERROR, reason, _structural_gaps(manifests)
        return None

    def _audit(self, work: Path, pins: list[Pin], settings: dict, started: float):
        cwd, home, tmp, cache = work / "cwd", work / "home", work / "tmp", work / "cache"
        for directory in (cwd, home, tmp, cache):
            directory.mkdir(mode=PRIVATE_DIR_MODE)
        env = self._env(tmp, home, settings)
        version = self._version(cwd, env)
        run = _Run()
        if version != PIP_AUDIT_VERSION:
            run.warn(
                f"pip-audit {version or 'unknown'} differs from the pinned {PIP_AUDIT_VERSION}; "
                "output format may differ."
            )
        deadline = started + self.options.total_timeout
        for index, batch in enumerate(_batches(pins, self.options.max_batch)):
            if time.monotonic() >= deadline:
                run.timed_out = True
                run.failed.update(dict.fromkeys(batch, "total time limit reached"))
                continue
            self._run_batch(work, cwd, cache, env, index, batch, deadline, run)
        if run.clean:
            run.warn(
                f"{run.clean} pinned package version(s) have no known vulnerabilities in OSV. "
                "This does not prove that they exist on PyPI or that they are safe."
            )
        for pin in pins:
            for vuln in run.vulns.get((pin.name, pin.version), []):
                finding = finding_for(pin, vuln, run)
                if finding is not None:
                    run.findings.append(finding)
        return run, version

    def _execution(self, started, manifests, settings, status, reason, not_analyzed=(),
                   run=None, version=None) -> ToolExecution:  # fmt: skip
        return ToolExecution(
            tool=TOOL,
            version=version,
            status=status,
            reason=reason,
            exit_codes=sorted(run.exit_codes) if run else [],
            duration_seconds=round(time.monotonic() - started, 3),
            files_requested=len(manifests),
            files_analyzed=len(manifests) - len({n.relative_path for n in not_analyzed}),
            not_analyzed=list(not_analyzed),
            settings=settings,
            command_summary="pip-audit -r <name==version list> --disable-pip --no-deps -s osv "
            "-f json",
            stderr_excerpt=None,
            warnings=(run.warnings if run else []) + _notes(manifests),
            coverage_limitations=_limitations(manifests),
        )

    def _env(self, tmp: Path, home: Path, settings: dict[str, str]) -> dict[str, str]:
        extra = {"HOME": str(home), "USERPROFILE": str(home),
                 "LOCALAPPDATA": str(home / "local"), "APPDATA": str(home / "roaming")}  # fmt: skip
        inherited = [k for k in NETWORK_VARIABLES if os.environ.get(k)]
        for key in inherited:
            extra[key] = os.environ[key]
        if inherited:
            settings["proxy"] = "proxy/certificate settings inherited (values not shown)"
        return minimal_env(tmp, extra=extra)

    def _version(self, cwd: Path, env: dict[str, str]) -> str | None:
        result = run_tool(
            [*self.command, "--version"], cwd=cwd, timeout=60, env=env, stdout_limit=256
        )
        match = re.fullmatch(r"pip-audit (\d+\.\d+\.\d+)", result.stdout.strip())
        return match.group(1) if result.exit_code == 0 and match else None

    def _argv(self, deps_file: Path, cache: Path) -> list[str]:
        argv = [*self.command, "-r", str(deps_file), "--disable-pip", "--no-deps", "-s", "osv",
                "-f", "json", "--cache-dir", str(cache), "--progress-spinner", "off",
                "--timeout", str(self.options.request_timeout), "--desc", "on",
                "--aliases", "on"]  # fmt: skip
        if self.options.osv_url:
            argv += ["--osv-url", self.options.osv_url]
        return argv

    def _run_batch(self, work, cwd, cache, env, index, batch, deadline, run: _Run) -> None:
        deps_file = work / f"deps-{index}.txt"
        create_private_file(deps_file, "".join(f"{n}=={v}\n" for n, v in sorted(batch)))
        result = run_tool(
            self._argv(deps_file, cache),
            cwd=cwd,
            timeout=max(1.0, min(self.options.batch_timeout, deadline - time.monotonic())),
            env=env,
            stdout_limit=self.options.max_output_bytes,
        )
        if result.exit_code is not None:
            run.exit_codes.add(result.exit_code)
        problem, report = _classify(result)
        if result.timed_out:
            run.timed_out = True
        if problem is not None:
            run.errors.append(problem)
            for key in batch:
                run.failed[key] = problem
            return
        _collect(report, batch, run)


def _overall(run: _Run, pins: list[Pin]) -> tuple[ToolStatus, str]:
    versions = {(p.name, p.version) for p in pins}
    if run.timed_out:
        return ToolStatus.TIMED_OUT, "pip-audit did not finish within the limit"
    if run.errors and len(run.failed) >= len(versions):
        return ToolStatus.ERROR, f"pip-audit failed: {run.errors[0]}"
    if not pins:
        return ToolStatus.SUCCESS, "No exactly pinned dependencies to audit"
    audited = len(versions) - len(run.failed)
    return ToolStatus.SUCCESS, f"Completed; {audited} pinned package version(s) checked against OSV"


def _classify(result: ProcessResult) -> tuple[str | None, dict | None]:
    if result.launch_error is not None:
        return "pip-audit could not be started", None
    if result.timed_out:
        return "timed out", None
    if result.exit_code not in (0, 1):
        return f"exit code {result.exit_code}", None
    try:
        report = json.loads(result.stdout) if result.stdout.strip() else None
    except ValueError:
        report = None
    valid = (
        isinstance(report, dict)
        and isinstance(report.get("dependencies"), list)
        and all(isinstance(d, dict) for d in report["dependencies"])
    )
    if valid:
        return None, report
    for marker, category in _ERROR_CATEGORIES:  # stderr is inspected, never stored
        if marker in result.stderr:
            return category, None
    return "invalid output (no valid JSON report)", None


def _collect(report: dict, batch: list[tuple[str, str]], run: _Run) -> None:
    wanted = set(batch)
    seen = set()
    for dep in report["dependencies"]:
        name = normalize_name(str(dep.get("name", "")))
        version = dep.get("version")
        if dep.get("skip_reason") is not None:
            matches = [key for key in wanted if key[0] == name]
            for key in matches:
                run.failed[key] = "skipped by pip-audit: " + flatten(dep["skip_reason"], 120)
                seen.add(key)
            continue
        key = (name, str(version))
        if key not in wanted:
            run.warn("A result for an unexpected package was dropped.")
            continue
        seen.add(key)
        vulns = dep.get("vulns") or []
        if not isinstance(vulns, list):
            run.failed[key] = "invalid output for this package"
            continue
        if not vulns:
            run.clean += 1
        run.vulns[key] = vulns
    for key in wanted - seen:
        run.failed.setdefault(key, "not reported by pip-audit")


def _unique_pins(manifests: list[ManifestResult]) -> list[Pin]:
    pins: list[Pin] = []
    for manifest in manifests:
        for pin in manifest.pins:
            if pin not in pins:
                pins.append(pin)
    return pins


def _batches(pins: list[Pin], size: int) -> list[list[tuple[str, str]]]:
    """Each run holds at most one version per package (pip-audit rejects duplicates)."""
    versions: dict[str, list[str]] = {}
    for pin in pins:
        if pin.version not in versions.setdefault(pin.name, []):
            versions[pin.name].append(pin.version)
    rounds: list[list[tuple[str, str]]] = []
    for name, found in sorted(versions.items()):
        for i, version in enumerate(found):
            while len(rounds) <= i:
                rounds.append([])
            rounds[i].append((name, version))
    return [r[i : i + size] for r in rounds for i in range(0, len(r), size)]


def _counts(manifests: list[ManifestResult], pins: list[Pin]) -> dict[str, str]:
    conditional = sum(1 for p in pins if p.marker)
    # an included file can also be a manifest of its own: count each gap once
    gaps = list(dict.fromkeys(g for m in manifests for g in m.gaps))
    by_reason: dict[str, int] = {}
    for gap in gaps:
        by_reason[gap.reason] = by_reason.get(gap.reason, 0) + 1
    text = ", ".join(f"{k} {v}" for k, v in sorted(by_reason.items())) or "none"
    return {
        "dependencies": f"{len(pins)} pinned (of which {conditional} conditional on an "
        f"environment marker); {len(gaps)} entries not audited ({text})",
        "formats": "supported: requirements*.txt (+ -r/-c), pylock.toml, pyproject.toml "
        "declarations verified against pylock.toml in the same directory; reported as not "
        "analyzed: setup.py, unlocked or dynamic pyproject.toml declarations, setup.cfg "
        "declarations, Poetry sections, Pipfile(.lock), poetry.lock, uv.lock, pdm.lock, "
        "environment.yml",
    }


def _notes(manifests: list[ManifestResult]) -> list[str]:
    return list(dict.fromkeys(f"{m.file}: {note}" for m in manifests for note in m.notes))


def _structural_gaps(manifests: list[ManifestResult]) -> list[NotAnalyzedFile]:
    return [
        NotAnalyzedFile(
            relative_path=m.file,
            reason=NotAnalyzedReason.UNSUPPORTED_MANIFEST,
            detail="; ".join(g.detail for g in m.gaps)[:300],
        )
        for m in manifests
        if m.fatal
    ]


def _limitations(manifests: list[ManifestResult]) -> list[LimitedFile]:
    by_file: dict[str, list[str]] = {}
    for manifest in manifests:
        if manifest.fatal:
            continue
        for gap in manifest.gaps:
            where = f"line {gap.line}" if gap.line else "file"
            by_file.setdefault(gap.file, []).append(f"{where}: {gap.detail}")
    return [
        LimitedFile(
            relative_path=file,
            reason="DEPENDENCIES_NOT_AUDITED",
            detail=f"{len(items)} entr{'y' if len(items) == 1 else 'ies'} not audited: "
            + "; ".join(dict.fromkeys(items))[:600],
        )
        for file, items in sorted(by_file.items())
    ]


def _failed_files(pins: list[Pin], failed: dict) -> list[NotAnalyzedFile]:
    per_file: dict[str, list[Pin]] = {}
    for pin in pins:
        per_file.setdefault(pin.file, []).append(pin)
    out = []
    for file, group in sorted(per_file.items()):
        bad = [p for p in group if (p.name, p.version) in failed]
        if bad:
            why = sorted({failed[(p.name, p.version)] for p in bad})
            out.append(
                NotAnalyzedFile(
                    relative_path=file,
                    reason=NotAnalyzedReason.TOOL_ERROR,
                    detail=f"{len(bad)} of {len(group)} pinned dependencies could not be "
                    f"audited: {'; '.join(why)}"[:300],
                )
            )
    return out


def finding_for(pin: Pin, vuln: dict, run: _Run) -> Finding | None:
    vuln_id = str(vuln.get("id", ""))
    if not _VULN_ID.match(vuln_id):
        run.warn("A vulnerability with an unexpected identifier was dropped.")
        return None
    aliases = [a for a in vuln.get("aliases") or [] if isinstance(a, str) and _VULN_ID.match(a)]
    fixes = [f for f in vuln.get("fix_versions") or [] if isinstance(f, str) and _VERSION.match(f)]
    summary = flatten(vuln.get("description"))
    parts = [f"OSV lists {vuln_id} for {pin.name} {pin.version}."]
    if aliases:
        parts.append(f"Aliases: {', '.join(aliases[:8])}.")
    parts.append(f"Fixed in: {', '.join(fixes[:8])}." if fixes else "No fixed version listed.")
    if summary:
        parts.append(f'Advisory summary (external, untrusted): "{summary}"')
    if pin.marker:
        parts.append(
            f"Applies only where this environment marker holds: {flatten(pin.marker, 160)}. "
            "Whether it is installed in the target environment is not known."
        )
    if pin.via_constraint:
        parts.append(f"Version taken from {pin.via_constraint}.")
    rule_id = f"{TOOL}.{vuln_id}"
    fingerprint = compute_fingerprint(
        tool=TOOL,
        rule_id=rule_id,
        relative_path=pin.file,
        start=(pin.line, None),
        end=(pin.line, None),
        message=f"{pin.name}=={pin.version}",
    )
    finding_id, suffix = f"{TOOL}-{fingerprint[:16]}", 2
    while finding_id in run.seen_ids:
        finding_id, suffix = f"{TOOL}-{fingerprint[:16]}-{suffix}", suffix + 1
    run.seen_ids.add(finding_id)
    tags = ["dependency", "UNRATED", "osv", *aliases[:5]]
    tags += ["conditional"] if pin.marker else []
    tags += ["via-constraint"] if pin.via_constraint else []
    fix_text = f"a fixed version ({', '.join(fixes[:4])})" if fixes else "a version without it"
    return Finding(
        finding_id=finding_id,
        fingerprint=fingerprint,
        source_tool=TOOL,
        rule_id=rule_id,
        title=f"{pin.name} {pin.version}: known vulnerability {vuln_id}",
        description=" ".join(parts),
        category=FindingCategory.SECURITY,
        severity=Severity.UNRATED,  # canonical (Stage 6); findings.json keeps MEDIUM
        original_severity="UNRATED",
        identifiers=FindingIdentifiers(
            package=pin.name, version=pin.version, vulnerability_ids=[vuln_id, *aliases[:8]]
        ),  # fmt: skip
        confidence=Confidence.MEDIUM if pin.marker else Confidence.HIGH,
        verification_status=VerificationStatus.NEEDS_REVIEW,
        relative_path=pin.file,
        start_line=pin.line,
        evidence=[Evidence(kind="dependency-pin", reference=f"{pin.file}:{pin.line}")],
        recommendation=f"Upgrade {pin.name} to {fix_text} if it is installed in the target "
        "environment, then run the audit again.",
        references=[f"https://osv.dev/vulnerability/{vuln_id}"],
        tags=tags,
    )
