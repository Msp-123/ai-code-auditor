"""Quality gate and exit codes (Stage 6, D-048).

The gate compares an *effective* severity with a user-chosen threshold (``--fail-on``,
default ``none``: not evaluated). UNRATED findings are mapped by ``--unrated-as`` (default
``high``, or ``ignore``); a finding's real severity is never changed. Every finding is
counted: relation groups never reduce the count.

Exit codes (precedence: invalid input / internal error > gate failed > partial):
0 complete and gate passed or not evaluated, 1 internal or report-writing error, 2 invalid
input, 3 partial coverage, 4 gate failed.
"""

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass

from auditor.core.audit_report import GateResult, GateStatus
from auditor.core.models import GATE_ORDER, Finding, ScanStatus, Severity

EXIT_OK = 0
EXIT_INTERNAL_ERROR = 1
EXIT_INVALID_INPUT = 2
EXIT_PARTIAL = 3
EXIT_GATE_FAILED = 4
MAX_LISTED_IDS = 100
FAIL_ON_CHOICES = ("none", "low", "medium", "high", "critical")
UNRATED_CHOICES = ("medium", "high", "ignore")


@dataclass(frozen=True)
class GatePolicy:
    fail_on: Severity | None = None  # None: the gate is not evaluated
    unrated_as: Severity | None = Severity.HIGH  # None: UNRATED findings are not counted


def parse_policy(fail_on: str, unrated_as: str) -> GatePolicy:
    if fail_on.lower() not in FAIL_ON_CHOICES:
        raise ValueError(f"--fail-on must be one of {', '.join(FAIL_ON_CHOICES)}")
    if unrated_as.lower() not in UNRATED_CHOICES:
        raise ValueError(f"--unrated-as must be one of {', '.join(UNRATED_CHOICES)}")
    threshold = None if fail_on.lower() == "none" else Severity(fail_on.upper())
    mapped = None if unrated_as.lower() == "ignore" else Severity(unrated_as.upper())
    return GatePolicy(threshold, mapped)


def effective_severity(finding: Finding, policy: GatePolicy) -> Severity | None:
    return policy.unrated_as if finding.severity is Severity.UNRATED else finding.severity


def evaluate_gate(findings: Sequence[Finding], policy: GatePolicy) -> GateResult:
    unrated = policy.unrated_as.value.lower() if policy.unrated_as else "ignore"
    if policy.fail_on is None:
        return GateResult(status=GateStatus.NOT_EVALUATED, fail_on="none", unrated_as=unrated)
    limit = GATE_ORDER.index(policy.fail_on)
    counted = []
    for finding in findings:
        severity = effective_severity(finding, policy)
        if severity is not None and GATE_ORDER.index(severity) <= limit:
            counted.append((finding, severity))
    by_severity = Counter(s.value for _, s in counted)
    return GateResult(
        status=GateStatus.FAILED if counted else GateStatus.PASSED,
        fail_on=policy.fail_on.value.lower(),
        unrated_as=unrated,
        counted=len(counted),
        counted_by_effective_severity={
            s.value: by_severity[s.value] for s in GATE_ORDER if by_severity[s.value]
        },  # fmt: skip
        counted_finding_ids=[f.finding_id for f, _ in counted][:MAX_LISTED_IDS],
    )


def decide_exit(coverage: ScanStatus, gate: GateStatus) -> int:
    """For a run whose reports were written; errors before that exit with 1 or 2."""
    if gate is GateStatus.FAILED:
        return EXIT_GATE_FAILED
    if coverage is ScanStatus.PARTIAL:
        return EXIT_PARTIAL
    return EXIT_OK
