"""Fixed limitation texts per scanner (report.json ``limitations`` and report.md)."""

SEMGREP_CE_LIMITATIONS = (
    "Semgrep Community Edition taint analysis is intraprocedural: flows through helper "
    "functions, across files, class attributes or framework wiring are not followed. The one "
    "exception is the verified request -> call -> parameter -> SQL text chain (evidence rules "
    "joined by a static AST check); everything unresolved keeps its pattern-based severity.",
    "Only the modelled sources are tracked (Flask `request`, Django `request.GET/POST/...`, "
    "`input()`, `sys.argv`); FastAPI/other framework parameters, ORM layers and custom "
    "wrappers are not modelled.",
    "Validation in code (allowlists, resolve-and-check guards) is not recognised as a "
    "sanitizer: such code may still be reported (false positives). Sanitizers are accepted "
    "only per vulnerability class (e.g. `shlex.quote` for POSIX shell commands only).",
    "Not covered by the ruleset: authentication/authorization logic, business-logic flaws, "
    "race conditions, cryptographic design, secrets (Gitleaks, Stage 4) and dependency "
    "vulnerabilities (pip-audit, Stage 5).",
    "Semgrep silently uses error-tolerant parsing; files Ruff could not parse are marked "
    "'scanned with limitations'. This does not guarantee that other files were analysed "
    "completely.",
)


GITLEAKS_LIMITATIONS = (
    "Each file is passed to Gitleaks on stdin, without its file name. The four "
    "path-conditioned content rules (`kubernetes-secret-yaml`, `hashicorp-tf-password`, "
    "`nuget-config-password`, `freemius-secret-key`) are applied through path-less copies only "
    "to files whose path matches; `pkcs12-file` is applied from the file name and reported as "
    "a potentially sensitive file, not as a secret value. Gitleaks' path allowlists "
    "(lockfiles, images, vendored code, a few rule-specific files) cannot apply on stdin, "
    "which can add false positives.",
    "Each file counts as scanned only if Gitleaks reported a random end marker appended after "
    "its content, which shows that the whole input was read.",
    "Detection is pattern- and entropy-based: low-entropy passwords, secrets split across "
    "lines or built at runtime, and unknown token formats can be missed (false negatives); "
    "random-looking test data can be reported (false positives). No finding is verified "
    "against its issuer (that would need network access).",
    "Archives and compressed documents are not extracted. Only the working tree is scanned; "
    "secrets that exist only in git history are not covered (git history: NOT_SCANNED).",
    "Secret values are never stored or shown: findings carry the rule id, file and line only.",
)


GIT_HISTORY_LIMITATIONS = (
    "Scope: every blob and commit message reachable from all refs and HEAD. Reflogs, "
    "unreachable objects, submodules and linked worktrees are not scanned.",
    "Attribution is derived from the commit trees; when the same content was introduced by "
    "several commits or paths, all are listed. Commit dates are commit metadata.",
    "Tag messages and other non-commit metadata are not scanned.",
    "Archives and compressed objects are not decoded; they are listed as not analyzed.",
    "Gitleaks' own false negatives apply (e.g. about 1% of random generic api_key values are "
    "not reported, measured).",
)


PIP_AUDIT_LIMITATIONS = (
    "Only exact pins are audited (requirements*.txt with -r/-c, pylock.toml). pyproject.toml "
    "declarations count only when a pylock.toml in the same directory verifiably pins them. "
    "Ranges, URLs, VCS, local paths, setup.py and other formats are listed as not audited.",
    "Environment markers are not evaluated: a finding on a conditional dependency does not "
    "mean that it is installed in the target environment.",
    "No finding means only that OSV lists no known vulnerability for that exact version. It "
    "does not prove that the package exists on PyPI or is safe; private package names are not "
    "distinguished from unknown ones.",
    "pip-audit gives no severity: findings have the severity UNRATED; the quality gate maps "
    "it with --unrated-as (default high). The legacy findings.json shows MEDIUM as a placeholder.",
    "With --allow-network every exactly pinned name and version is sent to api.osv.dev, "
    "including private or internal package names; names are not filtered or hidden.",
    "Transitive dependencies are covered only if they are pinned in the manifest or lock file.",
)


BY_TOOL = {
    "semgrep": SEMGREP_CE_LIMITATIONS,
    "gitleaks": GITLEAKS_LIMITATIONS,
    "pip-audit": PIP_AUDIT_LIMITATIONS,
    "gitleaks-history": GIT_HISTORY_LIMITATIONS,
}
