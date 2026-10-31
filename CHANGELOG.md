# Changelog

All notable changes to AI Code Auditor. The version in `pyproject.toml` is the single source.

## 0.1.0 — MVP (2026-10-30, not tagged or published)

First MVP: a read-only, offline-by-default audit CLI for local Python projects on Windows 11
and Python 3.12. The target is untrusted input: it is never executed, imported, installed or
written to, and secret values never reach a report, the terminal or a log.

### Added

- **Stage 0 — skeleton:** `src/` package, Typer CLI (`--help`, `--version`, `doctor`), pytest,
  Ruff with the Bandit (`S`) rules.
- **Stage 1 — safe discovery:** read-only inventory with link, junction and TOCTOU checks,
  size and count limits, and atomic `inventory.json`.
- **Stage 2 — Ruff:** code-quality scan using the auditor's own configuration (the target's
  config is ignored), `findings.json`, `--target-python`, and a shared `Finding` /
  `ToolExecution` model with `SUCCESS` / `SKIPPED` / `ERROR` / `TIMED_OUT`.
- **Stage 3 — Semgrep:** separate hash-verified tool environment, the auditor's own 14-rule set
  with a manifest, a private source mirror, process-tree termination, and
  `--disable-scanner`.
- **Stage 4a — Gitleaks (working tree):** pinned, hash-verified Gitleaks 8.30.1; one stdin
  scan per file; per-file coverage proof (end marker and self-test); the target's Gitleaks
  config and ignore files have no effect.
- **Stage 5 — pip-audit:** dependency audit through OSV for exactly pinned versions in
  `requirements*.txt` and `pylock.toml` (and `pyproject.toml` covered by a lock). The network is
  used only with `--allow-network`; without it the area is `NOT_PERMITTED`.
- **Stage 4b — Gitleaks (git history, opt-in `--scan-git-history`):** git never runs in the
  target; a verified private copy is used, blobs and commit messages are extracted, findings are
  attributed to commits and paths, and every listed object is reconciled.
- **Stage 6 — unified report:**
  - canonical `report.json` (schema `ai-code-auditor/report` 1.0.0,
    `schemas/report-v1.schema.json`);
  - `UNRATED` severity for pip-audit;
  - finding identifiers;
  - relations R1–R3 (same location, same content in history, same vulnerability);
  - per-area coverage;
  - quality gate (`--fail-on`, `--unrated-as`, exit code 4);
  - atomic report directory with `SHA256SUMS.json`;
  - `auditor report RUN_ID` (shows a saved run without rescanning);
  - escaped Markdown and terminal output.

### Hardening after pilot 01 (2026-10-31, same version)

- **Reproducible build:** every source and data file is stored with LF; two independent clean
  builds of the wheel are byte-identical and equal the build from `git archive`.
- **Binary formats Gitleaks does not scan** (zip, gzip, PDF, 7-Zip, RAR, bzip2, SQLite) are
  reported as *skipped by the tool* with the format named, instead of as a tool error;
  coverage stays partial.
- **pip-audit without network permission** reports the pinned version and "not run" instead
  of "version unknown"; no process is started.
- **File context:** every finding of every scanner carries a path-based `context`
  (`production`, `test`, `docs`, `examples`, `config`, `unknown`) with its basis, and test
  paths are tagged `test-path` for all scanners. Report schema 1.1.0 (additive; 1.0.0 runs
  still load with `auditor report`). Severity and the gate are not affected by the context.
- **Verified cross-function SQL injection:** two Semgrep *evidence* rules (never findings)
  are joined by an execution-free AST check of the target; only a fully resolved
  `request -> call -> parameter -> SQL text` chain raises the existing formatted-SQL finding
  (Semgrep `formatted-sql-query`, Ruff `S608`) to HIGH, with location-only evidence. The
  verification status stays `NEEDS_REVIEW`; nothing is created or dropped.

### Fixed after release candidate validation (2026-10-31, same version)

- **Stable Gitleaks finding identities (P9):** the fingerprint of a working-tree secret
  finding no longer depends on the order in which Gitleaks reports results (which varies
  between runs). Identity is now rule, path, line and match columns; exact duplicates at the
  same position are numbered and tagged `duplicate-match`. Secret values never enter the
  fingerprint. All Gitleaks working-tree fingerprints change once with this fix; counts,
  rules, locations, severities, coverage and the gate do not.
  - **Identity mapping limits:** Gitleaks finding ids and fingerprints in reports written
    before this fix do not match the new ones (there is no mapping table). Because the
    identity is location-only, a secret whose *content* changes at the same rule, line and
    columns keeps the same identity. Exact duplicates (same rule, line and columns) are only
    told apart by their number, so their ids can swap if the tool reports them in another
    order; they are tagged `duplicate-match` for that reason. Git-history findings keep their
    previous identity scheme (object id based). Working-tree and history scans still never
    store or show values.

### Licensing and packaging (2026-10-31, same version)

- The project is licensed under the **Apache License 2.0** (`LICENSE`, official text).
  Because the published packages also contain the four MIT-licensed Gitleaks rule copies,
  `pyproject.toml` declares the SPDX expression `license = "Apache-2.0 AND MIT"` for the
  distribution as a whole (PEP 639) and ships `LICENSE` and `THIRD_PARTY_NOTICES.md` inside
  the wheel and sdist metadata. The project's own licence and the original MIT copyright
  notice are unchanged.
- `THIRD_PARTY_NOTICES.md` records the four Gitleaks 8.30.1 default rules copied (and
  modified) into `src/auditor/rules/gitleaks/path-*.toml` under the MIT License, and the
  licence inventory of the published files. Semgrep, Gitleaks, Ruff and the Python
  dependencies are not distributed with the project.
- Package metadata claims only what was verified: Windows and CPython 3.12 classifiers and
  `requires-python >= 3.12`. Python 3.11 was never tested and is not claimed; `auditor doctor`
  requires 3.12 as well.

### Documentation (2026-10-31, same version)

- All public documentation is in English. `docs/MVP_VALIDATION.md` is the validation report of
  the released 0.1.0 build (safety invariants, accuracy on three repositories, verified SQL
  data flow, finding identity stability, reproducible packaging, test results). The initial
  pilot before hardening is preserved unchanged as `docs/PILOT_01_VALIDATION.md`.
- README restructured for GitHub users: features, scanners, installation, quick start, CLI
  examples, report outputs, quality gates, git history scanning, verified SQL flow, security
  and privacy design, validation results, known limitations, documentation, licence. No
  product behaviour, report format or security property changed.

### Exit codes

`0` complete coverage and the gate passed (or was not evaluated) · `1` internal or report-write
error · `2` invalid input · `3` partial coverage · `4` gate failed.
Precedence: 1 and 2 > 4 > 3.

### Known limitations

The measured results are in `docs/MVP_VALIDATION.md` (current 0.1.0 build) and
`docs/PILOT_01_VALIDATION.md` (historical pilot); three repositories, nothing here generalises
to all Python projects. The development repository keeps the full per-stage limitation lists
and the decision log. In short:

- **Accuracy as measured on pilot 01:** on Flask, 30 of 34 security-category findings were
  false positives (test fixtures, documentation examples, developer asserts); on the
  leaky-repo secrets benchmark the default Gitleaks rules reach 14 of 42 files and at most
  22 of 96 risk lines (low-entropy passwords, hashes, `.env`/PHP/`.netrc` credentials are
  missed). Git-history scans report one raw finding per file version that contains a value
  (Flask: 224 findings for at most 2 values).
- **Verified SQL flow covers one shape only:** exact import binding, one module file, one
  function definition, plain positional/keyword arguments. Re-exports, aliases that are
  re-bound, dynamic calls, `*args`/`**kwargs`, class methods and frameworks other than
  Flask/Django request objects are deliberately not verified and keep MEDIUM.
- **Context is path-based**, never a security proof: production code under `tests/` is
  classified as test.

- **Coverage is not a verdict:** `COMPLETE` / exit 0 means the requested areas were fully
  scanned, not that the project is safe. Every tool has false negatives. For example, Gitleaks
  misses about 1 % of random generic keys, and Semgrep CE taint tracking stays inside one
  function.
- **Dependencies:** only exactly pinned versions are audited. Many lock formats (`poetry.lock`,
  `uv.lock`, `Pipfile.lock`, …) and `setup.py` are not analysed. OSV results are not a
  guarantee. With `--allow-network`, private package names are sent to api.osv.dev.
- **Git history:** reflogs, dangling objects, submodules, linked worktrees, tag messages and
  history beyond a shallow boundary are not scanned. Unsafe repository layouts are refused
  (`PARTIAL`).
- **Report integrity record is not a signature.** Finding fingerprints depend on line and
  column, so there is no tracking across runs. The legacy `findings.json` keeps the MEDIUM
  placeholder for pip-audit and will be removed later, with approval.
- **Platform:** tested on Windows 11 / CPython 3.12 only; `requires-python >= 3.12`.
  Real-symlink tests (no privilege) and POSIX-only tests did not run.
- **Residual races:**
  - a small Windows race window remains in the output-directory checks (D-022);
  - stale workspaces and incomplete report directories are reported, never deleted
    automatically.
