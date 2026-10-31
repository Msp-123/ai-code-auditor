# AI Code Auditor

Evidence-based, **read-only**, offline-by-default security and quality audit for local Python
projects. It runs Ruff, Semgrep, Gitleaks and (with permission) pip-audit, merges their results
into one canonical report with honest coverage and a quality gate, and never executes, imports
or modifies the project it scans.

Version 0.1.0 (MVP). Verified on Windows 11 / CPython 3.12 only. Install from the wheel built
from this repository (see Installation); there is no PyPI package.

## What is AI Code Auditor?

A command-line tool that answers two questions about a local Python project without trusting
it: *what did we check* (coverage) and *what did we find* (findings and a gate). The target is
treated as untrusted input: its code is never run, its configuration files never influence the
scanners, and secret values never appear in any output. One `auditor scan` produces a
canonical `report.json` (schema 1.1.0), a Markdown report and a terminal summary.

## Key features

- **Read-only and offline by default.** Nothing is written into the target; the network is used
  only with `--allow-network` (dependency audit via OSV).
- **Four scanners, one report:** Ruff (code quality and Bandit-style rules), Semgrep (the
  auditor's own security ruleset), Gitleaks (secrets in the working tree and, on request, in
  the git history), pip-audit (known vulnerabilities of pinned dependencies).
- **Honest coverage.** Every scanner reports `SUCCESS`, `SKIPPED`, `ERROR` or `TIMED_OUT`;
  every file has a coverage state; a scan is `PARTIAL` whenever anything was not checked.
- **Verified cross-function SQL injection.** A static, execution-free data-flow check raises a
  formatted-SQL finding to HIGH only when the chain `request data -> call -> parameter -> SQL
  text` is fully proven, with the proof attached as evidence.
- **File context for every finding:** `production`, `test`, `docs`, `examples`, `config` or
  `unknown`, derived from the path.
- **Stable finding identities** based on tool, rule, path, line and columns; relations between
  findings (same location, same content in history, same vulnerability).
- **Quality gate** with exit code 4, `--fail-on` and `--unrated-as`.
- **Tamper-evident reports** with a per-run integrity record, and `auditor report` to show a
  saved run without rescanning.
- **Reproducible build:** wheels built from independent copies of the source are byte-identical.

## Supported scanners

| Scanner | Version used | What it covers | How it is isolated |
|---|---|---|---|
| Ruff | 0.17.3 (installed with the auditor) | Code quality and security rules `E4, E7, E9, F, B, S, C901`, syntax errors | Auditor's own configuration (`--isolated`), no cache, `# noqa` ignored, no fixes |
| Semgrep | 1.182.1 (separate tool environment) | 14 security rules: command/code/template injection, SQL injection, path traversal, SSRF, insecure deserialization, XXE, disabled TLS verification, JWT signature bypass, Flask debug; plus 2 evidence rules (never findings) | Private copy of the target's `.py`/`.pyi` files; hash-verified ruleset; target `.semgrep.yml`, `.semgrepignore` and `# nosemgrep` have no effect; metrics off |
| Gitleaks | 8.30.1 (pinned official release, SHA-256 verified before every run) | Secrets in the working tree; optionally every blob and commit message in the git history | One `stdin` scan per file, per-file coverage proof, `--redact=100`, auditor's own configuration; target `.gitleaks.toml`, `.gitleaksignore` and `gitleaks:allow` have no effect |
| pip-audit | 2.10.1 (separate hash-locked environment) | Known vulnerabilities (OSV) of exactly pinned dependencies in `requirements*.txt` and `pylock.toml` | Runs only with `--allow-network`; nothing is installed; `setup.py` is never executed |

Without a scanner the scan still runs and is reported as **partial** (exit code 3).

## Installation

Requirements: Windows 10/11 with PowerShell 5.1+, Python 3.12 (the only tested version;
`requires-python >= 3.12`), Git.

### 1. Python 3.12 without touching existing installations

Skip this if you already have Python 3.12.

```powershell
winget install --id Python.Python.3.12 --exact --source winget --scope user `
  --accept-package-agreements --accept-source-agreements `
  --override "/quiet InstallAllUsers=0 PrependPath=0 Include_launcher=0 AssociateFiles=0 Shortcuts=0"

& "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe" --version   # Python 3.12.x
```

A per-user install that does not change `PATH`, file associations or the existing `py`
launcher (the launcher still detects the new interpreter, so a bare `py` may now pick 3.12).

### 2. Virtual environment and the auditor

From the repository root, either install the project in editable mode:

```powershell
& "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe" -m venv .venv
.venv\Scripts\python.exe -m pip install -U pip
.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

or build and install the wheel (hatchling; two independent builds are byte-identical):

```powershell
.venv\Scripts\python.exe -m pip install hatchling
.venv\Scripts\python.exe -c "import hatchling.build as b; print(b.build_wheel('dist'))"
.venv\Scripts\python.exe -m pip install dist\ai_code_auditor-0.1.0-py3-none-any.whl
```

Activating the environment is optional. In VS Code, select `.venv\Scripts\python.exe` as the
interpreter.

### 3. Semgrep in its own tool environment

Semgrep has a large dependency tree, so it lives in a separate environment at a fixed per-user
location. The auditor never looks for it on `PATH`.

```powershell
& "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe" -m venv "$env:LOCALAPPDATA\ai-code-auditor\tools\semgrep"
& "$env:LOCALAPPDATA\ai-code-auditor\tools\semgrep\Scripts\python.exe" -m pip install `
    --disable-pip-version-check --only-binary ":all:" "semgrep==1.182.1"
```

Set `AUDITOR_TOOLS_DIR` (an absolute path) to use a different tools location.

### 4. Gitleaks (pinned official release)

Download the official `gitleaks_8.30.1_windows_x64.zip` release from GitHub, verify the zip
against **both** the release's `gitleaks_8.30.1_checksums.txt` and the asset digest shown by the
GitHub API, then extract only `gitleaks.exe` to:

```text
%LOCALAPPDATA%\ai-code-auditor\tools\gitleaks\8.30.1\gitleaks.exe
```

Do not add it to `PATH`. The auditor checks the executable's SHA-256 against a value pinned in
the code before every run and refuses any other binary. The release is not signed, so the hash
proves integrity against the verified release, not the publisher's identity.

### 5. pip-audit (hash-locked tool environment, optional)

pip-audit lives in its own environment. Download the wheels listed in
`tools/pip-audit-2.10.1.lock.txt` (wheels only), verify each against PyPI's published SHA-256,
then install offline:

```powershell
& "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe" -m venv "$env:LOCALAPPDATA\ai-code-auditor\tools\pip-audit"
& "$env:LOCALAPPDATA\ai-code-auditor\tools\pip-audit\Scripts\python.exe" -m pip install --isolated `
    --no-index --find-links <verified-wheels-dir> --require-hashes --only-binary ":all:" `
    -r tools\pip-audit-2.10.1.lock.txt
```

### 6. Verify

```powershell
.venv\Scripts\auditor.exe --version      # auditor 0.1.0
.venv\Scripts\auditor.exe doctor         # platform, Python, every scanner, ruleset integrity
.venv\Scripts\python.exe -m pytest -q    # development install only
```

`doctor` exits with code 1 on Python < 3.12, a missing or unverified scanner, or a failed
integrity check.

## Quick start

```powershell
.venv\Scripts\auditor.exe scan "C:\path\to\project"
```

The scan builds a read-only inventory, runs Ruff, Semgrep and Gitleaks, writes the report files
to `%LOCALAPPDATA%\ai-code-auditor\reports\<run_id>\` and prints a summary with coverage,
findings by severity and context, and the gate result. Dependency vulnerabilities are checked
only when you add `--allow-network`; without it the report says so and the scan is partial.

## CLI examples

```powershell
auditor scan "C:\path\to\project" --target-python 3.11       # syntax checks for the target's Python version
auditor scan "C:\path\to\project" --allow-network             # add the pip-audit dependency scan (OSV)
auditor scan "C:\path\to\project" --scan-git-history          # also scan every blob and commit message (offline)
auditor scan "C:\path\to\project" --fail-on high              # quality gate: exit 4 on HIGH or CRITICAL
auditor scan "C:\path\to\project" --fail-on high --unrated-as medium --quiet
auditor scan "C:\path\to\project" --disable-scanner semgrep   # deliberate skip; reported as missing coverage
auditor scan "C:\path\to\project" --gitleaks-workers 8        # 1-16, default 4
auditor scan "C:\path\to\project" --output-dir "D:\audit-reports" --max-files 20000
auditor report 20261030T120000Z-1a2b3c --format markdown      # show a saved run; no rescan, no network
```

| Command | Purpose |
|---|---|
| `auditor --help`, `auditor --version` | Help and installed version |
| `auditor doctor` | Platform, Python version, venv status, every scanner's path and version (Gitleaks also SHA-256), Semgrep ruleset and Gitleaks configuration integrity |
| `auditor scan PATH` | Read-only audit of a local project |
| `auditor report RUN_ID` | Show a stored run again (`--format summary\|markdown\|json`, `--reports-dir`); refuses runs whose integrity record is missing or does not match |

## Report outputs

Every run writes one folder `<run_id>` outside the target. The folder appears only when every
file was written and verified; a failed write leaves a hidden `.<run_id>.incomplete` folder with
`*.partial` files and no integrity record, which is never a valid report.

| File | Content |
|---|---|
| `report.json` | **Canonical report, schema 1.1.0** (`schemas/report-v1.schema.json`): run, permissions, coverage overall and per area, outcome by severity and `by_context`, gate, tools, findings (identifiers, group ids, context and its basis, evidence), relation groups, gaps, limitations, privacy note |
| `report.md` | Human-readable report rendered from `report.json` only; Markdown is escaped |
| `inventory.json`, `findings.json` | Legacy formats kept for one release (`findings.json` shows pip-audit findings with a MEDIUM placeholder; in `report.json` they are `UNRATED`) |
| `SHA256SUMS.json` | Integrity record of every file. It detects accidental or casual changes; **it is not a signature** |

**Two independent axes.** Coverage (`COMPLETE`/`PARTIAL`, per area `COMPLETE`, `PARTIAL`,
`FAILED`, `DISABLED`, `NOT_APPLICABLE`, `NOT_REQUESTED`, `NOT_PERMITTED`) says what was checked.
Findings and the gate say what was found. `COMPLETE` never means the project is safe.

**Relations** (`groups`): R1 `same_location` (different tools, same line), R2
`same_content_in_history` (the working-tree file is the identical git object of a history
finding, same rule and line), R3 `same_vulnerability` (same package version, shared
vulnerability id). Findings are never merged or removed, and every finding counts for the gate.

Every finding carries a path-based **context** (`production`, `test`, `docs`, `examples`,
`config`, `unknown`) with the directory name or file pattern it was derived from; findings under
test paths are also tagged `test-path`. Severity is never lowered by the context, and the context
is **not a security proof**: production code placed under `tests/` is classified as test.

Raw scanner output never reaches the reports. It is kept only in private per-user scratch
directories that are deleted after every run. Leftovers of earlier interrupted runs are reported
as `SECURITY WARNING [STALE_WORKSPACES_FOUND]` and never deleted automatically; a failed cleanup
is reported as `SECURITY ERROR [CLEANUP_FAILED]` with exit code 3.

## Quality gates

`--fail-on none|low|medium|high|critical` (default `none`) fails the run with exit code 4 when
at least one finding is at or above the threshold. `UNRATED` findings (pip-audit gives no
severity) count as `--unrated-as high|medium|ignore` (default `high`); their severity stays
`UNRATED`. Every scanner finding is `NEEDS_REVIEW`; the auditor never marks a finding as
confirmed.

| Exit code | Meaning |
|---|---|
| 0 | Complete coverage, and the gate passed or was not evaluated (never "the project is safe") |
| 1 | Internal error or reports could not be written (no complete-looking output is left behind) |
| 2 | Invalid input: target, output directory, `--target-python`, gate options; for `auditor report` an invalid, missing, changed or unsupported run |
| 3 | **Partial**: a discovery limit was hit; entries were unreadable or changed; a scanner is missing, unverified, failed or timed out; dependency manifests exist but were not checked (no `--allow-network`) or could not be audited; files could not be analysed or were scanned only with limitations; the git-history scan was refused, failed or left objects unanalysed; or temporary data could not be removed |
| 4 | **Quality gate failed** (takes precedence over 3; a partial run reports both) |

Precedence: 1 and 2 > 4 > 3. Without `--fail-on`, findings never change the exit code.

## Git history scanning

`--scan-git-history` (off by default) scans every reachable blob and commit message of the
target's repository for secrets, offline:

- **git never runs on the target's `.git`.** Objects and refs are copied into a private
  workspace whose configuration the auditor writes itself; the target's config, hooks,
  attributes, replace refs, grafts and logs are never used, and system/global git configuration
  is disabled.
- **Unsafe layouts are refused, never guessed:** links or junctions in `.git`, a `.git` file
  (gitdir redirect), alternates, partial clones, reftable, unknown extensions, a copy over
  1 GiB. The scan is then reported as not done (partial, exit 3).
- Every object is extracted as a file named by its object id and scanned with `gitleaks dir`
  with the same fixed options and configuration as the working-tree scan; every object carries
  an end marker, so unconfirmed objects (archives, errors) are reported as not analysed.
- **Attribution** is verified from the commit trees: every commit that introduces the content
  at a path is listed with commit id, date, path and line. Author names, e-mail addresses and
  message text are never put into a report.
- **Limits:** copy 1 GiB, extracted data 2 GiB, 10 MiB per object, 900 s in total. Not scanned:
  reflogs, unreachable objects, submodules, linked worktrees, tag messages. One raw finding is
  reported per blob version that contains a value, so long histories produce repeated findings
  for the same secret.

## Verified SQL injection flow detection

Semgrep CE taint tracking stays inside one function, so `view (request data) -> helper
(formatted SQL)` is only ever a pattern finding (`formatted-sql-query`, Ruff `S608`; MEDIUM,
because the source is unknown). Two Semgrep **evidence rules** record where a function
parameter reaches SQL text and where request data reaches a call argument; they are never
findings and never count. The auditor then joins them with a static, execution-free `ast` check
of the target's own files: exact import binding, one module file, exactly one function
definition, positional or keyword argument to parameter, parameter to SQL text through at most
three local assignments, no `int()`/`float()`. Only a fully resolved chain raises the existing
finding at that line to HIGH, with the proof as evidence, for example:

```text
view.py:8 request data -> login(username) -> lib.py:6 SQL text
```

The status stays `NEEDS_REVIEW`. Anything uncertain (re-bound aliases, two candidate modules,
`*args`/`**kwargs`, dynamic calls, constant arguments, sanitised values, frameworks other than
Flask/Django request objects) leaves the finding at MEDIUM. Measured on the Vulpy benchmark:
exactly the three exploitable SQL injections were raised to HIGH; the constant-data locations
stayed MEDIUM; Flask and the auditor's own repository produced no new HIGH findings.

## Security and privacy design

- **Untrusted target.** Nothing in the target is executed, imported, installed or compiled; no
  file is written into it; `--output-dir` inside the target is refused; links, junctions and
  other reparse points are never followed and are listed as excluded.
- **Trusted executables only.** Ruff is the binary installed next to the auditor; Semgrep,
  Gitleaks and pip-audit live in fixed per-user locations and Gitleaks is hash-verified before
  every run. There is no `PATH` lookup and no executable from the target is ever run. If the
  auditor's own environment lies inside the scanned project, that environment is still used and
  each run prints a "Trust assumption" note; prefer an environment outside the target.
- **The target's configuration has no effect** on any scanner (Ruff `--isolated`, private file
  copy for Semgrep, auditor-owned Gitleaks configuration, auditor-written git configuration);
  the presence of target scanner configuration is reported.
- **Secrets never leave the scanners.** Gitleaks runs with `--redact=100`; only rule id, line
  and columns are read from its output; findings never contain a value, its length or its
  entropy; secret-looking file names and message fragments are redacted in reports (a heuristic,
  not a leak guarantee).
- **Network only on request.** Without `--allow-network` no network access is attempted. With
  it, exactly the pinned package names and versions are sent to `api.osv.dev`, including
  private package names: do not use it on projects whose dependency names must stay
  confidential. Credentials in index URLs or proxies never appear in any output.
- **Coverage is proven per file.** Gitleaks receives an end marker after each file; a file
  counts as scanned only if the marker is reported. Files that could not be read, changed while
  read, exceeded limits, timed out or failed are *not analysed* and the scan is partial.
- **Reports are tamper-evident but unsigned**, written atomically to a per-user directory, and
  raw scanner output is deleted after every run (deletion works beyond 260-character paths,
  never follows links and only removes directories owned by the current account).

## Validation results

Measured on three public repositories at pinned commits, offline, with integrity snapshots, an
in-process guard and a TCP monitor:

- **Safety:** targets byte-identical across all scans; 0 target code executed; 0 network
  connections; 0 secret values, author names, e-mails or absolute paths in any output.
- **Vulpy (deliberately vulnerable):** the three exploitable SQL injections are HIGH with
  evidence; `--fail-on high` fails (exit 4); 9/9 verified vulnerabilities in the supported
  classes were detected (a very small sample).
- **Flask (real world):** 30 of 34 security-category findings are false positives (test
  fixtures, documentation examples, developer asserts); 2 by-design HIGH findings; no new HIGH
  after hardening.
- **leaky-repo (secret benchmark):** 14 of 42 risk files and at most 22 of 96 risk lines
  detected with the default Gitleaks rules; identical to a direct Gitleaks run.
- **Identity stability:** after the P9 fix, 5/5 identical fingerprint sets across runs.
- **Package:** 908 tests passed, 0 failed, 15 skipped; Ruff clean; reproducible wheel and
  sdist; clean offline installation and smoke scan verified.

Full report: `docs/MVP_VALIDATION.md`. The initial pilot before hardening is preserved as
`docs/PILOT_01_VALIDATION.md`. None of these results generalises to all Python projects.

## Known limitations

- **Platform:** verified on Windows 11 / CPython 3.12 only; Python 3.11, Linux and macOS are
  not claimed. Real-symlink and POSIX-specific tests did not run.
- **Accuracy is repository-specific**; see the figures above and their denominators.
- **Secret recall** is bounded by the default Gitleaks rule set; low-entropy passwords, hashes
  and many configuration-file credentials are missed; zip, gzip, PDF, 7-Zip, RAR, bzip2 and
  SQLite content is not scanned (reported as skipped, coverage partial).
- **Git history** produces one raw finding per blob version; reflogs, dangling objects,
  submodules, linked worktrees and tag messages are not scanned.
- **Verified SQL flow covers one shape only**; other cross-function flows stay MEDIUM.
- **Context is path-based**, never a security proof.
- **Dependencies:** only exact pins in `requirements*.txt` and `pylock.toml`; `poetry.lock`,
  `uv.lock`, `Pipfile.lock` and `setup.py` are not analysed; markers are not evaluated; OSV is
  not a guarantee.
- **Coverage is not a verdict**; the integrity record is not a signature; finding identities
  are location-based, so there is no tracking across runs.
- **Residual races:** a small Windows race window remains in the output-directory checks;
  stale workspaces and incomplete report folders are reported, never deleted automatically.

## Documentation

- `CHANGELOG.md` — what 0.1.0 contains and its known limitations.
- `docs/MVP_VALIDATION.md` — validation report of the released 0.1.0 build.
- `docs/PILOT_01_VALIDATION.md` — historical report of the initial pilot, before hardening.
- `schemas/report-v1.schema.json` — the report schema (1.1.0).
- `THIRD_PARTY_NOTICES.md` — third-party material contained in the published files.

Development planning, decision logs and progress tracking live in a private development
repository and are not part of the public release.

### Test fixtures and fake secrets

- `tests/fixtures/semgrep_rules/*.py` are **deliberately vulnerable, synthetic** Python files
  written for the Semgrep rule tests. They are only ever read by Semgrep as data; no test
  imports or executes them, and the project's own Ruff configuration excludes them.
- Secret-looking values in the tests are **fake**: most are generated at run time
  (`tests/conftest.py`, `FakeSecrets`); two tests keep a deliberately fragmented literal
  (`tests/security/test_ruff_security.py`, `tests/security/test_semgrep_security.py`). A
  Gitleaks scan of this repository therefore reports exactly those two `generic-api-key`
  findings; they are not credentials and are intentionally not suppressed.
- Some tests use non-ASCII file and directory names (Turkish, Japanese, emoji) on purpose to
  verify Unicode handling, normalisation and redaction.

## License

AI Code Auditor is licensed under the **Apache License 2.0** (`LICENSE`). The published
packages also contain four Gitleaks 8.30.1 default rules copied into
`src/auditor/rules/gitleaks/path-*.toml` under the MIT License (`THIRD_PARTY_NOTICES.md`), so
the package metadata declares the SPDX expression `Apache-2.0 AND MIT` for the distribution as
a whole. Semgrep, Gitleaks, Ruff, pip-audit and the Python dependencies are not distributed with
the project.
