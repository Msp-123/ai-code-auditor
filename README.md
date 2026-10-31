# AI Code Auditor

Evidence-based, **read-only** audit CLI for local Python projects. It never executes,
imports or modifies the target project, and it does not use the network unless explicitly
allowed.

> **Status:** v0.1.0 release candidate (Stage 6 MVP plus the post-pilot hardening round; not yet tagged or published; accuracy measured on three repositories only, see `docs/MVP_VALIDATION.md` and the known limitations in `CHANGELOG.md`). `auditor scan` builds a read-only file inventory and
> runs Ruff (code quality), Semgrep (security, the auditor's own ruleset), Gitleaks (secrets
> in the working tree; values are never shown) and, only with `--allow-network`, pip-audit
> (known vulnerabilities of pinned dependencies, via OSV). With `--scan-git-history` it also
> scans every blob and commit message reachable in the git history for secrets. One
> canonical report (`report.json`, schema v1) drives the Markdown report and the terminal
> summary; an optional quality gate (`--fail-on`) sets exit code 4. See `CHANGELOG.md`.

## Requirements

- Windows 10/11 with PowerShell 5.1+
- Python **3.12** (the only version tested; `requires-python >= 3.12`)
- Git

## Setup (Windows PowerShell)

### 1. Install Python 3.12 without touching existing Pythons

Skip this step if you already have Python 3.12.

```powershell
winget install --id Python.Python.3.12 --exact --source winget --scope user `
  --accept-package-agreements --accept-source-agreements `
  --override "/quiet InstallAllUsers=0 PrependPath=0 Include_launcher=0 AssociateFiles=0 Shortcuts=0"

& "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe" --version   # Python 3.12.x
```

This is a per-user install. It does not change `PATH`, file associations or the existing `py`
launcher. The existing `py` launcher still detects the new interpreter, so a bare `py` may now
pick 3.12. The project always calls Python by full path.

### 2. Create the virtual environment and install

Run these from the project root:

```powershell
& "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe" -m venv .venv
.venv\Scripts\python.exe --version                      # Python 3.12.x
.venv\Scripts\python.exe -m pip install -U pip
.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

Activating the environment is optional: `.venv\Scripts\Activate.ps1`. In VS Code, select
`.venv\Scripts\python.exe` as the interpreter.

### 3. Install Semgrep in its own tool environment

Semgrep (security scanner) has a large dependency tree, so it lives in a separate environment
at a fixed per-user location. The auditor never looks for it on `PATH`.

```powershell
& "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe" -m venv "$env:LOCALAPPDATA\ai-code-auditor\tools\semgrep"
& "$env:LOCALAPPDATA\ai-code-auditor\tools\semgrep\Scripts\python.exe" -m pip install `
    --disable-pip-version-check --only-binary ":all:" "semgrep==1.182.1"
```

Without Semgrep, scans still run but are reported as **partial** (exit code 3). Set
`AUDITOR_TOOLS_DIR` (an absolute path) to use a different tools location.

### 4. Install Gitleaks (pinned official release)

Gitleaks (secret scanner) is used as the official `gitleaks_8.30.1_windows_x64.zip` release
from GitHub. Verify the zip against **both** the release's `gitleaks_8.30.1_checksums.txt` and
the asset digest shown by the GitHub API, then extract only `gitleaks.exe` to:

```text
%LOCALAPPDATA%\ai-code-auditor\tools\gitleaks\8.30.1\gitleaks.exe
```

Do not add it to `PATH`. The auditor checks the executable's SHA-256 against a value pinned in
the code before every run and refuses any other binary. The release is not signed, so the hash
proves integrity against the verified release, not the publisher's identity. Without Gitleaks,
scans are reported as **partial** (exit code 3).

### 5. Install pip-audit (hash-locked tool environment)

pip-audit lives in its own environment at `%LOCALAPPDATA%\ai-code-auditor\tools\pip-audit`.
Download the wheels listed in `tools/pip-audit-2.10.1.lock.txt` (wheels only, no source
distributions), verify each one against PyPI's published SHA-256, then install offline:

```powershell
& "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe" -m venv "$env:LOCALAPPDATA\ai-code-auditor\tools\pip-audit"
& "$env:LOCALAPPDATA\ai-code-auditor\tools\pip-audit\Scripts\python.exe" -m pip install --isolated `
    --no-index --find-links <verified-wheels-dir> --require-hashes --only-binary ":all:" `
    -r tools\pip-audit-2.10.1.lock.txt
```

The hashes prove integrity against PyPI, not the publisher's identity.

### 6. Verify

```powershell
.venv\Scripts\auditor.exe --help
.venv\Scripts\auditor.exe --version
.venv\Scripts\auditor.exe doctor
.venv\Scripts\python.exe -m pytest -q
.venv\Scripts\ruff.exe check .
.venv\Scripts\ruff.exe format --check .
```

## Commands

| Command | Description |
|---|---|
| `auditor --help` | Show available commands |
| `auditor --version` | Show the installed version |
| `auditor doctor` | Show platform, Python version, venv status, the auditor's own Ruff, Semgrep and Gitleaks (path and version; Gitleaks also SHA-256), the Semgrep ruleset's and the Gitleaks configuration's integrity. Exits with code 1 on Python < 3.12, a missing or unverified scanner or a failed integrity check. |
| `auditor scan PATH` | Read-only audit of a local project: discovery (file inventory, exclusions, sensitive files), then a Ruff code-quality scan, a Semgrep security scan, a Gitleaks secret scan, (with `--allow-network`) a pip-audit dependency scan and (with `--scan-git-history`) a git history secret scan |
| `auditor report RUN_ID` | Show a stored run again (`--format summary\|markdown\|json`, `--reports-dir`). Read-only: starts no scanner, git or network; refuses runs whose `SHA256SUMS.json` is missing or does not match |

### `auditor scan`

```powershell
.venv\Scripts\auditor.exe scan "C:\path\to\project"
.venv\Scripts\auditor.exe scan "C:\path\to\project" --target-python 3.11
.venv\Scripts\auditor.exe scan "C:\path\to\project" --disable-scanner semgrep   # not a full audit
.venv\Scripts\auditor.exe scan "C:\path\to\project" --gitleaks-workers 8         # 1-16, default 4
.venv\Scripts\auditor.exe scan "C:\path\to\project" --allow-network               # dependency audit via OSV
.venv\Scripts\auditor.exe scan "C:\path\to\project" --scan-git-history            # secrets in git history (offline)
.venv\Scripts\auditor.exe scan "C:\path\to\project" --fail-on high                # quality gate: exit 4
.venv\Scripts\auditor.exe scan "C:\path\to\project" --fail-on high --unrated-as medium --quiet
.venv\Scripts\auditor.exe report 20261030T120000Z-1a2b3c --format markdown
.venv\Scripts\auditor.exe scan "C:\path\to\project" --output-dir "D:\audit-reports" --max-files 20000
```

- **Read-only.**
  - Discovery uses only directory listings and file sizes.
  - Ruff reads the inventory's `.py` and `.pyi` files in its own process.
  - Nothing in the target is executed, and nothing is written into the target.
- **The target cannot influence Ruff.**
  - Only the Ruff binary installed next to the auditor is used; there is no PATH lookup, and
    no executable from the target is ever run.
  - **Trust assumption:** if the auditor's own environment lies inside the scanned project
    (e.g. its `.venv`), that environment is still used, because it is the one already running
    the auditor. Each run then prints a "Trust assumption" note. Prefer an environment
    outside the target.
  - The target's Ruff configuration is ignored (`--isolated`), so it cannot exclude files,
    disable rules or point outside the project.
  - No cache is written (`--no-cache`).
  - `# noqa` comments are ignored (`--ignore-noqa`).
  - No fixes are ever applied.
- **Rules:** `E4, E7, E9, F, B, S, C901`. Severity comes from the auditor's own mapping table,
  and every scanner finding is `NEEDS_REVIEW` (never `CONFIRMED`).
- **`S101` (assert) in test files** (`tests/`, `test_*.py`, `*_test.py`, `conftest.py`) is
  suppressed, because pytest relies on `assert`. The suppressed count is always shown. S101
  still applies to all other code, and every other rule still applies to test files.
- **`--target-python`** (`3.7`–`3.15`) sets the Python version used for syntax checks. If
  omitted, `3.12` is assumed and the report says so.
- **Coverage is reported honestly.** A file Ruff cannot parse or read is listed as *not
  analyzed*, and the scan becomes **partial**. So does a missing, failing or timed-out Ruff.
- **Semgrep (security).**
  - **Ruleset:** the auditor's own versioned ruleset (14 finding rules: command injection, SQL
    injection, path traversal, SSRF, code injection, insecure deserialization, XXE, disabled
    TLS verification, template injection, JWT signature bypass, Flask debug; plus 2
    *evidence* rules, below). It is never downloaded from the Semgrep Registry, and its
    SHA-256 manifest is checked on every run.
  - **Verified cross-function SQL injection (H5):** Semgrep CE taint tracking stays inside one
    function, so `view (request data) -> helper (formatted SQL)` is only ever a pattern
    finding (`formatted-sql-query`, MEDIUM: the source is unknown). Two evidence rules record
    where a parameter reaches SQL text and where request data reaches a call argument; they
    are **never findings** and never count. The auditor then joins them with a static,
    execution-free `ast` check of the target's own files (exact import binding, one module
    file, one function definition, positional/keyword argument to parameter, parameter to SQL
    text through at most three local assignments, no `int()`/`float()`). Only a fully
    resolved chain raises the existing `formatted-sql-query` / Ruff `S608` finding at that
    line to HIGH, with the proof as evidence (`view.py:8 request data -> login(username) ->
    lib.py:6 SQL text`); the status stays `NEEDS_REVIEW`. Anything uncertain (aliases that
    are re-bound, two candidate modules, `*args`/`**kwargs`, dynamic calls, constant
    arguments, sanitised values) leaves the finding at MEDIUM.
  - **What Semgrep sees:** only a private copy of the target's `.py`/`.pyi` files. The
    target's `.semgrep.yml`, `.semgrepignore` and `.gitignore`, and `# nosemgrep` comments,
    have no effect.
  - **Offline:** metrics and version checks are off and only local rules are used. This is
    application-level, not an OS network block.
  - **Every finding is `NEEDS_REVIEW`.**
  - **Coverage of unparsable files:** Semgrep silently uses error-tolerant parsing. Files that
    Ruff cannot parse are therefore marked *scanned with limitations*, and the scan becomes
    partial.
  - **Not covered** (also listed in every report): flows through helper functions or across
    files other than the verified SQL case above (Semgrep CE taint analysis is
    intraprocedural); frameworks other than Flask/Django
    request objects, `input()` and `sys.argv`; allowlist checks (can cause false positives);
    authorization and business logic; secrets; dependency vulnerabilities.
- **Gitleaks (secrets).**
  - **Values are never shown or stored.** Findings carry the rule id, file, line, severity,
    confidence and a recommendation; never the value, its length or its entropy.
  - **Method:** every inventory file is read by the auditor (links are never followed; the
    file must not change while it is read) and passed to its own `gitleaks stdin` process
    through a pipe. No copy of any file content is written to disk.
  - **Fixed options:** `--redact=100`, `--log-level error` (debug/trace would print secrets),
    the auditor's own hash-verified configuration (no global allowlist). Gitleaks' stderr is
    discarded, and only `RuleID` and `StartLine` are read from its report.
  - **The target cannot hide secrets:** its `.gitleaks.toml`, `.gitleaksignore`, inline
    `gitleaks:allow` comments and `GITLEAKS_*` variables have no effect; their presence is
    reported.
  - **Coverage is checked per file.** A random end marker is appended after each file's
    content; the file counts as scanned only if Gitleaks reports it, which proves the whole
    input was read. A file that could not be read, changed while being read, is over the size
    limit, timed out or failed is *not analyzed* (partial scan). A self-check with known fake
    values runs before the scan.
  - **Path-conditioned rules** (`kubernetes-secret-yaml`, `hashicorp-tf-password`,
    `nuget-config-password`, `freemius-secret-key`) are applied through path-less copies,
    only to files whose path matches (verified against Gitleaks' own `dir` mode). YAML files
    are therefore fully scanned. `.p12`/`.pfx` files are reported as *potentially sensitive
    files* from their name, never as a detected secret value.
  - **Limitations** (also listed in every report): Gitleaks' path allowlists (lockfiles,
    images, vendored code) do not apply on stdin, which can add false positives. Zip, gzip and
    PDF files are not scanned at all (reported as *not analyzed*). Only the working tree is
    scanned by this scanner; git history is a separate, opt-in scan (below).
  - Every finding of every scanner carries a path-based **context** (`production`, `test`,
    `docs`, `examples`, `config` or `unknown`) with the directory name or file pattern it was
    derived from; findings under test paths are also tagged `test-path`. Severity is never
    lowered by the context. The context comes from names only and is **not a security proof**:
    production code placed under `tests/` is classified as test (same limit as D-034).
- **Git history secrets (`--scan-git-history`, off by default).**
  - **git never runs on the target's `.git`.** It is read without following links; objects
    and refs are copied into a private workspace whose config the auditor writes itself. The
    target's config, hooks, attributes, replace refs, grafts and logs are never used, and
    system/global git configuration is disabled (measured: on the target itself, `textconv`,
    `include.path` and `gpg.program` from its config run commands, and `-diff`/`binary`
    attributes and replace refs hide content).
  - **Refused, never guessed:** links or junctions in `.git`, a `.git` *file* (gitdir
    redirect), alternates (also UNC paths), partial clones, reftable, unknown repository
    extensions, a copy over 1 GiB. The scan is then reported as not done (partial, exit 3).
  - **Every reachable blob and commit message** (all refs and HEAD) is extracted as a file
    named by its object id and scanned with `gitleaks dir` and the same fixed options and
    configs as the working-tree scan. `gitleaks git` is not used: measured, it misses content
    introduced only by a merge, skips lock files, images and `node_modules` through its path
    allowlist, ignores commit messages, returns "no leaks" when git fails and puts authors,
    e-mails and raw commit messages (secrets included) into its output.
  - **Proof of reading:** every extracted object carries the end marker; one that is not
    confirmed (archives, errors) is reported as not analyzed.
  - **Attribution is verified from the commit trees:** every commit that introduces the
    content at a path is listed with its commit id, date, path and line. Content reachable
    only through a tag gets no commit or path. Author names, e-mail addresses and message
    text are never put into a report; findings in commit messages are located as
    `(commit message)`.
  - `still-in-working-tree` is set only when the working-tree file at the same path is the
    identical git object; no `removed-from-tree` tag exists.
  - **Limits:** copy 1 GiB, extracted data 2 GiB, 10 MiB per object, 900 s in total;
    anything beyond is listed as not analyzed (partial). Not scanned: reflogs, unreachable
    objects, submodules, linked worktrees, tag messages.
- **pip-audit (dependencies).**
  - **Network only with `--allow-network`.** Without it pip-audit is not started, the report
    says prominently that dependency vulnerabilities were *not* checked, and the scan is
    partial (exit 3). With it, exactly the pinned package names and versions are sent to
    `api.osv.dev` (the fixed service); nothing else leaves the machine. **This includes
    private or internal package names**: they are not filtered or hidden, so do not use
    `--allow-network` on projects whose dependency names must stay confidential.
  - **Nothing is installed or executed.** The auditor's own parser reads `requirements*.txt`
    (with `-r`/`-c`, confined to the project root and inventory) and `pylock.toml`, and passes
    pip-audit plain `name==version` lists (`--disable-pip --no-deps`). `setup.py` is never
    run.
  - **`pyproject.toml` declarations count as covered only through a `pylock.toml` in the
    same directory** that provably pins each of them: present, a version that satisfies the
    declared range, and the same condition (markers are compared as text, never evaluated).
    Anything that cannot be verified (missing, conflicting, other markers, pre-releases,
    `environments`-restricted locks, dynamic dependencies, no lock) is listed as not audited
    and the scan is partial. Transitive completeness of the lock is not verified.
  - **Only exact pins are audited.** Ranges, URLs, VCS, local paths, non-PyPI sources and
    unsupported formats (setup.py, unlocked pyproject.toml declarations, setup.cfg
    declarations, Poetry sections, Pipfile, poetry.lock, uv.lock, pdm.lock) are listed as not
    audited.
  - **Markers are not evaluated**: the auditor's Python/OS is not assumed to be the target's.
    A finding on a conditional dependency says so, and does not claim it is installed.
  - **No finding is not proof of safety**: it means OSV lists no known vulnerability for that
    exact version. Findings are MEDIUM and marked UNRATED (pip-audit gives no severity).
  - Credentials in index URLs or proxies never appear in any output; pip-audit's stderr is
    not stored.
- **`--disable-scanner ruff|semgrep|gitleaks|pip-audit`** skips a scanner on purpose. The report then states
  prominently that this coverage is missing.
- **Links are never followed.** Symlinks, junctions and other reparse points are listed as
  excluded.
- **Reports go to a per-user directory, never into the target.** The default is
  `%LOCALAPPDATA%\ai-code-auditor\reports\<run_id>\`. On Linux it is
  `$XDG_DATA_HOME/ai-code-auditor/reports` (default `~/.local/share/...`).
  - An `--output-dir` inside the target is refused.
  - Every directory the auditor creates is verified after creation (link/race protection).
- **Raw scanner output never reaches the reports.** It is kept only in private, per-user
  scratch directories and deleted after every run:
  - `...\ai-code-auditor\tmp\` for Ruff;
  - a short `%TEMP%\aca\r-*` directory for Semgrep, which also holds its redirected
    `HOME` and the private file copy. Semgrep never writes to `%USERPROFILE%\.semgrep`.
  - Deletion also works beyond 260 characters, never follows links or junctions, and only
    removes directories owned by the current account.
  - Only the current run's own directories are deleted automatically. Leftovers of earlier,
    interrupted runs (older than 2 hours) are **not** deleted; each scan reports their
    number as `SECURITY WARNING [STALE_WORKSPACES_FOUND]`, because they may contain
    sensitive data. Review and delete them manually.
  - **If deletion fails**, the run is reported as `SECURITY ERROR [CLEANUP_FAILED]` (terminal
    and `report.md`, plus `operational_errors` in `findings.json`) and exits with 3. The
    left-over folder may contain sensitive data such as source code; the report names the
    folder, not full paths. Findings stay valid.
- **Output files:**
  - `inventory.json`: the full file inventory, schema-validated.
  - `findings.json`: scanner executions, normalised findings, and a per-file coverage state
    for every scanner (`SCANNED`, `SCANNED_WITH_LIMITATIONS`, `NOT_ANALYZED`, `NOT_RUN`,
    `NOT_APPLICABLE`).
  - `report.md`: a human-readable summary.
- **Redaction and sensitive files:**
  - Secret-looking file names and message fragments are redacted. **This is a heuristic, not
    a leak guarantee:** short or low-entropy secrets are not detected. Secret detection
    proper is Gitleaks (see above).
  - Fix edits (code text) are never stored.
  - Sensitive files (`.env`, keys, certificates) are listed, but flagged as never allowed into
    AI context.

### Report files (one run folder `<run_id>`)

| File | Content |
|---|---|
| `report.json` | **Canonical report, schema 1.1.0** (`schemas/report-v1.schema.json`; `auditor report` also shows 1.0.0 runs): run, permissions, coverage (overall and per area), outcome (incl. `by_context`), gate, tools, findings (with `identifiers`, `group_ids`, path-based `context` and `context_basis`), relation groups, gaps, limitations, privacy note |
| `report.md` | Human-readable report, rendered from `report.json` only |
| `inventory.json`, `findings.json` | **Legacy** formats, kept for one release. Difference: `findings.json` shows pip-audit findings with the MEDIUM placeholder and has no `identifiers`/`group_ids`; in `report.json` their severity is `UNRATED` |
| `SHA256SUMS.json` | Integrity record (SHA-256 of every file). It detects accidental or casual changes; **it is not a signature** and gives no guarantee against someone who can write to the report directory |

A run folder appears only when every file was written and verified. A failed write leaves a
hidden `.<run_id>.incomplete` folder whose files are named `*.partial` and which has no
integrity record: never a valid report. Such folders are reported on the next run and never
deleted automatically.

**Two independent axes.** Coverage (`COMPLETE`/`PARTIAL`, and per area: `COMPLETE`, `PARTIAL`,
`FAILED`, `DISABLED`, `NOT_APPLICABLE`, `NOT_REQUESTED`, `NOT_PERMITTED`) says what was
checked. Findings and the gate say what was found. COMPLETE never means that the project is
safe or that every possible check was made. Areas switched off with `--disable-scanner` are
named in the first lines of the summary and the report.

**Relations** (`groups`): R1 `same_location` (different tools, same line; location only, not a
common root cause), R2 `same_content_in_history` (the working-tree file is the identical git
object of a history finding, same rule and line), R3 `same_vulnerability` (same package
version, shared vulnerability id or alias). Findings are never merged or removed, and every
finding counts for the gate.

**Quality gate**: `--fail-on none|low|medium|high|critical` (default `none`). UNRATED findings
count as `--unrated-as high|medium|ignore` (default `high`); their severity stays UNRATED.

| Exit code | Meaning |
|---|---|
| 0 | Complete coverage, and the gate passed or was not evaluated (never "the project is safe") |
| 1 | Internal error or reports could not be written (no complete-looking output is left behind) |
| 2 | Invalid input: target, output directory, `--target-python`, gate options; for `auditor report`: invalid run id, missing, changed or unsupported report (nothing written) |
| 3 | **Partial**: a discovery limit was hit; entries were unreadable or changed; Ruff, Semgrep, Gitleaks or pip-audit is missing, unverified, failed or timed out (including a failed ruleset or configuration check); dependency manifests exist but were not checked (no `--allow-network`) or could not be audited; some files could not be analyzed; some files were scanned only with limitations; the requested git history scan was refused (unsafe repository structure), failed, timed out or left objects unanalyzed; or temporary data could not be removed (`CLEANUP_FAILED`) |

| 4 | **Quality gate failed**: at least one finding at or above `--fail-on` (takes precedence over 3; a partial run reports both) |

Without `--fail-on`, findings never change the exit code: **COMPLETE / exit 0 means that every
requested check covered its whole scope, not that nothing was found.** The console (`Total:`,
`Gate:`) and the report (`Findings:`, `Gate:`) show the findings by severity.

## Project documents

- `CHANGELOG.md`: what each version contains and its known limitations
- `docs/MVP_VALIDATION.md`: measured accuracy and safety on three open-source repositories
- Development planning, decision log and progress tracking live in the private development
  repository and are not part of the public release.
- `LICENSE` (Apache-2.0) and `THIRD_PARTY_NOTICES.md` (the four Gitleaks default rules copied
  into `src/auditor/rules/gitleaks/path-*.toml`, MIT). The package metadata therefore declares
  the SPDX expression `Apache-2.0 AND MIT` for the distribution as a whole.

## Test fixtures and fake secrets

- `tests/fixtures/semgrep_rules/*.py` are **deliberately vulnerable, synthetic** Python files
  written for the Semgrep rule tests. They are only ever read by Semgrep as data; no test
  imports or executes them, and the project's own Ruff configuration excludes them.
- Secret-looking values in the tests are **fake**: most are generated at run time
  (`tests/conftest.py`, `FakeSecrets`); two tests keep a deliberately fragmented literal
  (`tests/security/test_ruff_security.py`, `tests/security/test_semgrep_security.py`). A
  Gitleaks scan of this repository therefore reports exactly those two `generic-api-key`
  findings; they are not credentials and are intentionally not suppressed.
