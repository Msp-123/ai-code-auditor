# MVP validation pilot 01 — real GitHub repositories (historical)

> **Historical validation report — This document describes the initial Pilot 01 results before
> subsequent hardening improvements. For current v0.1.0 results, see MVP_VALIDATION.md.**
>
> The measurements below were taken on 2026-10-30 with the first 0.1.0 build (development
> commit `0ecc262`, report schema 1.0.0). They are kept unchanged as the baseline that the
> hardening work was measured against. The findings P1–P8 listed in §7 were addressed or
> deliberately deferred afterwards; §10 summarises what happened to each of them without
> altering the original figures.

- **Date:** 2026-10-30
- **Version:** AI Code Auditor 0.1.0 (development commit `0ecc262`)
- **Status:** PILOT COMPLETED — accepted by the project owner on 2026-10-30. Safe operation,
  target integrity, privacy, network isolation and error handling passed. The accuracy and
  report-quality gaps (§7) were carried into the "MVP Accuracy & Reliability Hardening" plan.
  The `v0.1.0` tag, GitHub release and PyPI publication were postponed because of those gaps.
- **Out of scope:** no product code changed during this pilot; no commit, tag or release was
  created. No OSV query was made (not approved).

## 1. Summary

| Question | Result |
|---|---|
| **Did the target change?** | No. Across 3 repositories × 4 scenarios, file and `.git` contents (SHA-256, size, mtime) stayed byte-identical. |
| **Did target code run?** | No. The auditor process never imported, executed or compiled anything from the target. The only child processes were the 4 trusted executables, none with a working directory inside the target. |
| **Was there unauthorised network access?** | No. No DNS or connection attempt from the auditor process. No non-loopback TCP connection from the tool processes. |
| **Did a secret leak?** | No. Reports and console output contained no secret value, no middle fragment of a value, no benchmark token, no author name, e-mail or absolute path. |
| **Any false COMPLETE?** | No. Every object that could not be analysed was reported as PARTIAL. ERROR, TIMED_OUT and CLEANUP_FAILED never occurred. |
| **Stop condition** | Not triggered. |
| **Product defects** | No security defect. 8 accuracy and usability findings (§7). |

**Most important accuracy findings:**

1. **Severity calibration (P1):** the exploitable SQL injections in Vulpy were reported only as
   MEDIUM, so the deliberately vulnerable application passed the `--fail-on high` gate. Flask,
   by contrast, failed the gate because of its by-design `exec`/`eval` (S102/S307, HIGH).
2. **Secret coverage (leaky-repo):** the default Gitleaks rules produced findings in only 14 of
   the 42 files that contain risks. At most 22 of 96 risk lines (about 23 %) matched.
   Low-entropy passwords, hashes, PHP/.env/XML credentials, `.netrc` and `.git-credentials` were
   not detected. The adapter matched direct Gitleaks results location for location; the limit
   lies in the engine's rule set.
3. **Noise (Flask):** 30 of the 34 security-category findings in Flask were false positives (20
   under `tests/`, 6 under `docs/`). In the git history the same documentation example (at
   most 2 distinct values) was listed as 224 separate findings.

### The metrics have different denominators

The ratios in this document are **not comparable with each other**; each has its own numerator,
denominator and unit. None of them represents the Python ecosystem: three repositories, manual
classification and small samples.

| Metric | Unit | Numerator / denominator | Note |
|---|---|---|---|
| Vulpy recall 9/9 | Vulnerability verified by reading the code (`bad/`) | Detected / vulnerabilities the existing rules could catch | Unsupported classes are not in the denominator (§6). Very small denominator (9) |
| Vulpy precision 51/59 | Finding (before R1; 49 locations) | True / all security findings (`bad/`, `good/`, `utils/`) | A deliberately vulnerable repository; does not represent real-world precision |
| Flask precision 3/34 | Finding | True / all security-category findings | Maintenance and style findings (17) excluded |
| leaky-repo file coverage 14/42 | File | Files with at least one finding / files with a risk line in `secrets.csv` | Not verified that the finding is on the risk line |
| leaky-repo line coverage ≤ 22/96 | Line | Sum per file of `min(found lines, risk lines)` / risk lines | **Upper bound**; the benchmark gives no line numbers |
| History completion ratios (e.g. 313/319) | Git object (blob + commit message) | Analysed / listed | A coverage measure, not accuracy |
| Working-tree ratios (e.g. 113/113) | File | Analysed / files applicable to the tool | Depends on the tool (Ruff/Semgrep: Python files; Gitleaks: all files) |

## 2. Repositories tested

| Repo | Commit (HEAD) | Branch | Licence | Files (tracked) | Commits (all refs / HEAD) | Refs | Objects | Size (working tree / `.git`) | Git structure |
|---|---|---|---|---|---|---|---|---|---|
| `fportantier/vulpy` | `5249cc8b05a1c37f6b2f757b1cf16a509c327122` | master | MIT | 113 | 58 / 58 | 3 remote branches, 0 tags | 437 (1 pack) | 4.8 MB / 3.1 MB | format 0, no extensions, no submodules, no LFS. **2 symlinks** (`*/payloads/payload.js` → `keylogger.js`) became plain files through `core.symlinks=false` |
| `Plazmaz/leaky-repo` | `2e951359cac53addbee56437da3ffb546e3dfe24` | master | MIT | 61 | 26 / 25 | 3 remote branches, 4 tags | 233 (1 pack) | 0.6 MB / 0.08 MB | format 0, no extensions, submodules, LFS or symlinks |
| `pallets/flask` | `d086db856be187255b8ec61ef409357393020f32` | main | BSD-3-Clause | 236 | 5603 / 5562 | 5 remote branches, 69 tags | 26 390 (1 pack) | 1.8 MB / 13.5 MB | format 0, no extensions, submodules, LFS or symlinks. History since 2010 |

### Acquisition method

This was the pilot's only network step: only `github.com`, only these three repositories.

- **Git:** the trusted executable `C:\Program Files\Git\mingw64\bin\git.exe`; write permission
  only for SYSTEM and Administrators.
- **Isolated configuration:**
  - `GIT_CONFIG_NOSYSTEM=1`, an empty global config, a private `HOME`;
  - `GIT_TERMINAL_PROMPT=0`, credential helper disabled;
  - `--template=` and `core.hooksPath=NUL` (no hooks);
  - `--no-recurse-submodules`, `GIT_LFS_SKIP_SMUDGE=1` and empty LFS filters;
  - `protocol.allow=never` plus `https` only;
  - `core.symlinks=false`, `core.autocrlf=false`;
  - `transfer.fsckObjects=true` (received objects are verified).
- **Flask exception:** the first clone was rejected by fsck because of the `zeroPaddedFilemode`
  warning in 2010-era commits. It was cloned again with only that message ignored
  (`fetch.fsck.zeroPaddedFilemode=ignore`); all other fsck checks stayed on.
- **Never executed:** repository code, tests, hooks and setup scripts were never run. No
  dependency was downloaded.
- **Metadata commands:** read-only `git` commands (`rev-parse`, `rev-list`, `ls-files`,
  `count-objects`) ran after cloning, before the first integrity snapshot.

## 3. Method

### Laboratory: a local folder outside the project, used only for this pilot

| Folder | Content |
|---|---|
| `env\` | Clean venv. The verified 0.1.0 wheel (sha256 `fef7f80b…24ea`) installed with `--no-index --require-hashes`. 64 package files byte-identical to the wheel. The project `.venv` (0.0.1) was not used. |
| `sources\` | Clones |
| `reports\<repo>\<scenario>\` | Auditor reports |
| `measurements\` | Measurements and logs |
| `scripts\` | Pilot scripts |
| `git-home\` | Isolated git configuration |

### Scenarios (per repository)

| Scenario | Command |
|---|---|
| s1 | `auditor scan <repo>` (offline, defaults) |
| s2 | `--scan-git-history` |
| s3 | `--fail-on high` |
| s4 | the s1 run shown again with `auditor report <RUN_ID>` in `summary` and `json` format |

### Observation tools

1. **Integrity snapshot.** Before and after every scan, SHA-256, size and mtime of every file in
   the target (including `.git`) were recorded without following links. Directory and link
   lists were compared as well. For s4 the run folder was snapshotted too.
2. **In-process guard (`guard_run.py`, Python audit hook).** The auditor CLI ran under this guard,
   which recorded:
   - every child process (executable and cwd);
   - every DNS and socket attempt (non-loopback **denied**);
   - every write, delete, rename and chmod attempt under the target;
   - every import, exec or compile from the target (**denied**).

   The guard tested itself first: write, DNS, connect, import and subprocess attempts were all
   recorded and denied.
3. **TCP monitor.** Non-loopback TCP connections of the processes belonging to the auditor
   environment, the tools and Git were watched throughout the scans. Window 14:41:23Z–14:46:00Z,
   524 polls (about 0.5 s apart).
4. **Leak check (`leak_check.py`).**
   - Secret values were kept in memory only; Gitleaks ran directly and wrote its report to stdout.
   - Sources: working tree (pinned config and default config) and `gitleaks git --all`; for
     leaky-repo also the long tokens in the benchmark files.
   - Searched: all report files and console outputs.
   - Searched for: the full value, the middle 12 characters of values ≥ 20 characters, author
     and committer names/e-mails, absolute paths. Only counts were printed.
5. **Accuracy.**
   - Relations (`relations_check.py`): R1/R2 groups verified, blob ids recomputed for R2, missed
     groups searched for. Working-tree Gitleaks results compared location by location with a
     direct `gitleaks dir` run.
   - Benchmark (`leaky_benchmark.py`): compared with leaky-repo's `secrets.csv`.
   - Vulpy and Flask findings classified manually by reading the code (read as data only;
     nothing was executed).

### Limits of the observation tools

- The guard sees only the auditor's own Python process. File access of child processes was
  covered by the integrity snapshot, network access by the TCP monitor.
- The TCP monitor polls (about 0.5 s), so very short connections could be missed. No positive
  control was run, because a non-loopback connection would itself have been unauthorised
  network access.
- The integrity snapshot does not track access time (atime).

## 4. Measurement table

When the only reason for PARTIAL is the dependency area (`NOT_PERMITTED`), this is the expected
behaviour under the user's decision, not a product defect.

| Repo / scenario | Exit | Time | Coverage | Ruff | Semgrep | Gitleaks (working tree) | pip-audit | Gitleaks (history) | CRIT | HIGH | MED | LOW | UNRATED | History findings | Not analysed | Gate | `report.json` / `.md` |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| vulpy s1 | 3 | 19.5 s | PARTIAL (dependencies NOT_PERMITTED) | SUCCESS 57/57 | SUCCESS 57/57 | SUCCESS 113/113 | SKIPPED 0/1 | — | 0 | 0 | 62 | 61 | 0 | — | 0 | NOT_EVALUATED | 269 / 30 KB |
| vulpy s2 | 3 | 18.3 s | PARTIAL (+ secrets_history PARTIAL) | SUCCESS | SUCCESS | SUCCESS | SKIPPED | SUCCESS 313/319 (blobs 255/261, messages 58/58), 1.5 s | 0 | 0 | 66 | 61 | 0 | 4 | 6 objects: 5 SQLite `TOOL_ERROR`, 1 object > 10 MiB `SIZE_LIMIT` | NOT_EVALUATED | 296 / 34 KB |
| vulpy s3 | **3** | 19.2 s | PARTIAL | SUCCESS | SUCCESS | SUCCESS | SKIPPED | — | 0 | 0 | 62 | 61 | 0 | — | 0 | **PASSED** (0 ≥ high) | 269 / 30 KB |
| leaky-repo s1 | 3 | 13.9 s | PARTIAL (**secrets_working_tree PARTIAL**; dependencies NOT_APPLICABLE) | SUCCESS 2/2 | SUCCESS 2/2 | SUCCESS 58/60 | SKIPPED (no manifest) | — | 2 | 2 | 20 | 4 | 0 | — | 2 files (`cert9.db`, `key4.db`) `TOOL_ERROR` | NOT_EVALUATED | 105 / 17 KB |
| leaky-repo s2 | 3 | 13.1 s | PARTIAL | SUCCESS | SUCCESS | SUCCESS 58/60 | SKIPPED | SUCCESS 153/155 (blobs 127/129, messages 26/26), 2.0 s | 4 | 6 | 48 | 4 | 0 | 34 (CRIT 2, HIGH 4, MED 28) | 2 files + 2 objects (the same NSS databases) | NOT_EVALUATED | 199 / 42 KB |
| leaky-repo s3 | **4** | 11.0 s | PARTIAL | SUCCESS | SUCCESS | SUCCESS | SKIPPED | — | 2 | 2 | 20 | 4 | 0 | — | 2 files | **FAILED** (4 ≥ high) | 106 / 17 KB |
| flask s1 | 3 | 30.6 s | PARTIAL (dependencies NOT_PERMITTED, 6 manifests) | SUCCESS 83/83 | SUCCESS 83/83 (0 findings) | SUCCESS 236/236 | SKIPPED 0/6 | — | 0 | 2 | 28 | 21 | 0 | — | 0 | NOT_EVALUATED | 272 / 19 KB |
| flask s2 | 3 | 59.0 s | PARTIAL (+ secrets_history PARTIAL) | SUCCESS | SUCCESS | SUCCESS | SKIPPED | SUCCESS 14 918/14 921 (blobs 9315/9318, messages 5603/5603), 27.2 s | 0 | 2 | 252 | 21 | 0 | 224 (all MED `generic-api-key`) | 3 objects `SKIPPED_BY_TOOL` (2 PDF, 1 `.egg`) | NOT_EVALUATED | **752** / 88 KB |
| flask s3 | **4** | 30.4 s | PARTIAL | SUCCESS | SUCCESS | SUCCESS | SKIPPED | — | 0 | 2 | 28 | 21 | 0 | — | 0 | **FAILED** (2: S102, S307) | 272 / 19 KB |

### Common results

- **Other report files:** every run produced 5 files (`report.json`, `report.md`,
  `findings.json`, `inventory.json`, `SHA256SUMS.json`). Additional sizes: `findings.json`
  72–586 KB, `inventory.json` 18–67 KB.
- **`auditor report` (s4):** exit 0 for all 3 repositories; 0.3–0.4 s.
  - No new child process or network attempt; no new run folder; the run folder stayed
    byte-identical.
  - The `--format json` output was identical to `report.json`.
- **Status separation:**
  - **PARTIAL:** 9/9 scans. Reasons above; all correct and explained.
  - **TIMED_OUT, ERROR, CLEANUP_FAILED:** 0.
- **Operational warning `STALE_WORKSPACES_FOUND`:** printed on every scan, caused by 42 of the
  82 old folders under `%TEMP%\aca`. Expected behaviour (D-042); nothing was deleted.
- **Relation groups:**
  - vulpy: R1 10 (s1, s3), R1 10 + R2 1 (s2);
  - leaky-repo: R2 22 (s2);
  - flask: R2 6 (s2);
  - R3 never occurred (no OSV query; expected).

### Invariants

| Invariant | Result |
|---|---|
| Target integrity | First and last snapshot identical for every repository. No change across 9 scans + 6 report commands. Still identical after the direct Gitleaks runs of the leak check. |
| Guard | Network attempts 0, writes to the target 0, import/exec/compile of target code 0, child processes with cwd in the target 0, loopback 0. |
| Child-process executables | Only these four: `C:\Program Files\Git\mingw64\bin\git.exe`, `env\Scripts\ruff.exe`, `ai-code-auditor\tools\gitleaks\8.30.1\gitleaks.exe`, `ai-code-auditor\tools\semgrep\Scripts\semgrep.exe` |
| TCP monitor | 0 connections (524 polls) |
| Temporary files | The auditor's own temp folder empty. No new `r-*` workspace. Old experiment leftovers in the system temp folder (82 folders, 1075 entries) unchanged. |
| Main project | HEAD `0ecc262`, git status and object count unchanged (apart from this document) |

### Leak check

| Repo | Direct Gitleaks findings (pinned / default / git) | Distinct values | Files searched | Value / middle-fragment matches | Benchmark tokens (searched / matched) | Author and e-mail | Absolute paths (report files) |
|---|---|---|---|---|---|---|---|
| vulpy | 1 / 1 / 4 | 1 | 23 | 0 / 0 | — | 0 * | 0 |
| leaky-repo | 22 / 22 / 26 | 16 | 23 | 0 / 0 | 182 / 0 | 0 | 0 |
| flask | 6 / 6 / 12 | 2 | 23 | 0 / 0 | — | 0 * | 0 (1741 names/e-mails searched) |

\* The initial matches were examined and both turned out to be dictionary words. In Vulpy an
author name, "root", occurs in the phrase "root cause" in the report. In Flask an author name,
"unknown", occurs in "Version: unknown". No real personal data.

## 5. Accuracy assessment

Classes:
- **True finding:** the security-relevant pattern the rule claims is really present in the code.
- **False positive (FP):** the pattern matched but is not a security issue in context.
- **Uncertain:** depends on context or on a trust assumption.

### 5.1 Vulpy (deliberately vulnerable application)

Scope rule: recall was measured only for vulnerabilities verified by reading the code, in the
classes that the existing rules (Ruff S, 14 Semgrep rules, Gitleaks) can catch. The scope is
limited to `bad/`, the deliberately vulnerable version. Unsupported classes are in §6.

**Verified, supported vulnerabilities (`bad/`):** 9/9 detected.

| # | Vulnerability | Location | Detection | Reported severity |
|---|---|---|---|---|
| 1 | SQL injection (login; form → `str.format` → `execute`) — authentication bypass | `bad/libuser.py:12` | Semgrep `formatted-sql-query` + Ruff S608 (R1 group) | MEDIUM |
| 2 | SQL injection (user creation) | `bad/libuser.py:25` | Semgrep + S608 (R1) | MEDIUM |
| 3 | SQL injection (password change; user name from a forged cookie) | `bad/libuser.py:53` | Semgrep + S608 (R1) | MEDIUM |
| 4 | Flask `debug=True` (Werkzeug debugger) | `bad/vulpy.py:55` | S201 + Semgrep (R1) | MEDIUM |
| 5 | Flask `debug=True` | `bad/vulpy-ssl.py:29` | S201 + Semgrep (R1) | MEDIUM |
| 6 | Hard-coded, weak `SECRET_KEY` | `bad/vulpy.py:16` | Ruff S105 (no Gitleaks: low entropy) | MEDIUM |
| 7 | Hard-coded `SECRET_KEY` | `bad/vulpy-ssl.py:13` | Ruff S105 | MEDIUM |
| 8 | API keys kept in shared `/tmp` file names | `bad/libapi.py:16,20,33` | Ruff S108 ×3 | MEDIUM |
| 9 | API key written to a shared `/tmp` file | `bad/api_post.py:6` | Ruff S108 | MEDIUM |

- **False negatives (supported classes):** 0.
- **Taint rules:** `tainted-sql-query` (ERROR) never fired, because source (`request.form`) and
  sink are in different functions (`mod_user` → `libuser`). Cross-function taint was already
  documented as unsupported (Semgrep CE).
- **Small sample:** 9 vulnerabilities. This number cannot be generalised.

**Precision: 59 security findings** (Ruff S 48, Semgrep 10, Gitleaks 1; 49 locations with R1).

| Section | Findings | True | FP | Uncertain | FP / uncertain details |
|---|---|---|---|---|---|
| `bad/` | 27 | 21 | 6 | 0 | S608 + Semgrep `db.py:19`, `db_init.py:20` (4 findings; constant seed data, not exploitable); S603 `brute.py:21` (deliberate brute-force tool, no shell); S110 `libsession.py:21` |
| `good/` | 15 | 13 | 1 | 1 | FP: S110 `good/libsession.py:22`. Uncertain: S108 `good/cutpasswd.py:3` (reads a word list from `/tmp`) |
| `utils/` | 17 | 17 | 0 | 0 | — (S108 ×15: private keys written to and read from `/tmp`; S113 ×2) |
| **Total** | **59** | **51 (86 %)** | **7** | **1** | |

Notes:
- `good/` still contains real issues; these are correct findings, not tool errors:
  - `good/libuser.py:61` SQL injection;
  - `good/libsession.py:9` hard-coded Fernet key (Gitleaks);
  - `good/libapi.py:10` hard-coded secret (S105);
  - `debug=True`.
- Most true findings are low risk: S113 missing timeouts, `/tmp` usage.

**Severity calibration:** all 3 exploitable SQL injections in Vulpy are MEDIUM. No finding is
HIGH, so the `--fail-on high` gate **passes** (exit 3, only because of the dependency PARTIAL).
See P1.

### 5.2 leaky-repo (fake-secret benchmark)

- **Ground truth:** the repository's own `.leaky-meta/secrets.csv`: 44 files; per file the
  number of risk lines and informational lines.
- **Matching method:** the benchmark gives no line numbers, so matching was done per file and by
  distinct line count. The line figure is therefore an **upper bound**: a found line may be an
  informational line rather than a risk line.
- **Old Gitleaks results are not comparable:** the repository's `GITLEAKS.md` figure (127/175) was
  produced with an older Gitleaks version and a custom config, counting informational lines too.

| Metric | Value |
|---|---|
| Files with risks | 42 |
| Risk files with at least one finding | **14 / 42 (33 %)** |
| Risk lines (upper-bound matching) | **≤ 22 / 96 (≤ 23 %)** |
| Findings in information-only files (`id_rsa.pub`, `high-entropy-misc.txt`) | 0 (no file-level FP) |
| Lines found beyond the risk count | 1 (`cloud/.s3cfg`: 2 lines / 1 risk; probably an informational line) |
| Findings outside the benchmark | 1 (`.leaky-meta/benchmark.py` Ruff S603; the benchmark tool itself, not a secret) |
| Not analysed | 2 Firefox NSS databases (`cert9.db`, `key4.db`): `TOOL_ERROR` → PARTIAL. The benchmark does not count these files |
| Adapter accuracy | The auditor's 22 working-tree findings are **identical** to a direct `gitleaks dir` run (pinned config) at the (path, line, rule) level |
| History | 34 findings (`gitleaks git`: 26); (path, rule) pairs 15 = 15. The difference comes from per-object reporting |

**Found:**
- private keys (`.ssh/id_rsa`, `misc-keys/cert-key.pem`; CRITICAL);
- Slack and Mailchimp tokens (HIGH);
- AWS, Heroku, Tugboat, Docker, npm and hub tokens and Rails `secrets.yml` (`generic-api-key`,
  MEDIUM);
- Django `SECRET_KEY` (Ruff S105 only).

**Missed (limit of the Gitleaks default rule set):**
- `db/dump.sql` (10 bcrypt hashes), `etc/shadow`, `.htpasswd`, `proftpdpasswd`: password hashes;
- `wp-config.php` (9), `config.php`, `web/var/www/.env` (6): low-entropy passwords and PHP `define`;
- `.mozilla/firefox/logins.json` (8): encrypted credentials;
- `.netrc`, `.git-credentials`, `.pgpass`, `.esmtprc`, `ventrilo_srv.ini`: plain password files;
- FileZilla, DBeaver, JetBrains, VS Code / Atom / Sublime SFTP configs, robomongo, mongoid;
- PuTTY `.ppk`, Rails `master.key`, Salesforce JS.

### 5.3 Flask (real world; false positives, performance, coverage)

**Sample:** **all 34 security-category findings** were assessed, above the requested minimum of
20. The remaining 17 findings are maintenance and style: C901, F401, E402, B018.

| Rule | Findings | True | FP | Uncertain | Reasoning |
|---|---|---|---|---|---|
| Gitleaks `generic-api-key` | 6 | 0 | 6 | 0 | `docs/config.rst` (5), `docs/tutorial/deploy.rst` (1): example `SECRET_KEY` values in documentation |
| S105 / S106 / S107 (`tests/`) | 9 | 0 | 9 | 0 | Test fixture values |
| S106 `examples/tutorial/flaskr/__init__.py:11` | 1 | 1 | 0 | 0 | Hard-coded short default secret placeholder in the example app (the comment says it should be overridden). Low risk |
| S101 `assert` (`src/`) | 5 | 0 | 5 | 0 | Developer consistency checks, not security checks |
| S102 `config.py:209` (`from_pyfile` exec) | 1 | 1 | 0 | 0 | Real code-execution point; by design, the input is a trusted config file |
| S307 `cli.py:1022` (`flask shell` PYTHONSTARTUP eval) | 1 | 1 | 0 | 0 | Real point; by design, the input is the user's own startup file |
| S110 | 7 | 0 | 7 | 0 | `config.py:163` (deliberate fallback to a string) and tests |
| S324 `sessions.py:281` (`hashlib.sha1`) | 1 | 0 | 1 | 0 | itsdangerous HMAC-SHA1 signature; HMAC-SHA1 is not broken |
| S704 `json/tag.py:188` (`Markup(value)`) | 1 | 0 | 0 | 1 | Markup built from signed session data; safety depends on the secret key staying secret |
| S704 (`tests/`) | 2 | 0 | 2 | 0 | Tests of the escaping behaviour |
| **Total** | **34** | **3 (9 %)** | **30** | **1** | **20 of the FPs are under `tests/`, 6 under `docs/`** |

Other observations:
- **Semgrep:** 0 findings in Flask (no taint source). Expected and correct.
- **Performance:** the full history scan of 236 files / 5603 commits / 26 390 objects took 59 s
  (Gitleaks history 27 s). Far below the 900 s limit.
- **History noise:** all 224 history findings are under `docs/config.rst` (220) and
  `docs/tutorial/deploy.rst` (4); at most 2 distinct values. `gitleaks git` reports 12 findings
  for the same content; the (path, rule) pairs are the same (2 = 2). The difference: the auditor
  reports **every blob version** that contains the value, while `gitleaks git` reports only the
  **diff that introduced** it. See P2.

### 5.4 R1–R3 correlation

| Relation | Groups | Verification | Result |
|---|---|---|---|
| R1 `same_location` | 10 (vulpy) | Each group: same path and line, different tools, all in the security category. Ungrouped same-line security pairs: 0 | **Correct and meaningful.** S608 ↔ `formatted-sql-query` (6) and S201 ↔ `flask-debug-enabled` (4) confirm the same vulnerability with two tools |
| R2 `same_content_in_history` | 1 / 22 / 6 | For every member the working-tree file's git blob id was recomputed; the same blob id, line, rule and history path held. Missed R2: 0 | **Correct.** It tells "this secret also exists in history with the same content". In Flask only 6 of 224 findings were grouped: R2 by design (blob and line must match) does not link old versions |
| R3 `same_vulnerability` | 0 | No OSV query | Not tested in this pilot (expected) |

## 6. Coverage gaps (not counted in the false-negative metric)

| Class | Example (repo: location) | Why it is not caught |
|---|---|---|
| XSS in templates (`\|safe`) | vulpy: `bad/templates/posts.view.html:23`, `messages.html:8` (stored/reflected XSS) | Our Semgrep rules scan only Python files; Jinja templates are not analysed |
| Unsigned session cookie / session forgery | vulpy: `bad/libsession.py` (base64 JSON, no signature) | Authentication and business logic are out of scope |
| Authentication bypass through glob/wildcard injection | vulpy: `bad/libapi.py:33` (`X-APIKEY: *`) | The path-traversal rule's sinks do not model `Path.glob` |
| Weak randomness | vulpy: `bad/libapi.py:14` (`random.getrandbits`) | Ruff S311 does not cover `getrandbits` (verified with a separate snippet) |
| Plain-text password storage, password logging through SQL trace | vulpy: `libuser.create`, `set_trace_callback(print)` | Needs logic and flow analysis |
| Hard-coded credentials in data structures | vulpy: `bad/db_init.py` (list of tuples) | S105/S106 only look at assignments and arguments with password-like names |
| CSRF, brute-force protection, password complexity, MFA logic | vulpy | Out of scope |
| Low-entropy passwords, hashes, credentials in config files, encrypted browser passwords | leaky-repo (§5.2) | Gitleaks default rule set (the adapter gives identical results) |
| Binary databases (SQLite, NSS) | vulpy history (5), leaky-repo (2 + 2) | Gitleaks does not confirm reading the content → `TOOL_ERROR` → PARTIAL (correct and on the safe side) |
| Archives/PDF/egg | flask history (3) | `SKIPPED_BY_TOOL` → PARTIAL |
| Objects above 10 MiB | vulpy history (`good/utils/sys`) | `SIZE_LIMIT` → PARTIAL |
| Dependency vulnerabilities | vulpy (1 manifest), flask (6 manifests) | No OSV permission in this pilot → `NOT_PERMITTED` (expected) |

## 7. Product findings (not fixed in this phase)

No security defect. All are accuracy, noise or usability matters. Each is reproducible with the
saved reports.

| # | Type | Finding | Reproduction | Impact |
|---|---|---|---|---|
| P1 | Severity calibration (high priority) | Pattern-based SQL injection (Semgrep WARNING, Ruff S608) and `debug=True` are MEDIUM. The taint rule is ERROR → HIGH, but does not fire on cross-function flows. Result: the vulnerable application passes `--fail-on high` | `auditor scan vulpy --fail-on high` → exit 3, gate PASSED; all 5 SQL findings under `bad/` (3 exploitable) are MEDIUM | A CI gate on "high" misses the most important web vulnerability; users may gain false confidence |
| P2 | Noise | The history scan produces a separate finding for every blob version that contains the same value. In Flask 224 findings for at most 2 values; R2 only links the identical blob in the working tree | `auditor scan flask --scan-git-history` | Reports swell (`report.json` 752 KB); genuinely new secrets may be overlooked |
| P3 | Noise / context | Findings in test and documentation paths count with the same weight in the gate and summary (the `test-path` tag exists but does not lower severity). S101 under `src/` counts as a security finding | Flask s1: 30 of 34 security findings are FP | Precision 9 % on real-world repositories |
| P4 | Gate usability | By-design risky APIs (S102/S307) fail the gate permanently. There is no way to mark an accepted risk (outside the target, user-approved baseline) without hiding the finding | `auditor scan flask --fail-on high` → exit 4 | A "high" gate in CI stays red on projects like Flask |
| P5 | Reporting precision | Binary SQLite/NSS databases are labelled `TOOL_ERROR` ("input not fully consumed" / "end marker"), PDF and egg `SKIPPED_BY_TOOL`. The coverage effect (PARTIAL) is correct, but the "tool error" label can mislead. Root cause (Gitleaks' binary-content behaviour) not verified | vulpy s2, leaky-repo s1 and s2 | Users may suspect a real tool failure |
| P6 | Usability | Without network permission the console says `Pip-audit: SKIPPED (version unknown)`; the tool is installed and `doctor` shows its version (2.10.1) | Every offline scan | Minor; confusing |
| P7 | Operational noise | The `STALE_WORKSPACES_FOUND` warning repeats on every scan for 42 old folders (deliberate policy, D-042) | Every scan | Waits for a manual clean-up decision; risk of warning fatigue |
| P8 | Reproducible build | `src/auditor/rules/semgrep/MANIFEST.json` is LF in git (`eol=lf`) but CRLF in the working tree and in the tested wheel. A wheel built from a clean clone has a different hash. No functional effect because the manifest is parsed as JSON; the rule file hashes are the same either way | `git ls-files --eol src/auditor/rules/semgrep/MANIFEST.json` → `i/lf w/crlf` | The wheel hash depends on the source checkout |

## 8. Suggested next improvements (as written at the time)

Suggestions; each needs a separate plan and approval.

1. **P1, severity policy:**
   - review the severity mapping for SQL injection and `debug=True`, e.g. HIGH for pattern-based
     SQL, or confidence/priority information when R1 shows two tools confirming the same
     vulnerability;
   - README warning "`--fail-on high` does not catch pattern-based SQL injection"; recommend
     `--fail-on medium` for CI.
2. **P2, de-duplication of history findings:** a single "history group" relation per rule and
   value (without storing the value; salted in-memory hash). First and last commit in the report.
3. **P3, context-aware counting:** show `test-path` / `docs-path` findings separately in the
   summary. An explicit gate option: `--gate-scope production`. Findings stay in the report.
4. **P4, user-approved baseline:** an acceptance file in the user's own directory, not in the
   target, with reasons and a signed digest. The gate applies it only as a separate count; the
   finding stays visible.
5. **Secret coverage:**
   - an additional Gitleaks rule pack (from the auditor's versioned rules, not from the target's
     config): `.netrc`, `.git-credentials`, credentials in URLs, PHP `define`, `.env`
     `*_PASSWORD`, bcrypt/shadow hashes;
   - re-measure with the same leaky-repo benchmark.
6. **Template XSS:** template-file analysis for Jinja `|safe` / `Markup` (Semgrep generic or own
   rule) as a separate stage.
7. **P5/P6 report fixes:** a separate `BINARY_NOT_SCANNED` reason for binary content; show the
   installed version for skipped pip-audit.
8. **P8:** normalise `MANIFEST.json` to LF in the working tree (`git add --renormalize`) and check
   before building.
9. **Second pilot (separate approval):**
   - PyGoat, DVPWA, Requests, Django (performance, 900 s limit);
   - optional OSV for R3 and pip-audit verification (approved package list only).

## 9. Laboratory and data status (at the time)

- The laboratory folder was **not deleted** (awaiting the owner's decision).
  - It contains the clones, publicly known fake secrets (leaky-repo) and deliberately
    vulnerable code.
  - Report and measurement files contain no secret values (§4).
- Sources: `sources\` (3 clones).
- Reports: `reports\` (9 run folders).
- Measurements: `measurements\`
  - `acquisition*.json`, `metrics.json`, `tcp_monitor.log`, `temp_before/after.json`,
    `project_before.txt`;
  - per repository: `scenarios.json`, `leak_check.json`, `relations_check.json`,
    `benchmark.json` (leaky-repo), guard logs, console outputs and integrity snapshots.
- Scripts: `scripts\`: `acquire.py`, `guard_run.py`, `snapshot.py`, `tcp_monitor.ps1`,
  `run_pilot.py`, `leak_check.py`, `metrics.py`, `relations_check.py`, `leaky_benchmark.py`,
  `context.py`, `author_hit.py`.
- Effects outside the pilot:
  - two small probe folders in the temporary working area: `glstdout_probe` (Gitleaks stdout
    probe) and `s311probe` (Ruff S311 probe), both containing only files written for the probe;
  - the guard self-test target was created and deleted.
- Project repository: only this document was added (not committed at the time). The 82 old
  folders, earlier laboratory data and the git history were unchanged.

## 10. Historical follow-up (added later; does not change the figures above)

The hardening rounds that followed this pilot (development commits `a440942` → `a86be96`) were
measured offline on the same three pinned clones. The current results are in
`MVP_VALIDATION.md`; this section only records what became of each pilot finding.

| Pilot finding | Outcome |
|---|---|
| P1 severity calibration | **Addressed (H5)** by verified cross-function SQL data flow: exactly the 3 exploitable Vulpy locations (`bad/libuser.py:12/25/53`) rose to HIGH for both Semgrep and Ruff (6 findings); the constant-seed and constant-call locations stayed MEDIUM; `--fail-on high` now fails on Vulpy (exit 4). No broad severity change was made. |
| P2 history noise | **Deferred (H7).** Raw per-blob findings are kept; summarisation is planned for a later release. |
| P3 context | **Partly addressed (H6):** every finding of every scanner carries a path-based `context` and test paths are tagged for all tools. Severity and the gate are unchanged; a gate scope option (H8) is deferred. |
| P4 accepted-risk baseline | **Deferred (H8).** |
| P5 binary formats | **Addressed (H2):** zip, gzip, PDF, 7-Zip, RAR, bzip2 and SQLite inputs are reported as skipped by the tool with the format named; coverage stays PARTIAL. |
| P6 pip-audit version | **Addressed (H3):** the pinned version is shown and the tool is marked "not run"; no process is started. |
| P7 stale-workspace warning | **Deferred (H11);** nothing is deleted automatically. |
| P8 reproducible build | **Addressed (H1):** every source and data file is stored with LF; wheels built from independent copies and from `git archive` are byte-identical. |
| Secret coverage (leaky-repo) | **Unchanged in 0.1.0** (14/42 files, ≤ 22/96 lines); additional rules (H10) deferred. |
| S101/S110 category (H4) | **Unchanged** by decision; a conditional S101 candidate was analysed but not applied. |

One further defect, **P9**, was found during release-candidate validation rather than in this
pilot: the identity (fingerprint) of a Gitleaks working-tree finding depended on the order in
which Gitleaks reported results, so finding ids could swap between runs when one file held
several findings. It was present in the pilot's own runs (3–5 findings differed between
scenarios in leaky-repo) and was fixed before the release (development commit `bd0e2bd`). The
fix changes every Gitleaks working-tree fingerprint once; counts, locations and severities are
unaffected. Details: `MVP_VALIDATION.md`, section "Finding identity stability (P9)".
