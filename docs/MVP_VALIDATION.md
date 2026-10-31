# AI Code Auditor 0.1.0 — validation report

This report describes how the released 0.1.0 build of AI Code Auditor was validated and what
was measured. It is evidence-based: every figure comes from a recorded run on the stated
environment, and every ratio keeps its own denominator. Nothing here generalises to all Python
projects; the accuracy measurements cover three public repositories, chosen for their
properties, scanned offline at pinned commits.

The initial pilot that preceded the hardening work is preserved unchanged as the historical
report `PILOT_01_VALIDATION.md`.

## 1. Executive summary

- **Safety invariants held in every run.** Across the pilot and its repetition with the
  hardened build (12 scans and 6 `report` commands on three repositories), the targets stayed
  byte-identical, no target code was imported, executed or compiled, no network connection was
  attempted, and no secret value, author name, e-mail address or absolute target path appeared
  in any report or console output.
- **Exploitable SQL injection is now HIGH where it can be proven.** The verified cross-function
  data-flow check (H5) raised exactly the three exploitable Vulpy locations from MEDIUM to HIGH
  for both Semgrep and Ruff (six findings). The `--fail-on high` quality gate, which Vulpy
  passed in the pilot, now fails with exit code 4. Raw finding counts did not change.
- **No new false HIGH findings elsewhere.** Flask kept its two by-design HIGH findings
  (`exec`/`eval`) and its 30 known false positives; leaky-repo kept its severities.
- **Secret coverage is limited and stated.** On the leaky-repo benchmark the default Gitleaks
  rule set reaches 14 of 42 risk files and at most 22 of 96 risk lines.
- **Finding identities are stable.** After the P9 fix, five offline scans of leaky-repo produced
  identical fingerprint sets (5/5); before the fix, 2–5 identities differed between runs.
- **The release package is reproducible and verified.** Two independent clean builds and a build
  from `git archive` produced byte-identical wheel and sdist files; a fresh offline environment
  installed the wheel with hash locking and passed the CLI, doctor, SQL-flow, gate and report
  smoke checks. The full test suite: 908 passed, 0 failed, 15 skipped.
- **Platform claim is narrow by design:** Windows 11 / CPython 3.12.10 only.

## 2. Tested version and environment

| Item | Value |
|---|---|
| Product | AI Code Auditor 0.1.0 (MVP) |
| Report schema | `ai-code-auditor/report` 1.1.0 (`schemas/report-v1.schema.json`); 1.0.0 runs are still readable by `auditor report` |
| Release source | Development commit `a86be96`; the public repository's initial commit (`9edd5c4c…`, tag `v0.1.0`) contains the same 156 files |
| Operating system | Windows 11 (10.0.26200) |
| Python | CPython 3.12.10; `requires-python >= 3.12` |
| Scanners | Ruff 0.17.3, Semgrep 1.182.1 (own ruleset 2026.10.1), Gitleaks 8.30.1 (pinned, SHA-256 verified), pip-audit 2.10.1, git 2.47 |
| Package | wheel SHA-256 `7f964c823532c7c4bb82de522fd88fcad920e584e32af42553050df1dfe848f7`; sdist SHA-256 `6b572c6b27505c0596e8adeb687ac11a48d5693352f26dada15c784027fb5bae` |

**Which build produced which measurement.** The accuracy measurements (§6–§8) were taken with
the hardened build (development commit `a440942`) during release-candidate validation and
re-confirmed after the P9 fix (`bd0e2bd`): raw findings, locations, severities, coverage, gate
results and relation groups were identical. The final package (`a86be96`) differs from that
tree only in licence files, package metadata, documentation and the `doctor` minimum Python
version; it was verified with the full test suite, the reproducibility check and the clean
offline smoke test (§12), not with a further scan of the three repositories.

## 3. Architecture and scanning capabilities

AI Code Auditor is a read-only, offline-by-default CLI. One `auditor scan` run performs:

1. **Discovery:** a read-only file inventory with link, junction and race (TOCTOU) checks,
   size and count limits, and path-based classification of every file.
2. **Ruff (code quality and Bandit-style security rules):** runs with the auditor's own
   configuration; the target's configuration, `# noqa` comments and caches are ignored.
3. **Semgrep (static security):** the auditor's own 14-rule set with two additional
   *evidence* rules that never produce findings, verified against a SHA-256 manifest on every
   run; a private copy of the target's Python files is scanned, so the target's Semgrep
   configuration has no effect.
4. **Gitleaks (secrets in the working tree):** one `stdin` scan per file with per-file coverage
   proof; secret values are never shown, stored or logged. Optionally (`--scan-git-history`)
   every reachable blob and commit message of the git history is extracted into a private
   workspace and scanned; git never runs on the target's `.git`.
5. **pip-audit (dependencies):** only with `--allow-network`; exactly pinned versions from
   `requirements*.txt` and `pylock.toml` are sent to OSV. Without permission the area is
   reported as `NOT_PERMITTED` and the scan is PARTIAL.
6. **Report:** one canonical `report.json` (schema 1.1.0) with coverage per area, outcome by
   severity and by file context, a quality gate, finding relations (same location, same
   content in history, same vulnerability) and an integrity record; `report.md` and the
   terminal summary are rendered from it.

Every scanner reports `SUCCESS`, `SKIPPED`, `ERROR` or `TIMED_OUT`, and coverage is tracked per
file and per area. Every scanner finding is `NEEDS_REVIEW`; the auditor never marks a finding
as confirmed.

## 4. Validation methodology

The validation consisted of three stages on the same three pinned clones:

| Stage | Build | Purpose |
|---|---|---|
| Pilot 01 (2026-10-30) | first 0.1.0 build, schema 1.0.0 | Baseline for safety, privacy, accuracy and report quality; produced findings P1–P8 (`PILOT_01_VALIDATION.md`) |
| Hardening rounds 1–2 and release-candidate validation (2026-10-31) | hardened build `a440942`, schema 1.1.0 | Re-measure every scenario, verify that only the intended findings changed, document remaining limits; found P9 |
| P9 fix and release preparation (2026-10-31) | `bd0e2bd` → `a86be96` | Fingerprint stability, full regression, reproducible packaging, clean offline installation |

**Scenarios per repository:** `s1` default offline scan, `s2` `--scan-git-history`, `s3`
`--fail-on high`, `s4` `auditor report <RUN_ID>` on the s1 run.

**Observation tools** (the same in the pilot and its repetition):

- **Integrity snapshots:** SHA-256, size and mtime of every file of the target including
  `.git`, before and after every scan, without following links.
- **In-process guard:** a Python audit hook under which the CLI ran; it recorded every child
  process, every DNS or socket attempt (non-loopback denied), every write under the target and
  every import, exec or compile from the target (denied). It was self-tested first.
- **TCP monitor:** polled the auditor, tool and git processes for non-loopback connections
  (pilot: 524 polls; repetition: 482 polls).
- **Leak check:** secret values obtained from direct Gitleaks runs were kept in memory only
  and searched for in every report and console output (full value, middle 12 characters of
  values ≥ 20 characters, author and committer names and e-mails, absolute paths); only counts
  were recorded.
- **Accuracy:** findings in Vulpy and Flask were classified manually by reading the code (as
  data; nothing executed); leaky-repo was compared with its own `secrets.csv` benchmark;
  relation groups were verified by recomputing blob ids.

**Limits of the method:** the guard sees only the auditor's own process (child processes are
covered by the snapshots and the TCP monitor); the TCP monitor polls and could miss very short
connections; three repositories and manual classification are a small sample.

## 5. Benchmark repositories

| Repository | Commit | Why it was chosen | Size |
|---|---|---|---|
| `fportantier/vulpy` | `5249cc8b05a1c37f6b2f757b1cf16a509c327122` | Deliberately vulnerable Flask application (`bad/`) with a hardened twin (`good/`): known SQL injections, `debug=True`, hard-coded secrets, shared `/tmp` files | 113 tracked files, 58 commits |
| `Plazmaz/leaky-repo` | `2e951359cac53addbee56437da3ffb546e3dfe24` | Public fake-secret benchmark with a ground-truth file (`.leaky-meta/secrets.csv`, 44 files, 96 risk lines) | 61 tracked files, 26 commits |
| `pallets/flask` | `d086db856be187255b8ec61ef409357393020f32` | Mature real-world project: false-positive rate, performance, a long git history (since 2010) | 236 tracked files, 5603 commits, 26 390 objects |

The clones were obtained once over `https://github.com` with an isolated git configuration (no
hooks, no submodules, no LFS, `transfer.fsckObjects=true`); nothing from the repositories was
ever executed. All later measurements were offline.

## 6. Detection accuracy

The ratios below have different numerators, denominators and units and must not be compared with
each other or extrapolated.

### 6.1 Vulpy

- **Recall on supported classes:** 9 of 9 vulnerabilities verified by reading `bad/` and
  within the reach of the existing rules were detected (pilot; unchanged by hardening). This
  denominator is tiny and excludes unsupported classes such as template XSS, session forgery
  and weak randomness (listed in `PILOT_01_VALIDATION.md` §6).
- **Precision:** 51 of 59 security findings were true findings in the pilot (7 false positives,
  1 uncertain); a deliberately vulnerable repository does not represent real-world precision.
- **Severity after hardening (release-candidate measurement):**

| Location | Tools | Pilot | 0.1.0 | Evidence recorded in the finding |
|---|---|---|---|---|
| `bad/libuser.py:12` (login) | Semgrep `formatted-sql-query` + Ruff `S608` | MEDIUM | **HIGH** | `bad/mod_user.py:20 request data -> login(username/password) -> bad/libuser.py:12 SQL text` |
| `bad/libuser.py:25` (create) | Semgrep + Ruff | MEDIUM | **HIGH** | `bad/mod_user.py:52 request data -> create(username/password) -> …:25` |
| `bad/libuser.py:53` (password change) | Semgrep + Ruff | MEDIUM | **HIGH** | `bad/mod_user.py:80 request data -> password_change(password) -> …:53` |
| `bad/db.py:19`, `bad/db_init.py:20` (constant seed data) | Semgrep + Ruff | MEDIUM | MEDIUM | none (not exploitable) |
| `good/libuser.py:61` (called with constants only) | Semgrep + Ruff | MEDIUM | MEDIUM | none |

  Six findings changed severity (3 locations × 2 tools); no other severity changed; all stay
  `NEEDS_REVIEW`. Raw findings: 123 (s1) and 127 (s2) in both the pilot and 0.1.0; fingerprint
  sets identical. **Quality gate:** `--fail-on high` went from PASSED (exit 3, partial coverage
  only) to **FAILED with 6 counted findings (exit 4)**.

### 6.2 Flask

- **No new HIGH findings.** HIGH stayed at 2 (`S102` in `config.py`, `S307` in `cli.py`, both
  by-design `exec`/`eval`); no severity changed; 51 (s1) and 275 (s2) raw findings, identical
  fingerprint sets.
- **False positives persist as documented:** of the 34 security-category findings, 30 remain
  false positives (test fixtures 17, documentation examples 6, `assert` and other production
  code 7). They now carry a path-based context: for all 51 findings, test 25, production 17,
  docs 6, examples 3; for the 34 security-category findings, test 17, production 10, docs 6,
  examples 1. Context does not change severity or the gate in 0.1.0 (gate scope is a deferred
  feature).
- **Git history repetition remains a known limitation:** the history scan reports 224 findings
  for at most 2 distinct documentation values (68 blobs, 2 paths); the R2 relation links only
  the 6 that share the identical blob with the working tree.

### 6.3 leaky-repo

| Metric | Value | Denominator |
|---|---|---|
| Risk files with at least one finding | **14 / 42** | files listed with risk lines in `secrets.csv` |
| Risk lines matched | **≤ 22 / 96** (upper bound) | risk lines; the benchmark gives no line numbers, so a matched line may be informational |
| Working-tree findings | 22 | identical to a direct `gitleaks dir` run at the (path, line, rule) level |
| Severities | CRITICAL 2 (private keys), HIGH 2, MEDIUM 20, LOW 4 | unchanged since the pilot |
| Not analysed | 2 Firefox NSS databases (`cert9.db`, `key4.db`) | reported as skipped by the tool (SQLite format), coverage PARTIAL |

Missed classes are a limit of the default Gitleaks rule set, not of the adapter: password
hashes (`dump.sql`, `shadow`, `.htpasswd`), low-entropy passwords in PHP/`.env`/XML
configuration, `.netrc`/`.pgpass`/`.git-credentials`, encrypted browser credentials, PuTTY and
Rails key files. Additional rules are deferred to a later release.

## 7. Verified SQL injection data flow (H5)

Semgrep CE taint tracking stays inside one function, so `view (request data) -> helper
(formatted SQL)` can only ever be a pattern finding (`formatted-sql-query`, MEDIUM: the source
is unknown). In 0.1.0 two Semgrep *evidence* rules record where a function parameter reaches
SQL text and where request data reaches a call argument. These observations are never findings
and never count. The auditor joins them with a static, execution-free `ast` analysis of the
target's own files: exact import binding, one module file, exactly one function definition,
positional or keyword argument to parameter, parameter to SQL text through at most three local
assignments, no `int()`/`float()` conversion. Only a fully resolved chain raises the existing
`formatted-sql-query` / `S608` finding at that line to HIGH, adds the chain as location-only
evidence and tags it `verified-data-flow`; the status stays `NEEDS_REVIEW`.

**Measured:** Vulpy exactly 3 of 6 `formatted-sql-query` locations verified (above); Flask 0
sinks; the auditor's own repository 0 verifications (its 8 deliberately vulnerable Semgrep
fixtures stayed MEDIUM). Negative cases are covered by tests: import aliases and wrong
modules, two same-named functions, `*args`/`**kwargs`, `getattr` and dynamic imports, constant
arguments, request data reaching only another parameter, `int()` sanitisation, parameterised
queries (no finding at all). Evidence text is sanitised (normalised `path:line` and identifier
names only; no raw control characters in JSON, Markdown or terminal output), verified with
hostile directory names.

**Cost in the product pipeline** (same machine, five alternating runs, Semgrep time, median):
Vulpy 4.56 s → 4.56 s, Flask 4.91 s → 5.14 s, own repository 5.03 s → 5.42 s; the difference is
within the machine's noise (single 7–8 s outliers appeared in both variants).

## 8. Finding identity stability (P9)

Release-candidate validation found that the fingerprint of a Gitleaks working-tree finding
included the position of the result in Gitleaks' per-file output, which is not stable between
runs. When one file held several findings (leaky-repo `.bash_profile`, `.bashrc`), finding ids
swapped between runs: 2–5 identities differed between otherwise identical scans, and the
pilot's own scenarios had shown 3–5 differences. Locations, rules, severities and counts were
never affected.

**Fix (0.1.0):** the identity is now tool, rule, path, line and the match's start and end
columns, processed in position order; exact duplicates at the same position are numbered and
tagged `duplicate-match`. Secret values and anything derived from them never enter the
fingerprint. **Measured:** five offline Gitleaks scans of leaky-repo produced identical
fingerprint and finding-id sets (5/5; 22 findings, 0 exact duplicates); a repetition of all nine
scenarios on the three repositories matched the release-candidate results in raw findings,
locations, severities, coverage, gate and group counts, with only the Gitleaks working-tree
fingerprints changed (Vulpy 1, leaky-repo 22, Flask 6 — all of them, once, by design).

**Compatibility:** Gitleaks working-tree finding ids and fingerprints in reports written before
the fix do not match those of 0.1.0 and no mapping table exists. Because the identity is
location-only, a secret whose content changes at the same rule, line and columns keeps its
identity; exact duplicates are distinguished only by their number and are tagged for that
reason. Git-history finding identities (object-id based) did not change.

## 9. Security and privacy guarantees

What was verified, and how:

| Guarantee | Evidence |
|---|---|
| The target is never modified | Integrity snapshots identical before and after 9 pilot scans, 12 repetition scans and all `report` commands, for all three repositories |
| Target code is never executed, imported or compiled | Guard: 0 import/exec/compile from the target; only four trusted executables were started (git, ruff, gitleaks, semgrep), none with a working directory inside the target |
| Offline by default | Guard: 0 DNS/socket attempts; TCP monitor: 0 non-loopback connections (524 + 482 polls); pip-audit is not started without `--allow-network` and is reported as `SKIPPED (version 2.10.1, not run)` |
| Secret values never reach any output | Leak check against values from direct Gitleaks runs: 0 full-value and 0 middle-fragment matches in all reports and console outputs; 182 benchmark tokens searched in leaky-repo, 0 matched |
| No personal or environment data in reports | 0 author/committer names or e-mails (1741 searched in Flask), 0 absolute paths; the two apparent name hits were the dictionary words "root" and "unknown" |
| The target cannot influence the scanners | Target Ruff/Semgrep/Gitleaks configurations, ignore files and inline suppressions have no effect (tested); git never runs on the target's `.git` and unsafe repository layouts are refused |
| Errors are never shown as clean results | Every object that could not be analysed produced PARTIAL coverage with a reason; `TIMED_OUT`, `ERROR` and `CLEANUP_FAILED` never occurred |
| Reports are tamper-evident, not signed | `SHA256SUMS.json` per run; `auditor report` refuses runs whose record is missing or does not match |
| Clean environment | Fresh venv, hash-locked offline install of the release wheel: installed files identical to the wheel; no absolute target path or user-home fragment in the produced reports |

The repository's own test suite enforces these properties (read-only invariant, privacy and
redaction, report injection, link handling, Unicode safety, workspace cleanup). The repository
also contains deliberately vulnerable synthetic fixtures and fake secrets for those tests; a
Gitleaks scan of the repository reports exactly two `generic-api-key` findings that are
fragmented fake literals, not credentials.

## 10. Performance and coverage

**Wall-clock times (Pilot 01, first 0.1.0 build; the hardened build adds ≤ 0.4 s of Semgrep
time, §7):**

| Repository | Default scan (s1) | With git history (s2) | History scan portion |
|---|---|---|---|
| vulpy | 19.5 s | 18.3 s | 1.5 s (313/319 objects) |
| leaky-repo | 13.9 s | 13.1 s | 2.0 s (153/155 objects) |
| flask | 30.6 s | 59.0 s | 27.2 s (14 918/14 921 objects) |

`auditor report` took 0.3–0.4 s and started no process. Earlier development measurements:
20 000 commits / 80 000 objects in 136 s for the history scan.

**Coverage outcomes (identical in the pilot and the hardened build):**

- All 9 scenario scans were **PARTIAL**, each for a stated reason: the dependency area is
  `NOT_PERMITTED` without `--allow-network` (Vulpy 1 manifest, Flask 6 manifests); leaky-repo
  has 2 binary NSS databases that Gitleaks does not scan; the histories contain binary or
  archive objects (Vulpy 5 SQLite objects and 1 object over 10 MiB; Flask 2 PDFs and 1 `.egg`).
- Working-tree coverage was otherwise complete: Vulpy 57/57 Python files for Ruff and Semgrep
  and 113/113 files for Gitleaks; Flask 83/83 and 236/236; leaky-repo 2/2 and 58/60.
- Dependency analysis without network permission is reported as not checked and makes the scan
  PARTIAL (exit 3); this is expected behaviour, not a defect.

## 11. Known limitations

- **Accuracy figures are specific to three repositories.** Vulpy's 9 verified vulnerabilities
  are too few to support a recall claim; Flask's false-positive rate and leaky-repo's recall
  describe those repositories only.
- **False positives in real-world code:** on Flask 30 of 34 security-category findings are
  false positives (test fixtures, documentation examples, developer asserts). The path-based
  `context` field helps triage but does not change severity or the gate; a gate scope option
  and S101/S110 recalibration are deferred.
- **Secret recall is limited by the default Gitleaks rules:** 14/42 files and ≤ 22/96 lines on
  leaky-repo; low-entropy passwords, hashes and many configuration-file credentials are missed.
  Gitleaks also skips binary formats (zip, gzip, PDF, 7-Zip, RAR, bzip2, SQLite); they are
  reported as skipped and make coverage PARTIAL.
- **Git-history noise:** one raw finding per blob version that contains a value (Flask: 224
  findings for ≤ 2 values). Reflogs, dangling objects, submodules, linked worktrees and tag
  messages are not scanned.
- **Verified SQL flow covers one shape only:** exact import binding, one module file, one
  function definition, plain positional or keyword arguments, Flask/Django request objects. Any
  other flow stays MEDIUM; cross-function flows for other sinks are not verified.
- **Context is path-based, not a security proof:** production code placed under `tests/` is
  classified as test.
- **Dependencies:** only exactly pinned versions in `requirements*.txt` and `pylock.toml` are
  audited; `poetry.lock`, `uv.lock`, `Pipfile.lock` and `setup.py` are not analysed; OSV results
  are not a guarantee; with `--allow-network`, package names (including private ones) are sent
  to `api.osv.dev`.
- **Coverage is not a verdict:** `COMPLETE` / exit 0 means the requested areas were fully
  scanned, not that the project is safe. The integrity record is not a signature.
- **Finding identities are location-based** (line and column); there is no tracking across
  runs, and pre-fix Gitleaks identities cannot be mapped to 0.1.0 identities.
- **Platform:** verified on Windows 11 / CPython 3.12.10 only. 15 tests are skipped on this
  platform (7 need symlink privileges, 6 are POSIX-specific, 2 need network opt-in); Python
  3.11, Linux and macOS were not tested and are not claimed.
- **Residual races:** a small Windows race window remains in the output-directory checks; stale
  workspaces and incomplete report directories are reported, never deleted automatically.

## 12. Test and release readiness summary

| Check | Result |
|---|---|
| Full test suite (release package `a86be96`) | **908 passed, 0 failed, 15 skipped** (skips: 7 symlink privilege, 6 POSIX-only, 2 network opt-in); also 908 passed from inside the public source snapshot |
| Ruff | `ruff check .` clean; `ruff format --check .` clean (target `py312`) |
| Semgrep ruleset manifest | 2026.10.1 verified on every run (`doctor` and scan) |
| Reproducible packaging | Two independent clean copies and `git archive` → identical wheel (`7f964c82…`) and sdist (`6b572c6b…`); wheel package files byte-identical to the source; licence files inside both packages |
| Clean offline installation | Fresh venv (CPython 3.12.10), `pip --no-index --require-hashes`; installed files identical to the wheel; `--version` 0.1.0; `doctor` exit 0 |
| Smoke scan (synthetic SQL-flow target, real Semgrep + Ruff) | 6 findings; the request → call → parameter → SQL chain HIGH for both tools with `verified-data-flow`; constant-data and `int()` cases MEDIUM; parameterised query no finding; all `NEEDS_REVIEW`; `--fail-on high` exit 4 (2 counted); `auditor report` identical JSON, no rescan; target unchanged; no path leaks |
| Package metadata | `License-Expression: Apache-2.0 AND MIT` (project Apache-2.0 plus four MIT-licensed Gitleaks rule copies), `Requires-Python: >=3.12`, no author or URL invented |
| Intermittent test | `test_results_do_not_depend_on_the_worker_count` failed once under heavy concurrent load in an earlier run and passed in every subsequent full run; it is tracked, not hidden |

Release readiness: the 0.1.0 package is fit for release on the verified platform with the
limitations above stated alongside it. Dependency analysis remains PARTIAL without explicit
network permission, which is the intended default.
