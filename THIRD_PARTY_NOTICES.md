# Third-party notices

AI Code Auditor itself is licensed under the Apache License, Version 2.0 (see `LICENSE`).
Because the published packages also contain the MIT-licensed material listed below, the
package metadata declares the SPDX expression `Apache-2.0 AND MIT` for the distribution as a
whole; this does not change the project's licence or the original copyright notices.
This file lists third-party material that is **contained in the published source and
packages**, with its own licence terms. Tools that the auditor only *runs* (Semgrep, Gitleaks,
Ruff, pip-audit) and the Python packages it *depends on* are not distributed with it and are
not covered here, except where their content was copied.

## 1. Gitleaks default rules (copied, modified) — MIT License

- **Project:** Gitleaks — https://github.com/gitleaks/gitleaks
- **Version:** 8.30.1 (the release pinned by the auditor; rules are embedded in the binary's
  default configuration `config/gitleaks.toml`)
- **Files in this repository that contain copied material:**
  - `src/auditor/rules/gitleaks/path-freemius-secret-key.toml` (rule `freemius-secret-key`)
  - `src/auditor/rules/gitleaks/path-hashicorp-tf-password.toml` (rule `hashicorp-tf-password`)
  - `src/auditor/rules/gitleaks/path-kubernetes-secret-yaml.toml` (rule `kubernetes-secret-yaml`)
  - `src/auditor/rules/gitleaks/path-nuget-config-password.toml` (rule `nuget-config-password`)
- **What was copied and how it was modified:** each file contains one rule copied verbatim
  from the Gitleaks 8.30.1 default configuration (id, description, regex, keywords and the
  rule-level allowlists). Two changes were made: the rule id was prefixed with
  `auditor-pathless-`, and the rule's `path` condition was removed, because the auditor feeds
  files to Gitleaks on standard input where path conditions cannot apply (the auditor applies
  the original path condition itself). A test compares each copy against the rule embedded in
  the pinned binary. `src/auditor/rules/gitleaks/gitleaks.toml` contains no copied rules; it
  only enables the default rule set (`useDefault = true`).
- **Licence text** (from the `LICENSE` file shipped in the Gitleaks 8.30.1 release archive
  `gitleaks_8.30.1_windows_x64.zip`; SHA-256 of that file: `e3884b252b3bfc045e55be43a34d1e80da070bc6f804ac95bf4660e97d62ebc6`):

```text
MIT License

Copyright (c) 2019 Zachary Rice

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## 2. Licence inventory of the published files

| Content | Origin | Licence |
|---|---|---|
| `src/auditor/**` (Python code), `schemas/`, `tests/**`, documentation | written for this project | Apache-2.0 (`LICENSE`) |
| `src/auditor/rules/semgrep/*.yaml` (16 rules) and `MANIFEST.json` | written for this project; not taken from the Semgrep Registry | Apache-2.0 |
| `src/auditor/rules/gitleaks/path-*.toml` (4 files) | copied from Gitleaks 8.30.1 default rules, modified as described above | MIT (section 1) |
| `src/auditor/rules/gitleaks/gitleaks.toml` | written for this project (enables Gitleaks defaults by reference only) | Apache-2.0 |
| `tests/fixtures/semgrep_rules/*.py` | synthetic, deliberately vulnerable code written for the rule tests; uses the Flask/Django request APIs by name only, no third-party code copied | Apache-2.0 |
| Fake secrets in tests | generated at run time (`FakeSecrets`); two deliberately fragmented literal placeholders in `tests/security/test_ruff_security.py` and `tests/security/test_semgrep_security.py` | Apache-2.0; not real credentials |
| `tools/*.lock.txt` | package names, versions and SHA-256 hashes for the separate tool environments | Apache-2.0 (the listed packages are not distributed) |

## 3. Tools and dependencies that are not distributed

The auditor runs Semgrep Community Edition (LGPL-2.1) and Gitleaks (MIT) from separate tool
environments that the user installs, and depends on Ruff, Typer, Pydantic and Rich (MIT) from
PyPI. None of their code is included in this repository or in the wheel.
