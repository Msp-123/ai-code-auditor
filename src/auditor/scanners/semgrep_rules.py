"""The auditor's own, versioned Semgrep ruleset.

Rules are loaded only from the installed ``auditor`` package (never from the target, never
from the Semgrep Registry). ``MANIFEST.json`` lists every rule file with its SHA-256.

What the manifest does and does not protect against (D-037):

- It detects accidental corruption, partial updates and rule files being added, removed or
  edited without a deliberate manifest update. It also pins *which* bytes were scanned: the
  verified bytes are copied into the private workspace and Semgrep reads only that copy, so
  the files cannot be swapped between verification and use.
- It is NOT a defence against a malicious actor who can write to the installed package: such
  an actor can rewrite the manifest (or the auditor's code) as well. Protecting the
  installation itself is the job of the environment (file permissions, signed releases).

Regenerate after editing a rule:  python -m auditor.scanners.semgrep_rules <version>
"""

import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path

from auditor.core.safe_fs import PRIVATE_DIR_MODE, create_private_file

RULES_DIR = Path(__file__).resolve().parent.parent / "rules" / "semgrep"
MANIFEST_NAME = "MANIFEST.json"


class RulesetError(Exception):
    """The ruleset is missing, incomplete or does not match its manifest."""


@dataclass(frozen=True)
class Ruleset:
    version: str
    digest: str  # SHA-256 over all (name, file hash) pairs
    files: dict[str, bytes]


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _combined(hashes: dict[str, str]) -> str:
    joined = "\n".join(f"{name}:{hashes[name]}" for name in sorted(hashes))
    return _sha256(joined.encode("utf-8"))


def build_manifest(rules_dir: Path, version: str) -> dict:
    hashes = {p.name: _sha256(p.read_bytes()) for p in sorted(rules_dir.glob("*.yaml"))}
    return {"ruleset_version": version, "files": hashes}


def load_ruleset(rules_dir: Path = RULES_DIR) -> Ruleset:
    manifest_path = rules_dir / MANIFEST_NAME
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        expected: dict[str, str] = dict(manifest["files"])
        version = str(manifest["ruleset_version"])
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise RulesetError(f"{MANIFEST_NAME} is missing or invalid") from exc

    present = {p.name for p in rules_dir.glob("*.yaml")}
    unexpected = sorted(present - set(expected))
    missing = sorted(set(expected) - present)
    if unexpected:
        raise RulesetError(f"rule file(s) not listed in the manifest: {', '.join(unexpected)}")
    if missing:
        raise RulesetError(f"rule file(s) listed in the manifest are missing: {', '.join(missing)}")

    files: dict[str, bytes] = {}
    for name in sorted(expected):
        content = (rules_dir / name).read_bytes()
        if _sha256(content) != expected[name]:
            raise RulesetError(f"rule file does not match its manifest hash: {name}")
        files[name] = content
    return Ruleset(version=version, digest=_combined(expected), files=files)


def materialize(ruleset: Ruleset, workspace: Path) -> Path:
    """Write the verified bytes into a private directory that Semgrep will read."""
    directory = workspace / "rules"
    workspace.mkdir(parents=True, exist_ok=True)
    directory.mkdir(mode=PRIVATE_DIR_MODE)
    for name, content in ruleset.files.items():
        create_private_file(directory / name, content.decode("utf-8"))
    return directory


if __name__ == "__main__":  # developer helper: regenerate MANIFEST.json
    new_version = sys.argv[1] if len(sys.argv) > 1 else "dev"
    (RULES_DIR / MANIFEST_NAME).write_text(
        json.dumps(build_manifest(RULES_DIR, new_version), indent=2) + "\n", encoding="utf-8"
    )
    print(f"wrote {RULES_DIR / MANIFEST_NAME} (ruleset_version={new_version})")
