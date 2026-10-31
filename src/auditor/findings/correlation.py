"""Finding relations R1-R3 (Stage 6, D-048): related, never merged, never removed.

- R1 ``same_location``: security findings of *different* working-tree scanners whose line
  ranges contain the same line of the same file. Location only: two tools can describe two
  different problems on one line, so no common root cause is claimed.
- R2 ``same_content_in_history``: a git-history finding and a working-tree Gitleaks finding with
  the same rule and line, at a path where the history object was verified, and whose analysed
  working-tree bytes have exactly that git blob id (same object format). Anything less, e.g.
  different line endings, gives no relation.
- R3 ``same_vulnerability``: pip-audit findings for the same package and version that share a
  validated vulnerability id or alias.

Groups do not chain: every group is built around one anchor (a line, a history finding, an
id). Identical member sets are reported once. Group ids derive from the relation and the
members' fingerprints, so they are stable across runs.
"""

import hashlib
from collections.abc import Sequence

from auditor.core.audit_report import FindingGroup, RelationType
from auditor.core.models import Finding, FindingCategory

WORKING_TREE_TOOLS = frozenset({"ruff", "semgrep", "gitleaks"})
STATEMENTS = {
    RelationType.SAME_LOCATION: "Reported at the same location by different tools. Related by "
    "location only: this is not the same root cause, and both findings stay separate.",
    RelationType.SAME_CONTENT_IN_HISTORY: "The working-tree file is the identical git object "
    "that git history holds at this path, and the same rule matched on the same line. Both "
    "findings stay separate: the value must be rotated, and it also remains in history.",
    RelationType.SAME_VULNERABILITY: "The same package version is affected by the same "
    "vulnerability (shared id or alias), reported from more than one manifest or entry.",
}


def _lines(finding: Finding) -> range:
    start = finding.start_line or 0
    return range(start, max(start, finding.end_line or start) + 1)


def _same_location(findings: Sequence[Finding]) -> list[tuple[dict, list[Finding]]]:
    eligible = [f for f in findings if f.source_tool in WORKING_TREE_TOOLS
                and f.category is FindingCategory.SECURITY and f.start_line]  # fmt: skip
    by_path: dict[str, list[Finding]] = {}
    for finding in eligible:
        by_path.setdefault(finding.relative_path, []).append(finding)
    out = []
    for path, group in sorted(by_path.items()):
        for anchor in sorted({f.start_line for f in group}):
            members = [f for f in group if anchor in _lines(f)]
            tools = sorted({f.source_tool for f in members})
            if len(tools) > 1:
                out.append(({"path": path, "line": anchor, "tools": tools}, members))
    return out


def _same_content(findings: Sequence[Finding]) -> list[tuple[dict, list[Finding]]]:
    tree = [f for f in findings if f.source_tool == "gitleaks" and f.content_ids]
    out = []
    for h in findings:
        ids = h.identifiers
        if h.source_tool != "gitleaks-history" or not ids.git_object or not ids.object_format:
            continue
        matches = [
            t for t in tree
            if t.relative_path in ids.history_paths and t.rule_id == h.rule_id
            and t.start_line == h.start_line
            and t.content_ids.get(ids.object_format) == ids.git_object
        ]  # fmt: skip
        if not matches:
            continue
        twins = [o for o in findings if o.source_tool == "gitleaks-history"
                 and o.identifiers.git_object == ids.git_object and o.rule_id == h.rule_id
                 and o.start_line == h.start_line]  # fmt: skip
        for path in sorted({t.relative_path for t in matches}):
            basis = {"path": path, "rule": h.rule_id, "line": h.start_line,
                     "content": "identical git blob"}  # fmt: skip
            out.append((basis, [*twins, *(t for t in matches if t.relative_path == path)]))
    return out


def _same_vulnerability(findings: Sequence[Finding]) -> list[tuple[dict, list[Finding]]]:
    deps = [f for f in findings if f.source_tool == "pip-audit" and f.identifiers.package
            and f.identifiers.version and f.identifiers.vulnerability_ids]  # fmt: skip
    keys: dict[tuple[str, str, str], list[Finding]] = {}
    for finding in deps:
        ids = finding.identifiers
        for vuln_id in set(ids.vulnerability_ids):
            keys.setdefault((ids.package, ids.version, vuln_id), []).append(finding)
    by_members: dict[tuple[str, ...], tuple[str, str, set[str], list[Finding]]] = {}
    for (package, version, vuln_id), members in sorted(keys.items()):
        if len(members) < 2:
            continue
        member_key = tuple(sorted(m.fingerprint for m in members))
        entry = by_members.setdefault(member_key, (package, version, set(), members))
        entry[2].add(vuln_id)
    return [({"package": p, "version": v, "ids": sorted(ids)}, members)
            for p, v, ids, members in by_members.values()]  # fmt: skip


def _group_id(relation: RelationType, members: Sequence[Finding]) -> str:
    key = "\x1f".join([relation.value, *sorted({m.fingerprint for m in members})])
    return "grp-" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def relate(findings: Sequence[Finding]) -> tuple[list[Finding], list[FindingGroup]]:
    """(the same findings in the same order with ``group_ids`` set, the groups)."""
    groups: dict[str, FindingGroup] = {}
    for relation, builder in ((RelationType.SAME_LOCATION, _same_location),
                              (RelationType.SAME_CONTENT_IN_HISTORY, _same_content),
                              (RelationType.SAME_VULNERABILITY, _same_vulnerability)):  # fmt: skip
        for basis, members in builder(findings):
            unique = {m.finding_id: m for m in members}
            if len(unique) < 2:
                continue
            group_id = _group_id(relation, list(unique.values()))
            groups.setdefault(group_id, FindingGroup(
                group_id=group_id, relation=relation, basis=basis,
                finding_ids=sorted(unique), statement=STATEMENTS[relation]))  # fmt: skip
    ordered = sorted(groups.values(), key=lambda g: (g.relation.value, g.group_id))
    memberships: dict[str, list[str]] = {}
    for group in ordered:
        for finding_id in group.finding_ids:
            memberships.setdefault(finding_id, []).append(group.group_id)
    related = [f.model_copy(update={"group_ids": memberships.get(f.finding_id, [])})
               for f in findings]  # fmt: skip
    return related, ordered
