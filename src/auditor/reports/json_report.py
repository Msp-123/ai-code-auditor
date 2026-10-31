"""Machine-readable inventory report."""

from auditor.core.models import RepositoryInventory
from auditor.core.redaction import redact_inventory


def render_json(inventory: RepositoryInventory) -> str:
    return redact_inventory(inventory).model_dump_json(indent=2) + "\n"
