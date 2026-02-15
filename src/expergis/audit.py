"""JSONL audit trail for Expergis events."""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("expergis.audit")

AUDIT_FILE = Path("expergis_audit.jsonl")


def audit_log(entry: dict, audit_path: Path | None = None) -> None:
    """Append an audit entry to the JSONL log."""
    path = audit_path or AUDIT_FILE
    entry["timestamp"] = datetime.now(timezone.utc).isoformat()
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError as e:
        logger.warning(f"Failed to write audit log: {e}")
