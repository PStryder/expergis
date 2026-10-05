"""JSONL audit trail for Expergis events."""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("expergis.audit")

AUDIT_FILE = Path("expergis_audit.jsonl")
MAX_AUDIT_BYTES = 1024 * 1024


def audit_log(entry: dict, audit_path: Path | None = None) -> None:
    """Append an audit entry to the JSONL log."""
    path = audit_path or AUDIT_FILE
    entry["timestamp"] = datetime.now(timezone.utc).isoformat()
    try:
        record = json.dumps(entry, allow_nan=False) + "\n"
        if len(record.encode("utf-8")) > 16384:
            logger.warning("Audit record exceeds size limit")
            return
        if path.exists() and path.stat().st_size + len(record.encode("utf-8")) > MAX_AUDIT_BYTES:
            path.replace(path.with_name(path.name + ".1"))
        with open(path, "a", encoding="utf-8") as f:
            f.write(record)
    except (OSError, ValueError, TypeError) as e:
        logger.warning("Audit write failed: %s", type(e).__name__)
