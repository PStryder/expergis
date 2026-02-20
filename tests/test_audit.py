"""Tests for expergis.audit — JSONL audit logging."""

import json

from expergis.audit import audit_log


class TestAuditLog:
    def test_audit_writes_jsonl(self, tmp_path):
        """Verify audit entry written with timestamp."""
        audit_file = tmp_path / "test_audit.jsonl"
        entry = {"action": "dispatch", "watcher_id": "w1", "event_type": "modified"}
        audit_log(entry, audit_path=audit_file)

        lines = audit_file.read_text().strip().splitlines()
        assert len(lines) == 1
        data = json.loads(lines[0])
        assert data["action"] == "dispatch"
        assert data["watcher_id"] == "w1"
        assert "timestamp" in data
