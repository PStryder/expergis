"""Tests must never create a real outbound HTTP session or write live audit data."""
import pytest


@pytest.fixture(autouse=True)
def isolate_runtime(monkeypatch, tmp_path):
    import aiohttp
    from expergis import audit

    def forbidden(*args, **kwargs):
        raise AssertionError("Real HTTP session forbidden in unit tests")

    monkeypatch.setattr(aiohttp, "ClientSession", forbidden)
    monkeypatch.setattr(audit, "AUDIT_FILE", tmp_path / "audit.jsonl")
