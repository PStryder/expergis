"""Deny real HTTP by default; the sole integration escape targets a test loopback port."""
import aiohttp
import pytest

_ORIGINAL_SESSION = aiohttp.ClientSession


@pytest.fixture(autouse=True)
def isolate_runtime(monkeypatch, tmp_path):
    from expergis import audit
    def forbidden(*args, **kwargs):
        raise AssertionError("Real HTTP session forbidden in unit tests")
    monkeypatch.setattr(aiohttp, "ClientSession", forbidden)
    monkeypatch.setattr(audit, "AUDIT_FILE", tmp_path / "audit.jsonl")


@pytest.fixture
def loopback_client():
    async def post(port, body, headers):
        assert type(port) is int and 1024 <= port <= 65535
        async with _ORIGINAL_SESSION(trust_env=False, timeout=aiohttp.ClientTimeout(total=5)) as session:
            async with session.post(f"http://127.0.0.1:{port}/callback", data=body,
                                    headers=headers, allow_redirects=False) as response:
                return response.status, await response.content.read(4097)
    return post
