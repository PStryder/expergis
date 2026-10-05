import asyncio
import base64
import hashlib
import hmac
import json
import os
import socket
from dataclasses import replace

import pytest

from expergis.event_service import EventService
from expergis.event_store import EventStore
from expergis.events_security import (WebhookSender, CallbackError, PublicResolver,
    json_bytes, signed_headers, signing_key, validate_url)
from expergis.plugins.base import Event

SECRET = "whsec_" + base64.b64encode(b"synthetic-test-material-only-12345").decode()


class TestProtector:
    __test__ = False
    # Test-only reversible encoding, never a deployment protector.
    def seal(self, value):
        return base64.b64encode(value)

    def open(self, value):
        return base64.b64decode(value)


class Receiver(WebhookSender):
    def __init__(self):
        self.messages = []
        self.status = 202
        self.challenge_ok = True
        self.secret = SECRET

    async def post(self, url, body, headers):
        message = headers["webhook-id"].encode() + b"." + headers["webhook-timestamp"].encode() + b"." + body
        expected = "v1," + base64.b64encode(hmac.new(signing_key(self.secret), message, hashlib.sha256).digest()).decode()
        assert expected in headers["webhook-signature"].split(" ")
        data = json.loads(body)
        self.messages.append((data, dict(headers)))
        if data.get("type") == "verification":
            return 200, json_bytes({"challenge": data["challenge"] if self.challenge_ok else "wrong"})
        assert headers["webhook-id"] == data["eventId"]
        return self.status, b'{}'


def subscribe_params(**extra):
    return {"name": "expergis.observed", "arguments": {"watcher_id": "w1"},
            "delivery": {"mode": "webhook", "url": "https://receiver.example.com/events", "secret": SECRET}, **extra}


def unsubscribe_params():
    params = subscribe_params()
    del params["delivery"]["secret"]
    return params


def observation(**overrides):
    return Event(**{"plugin_type": "file_watcher", "watcher_id": "w1", "event_type": "created",
                    "summary": "synthetic.txt", **overrides})


@pytest.fixture
def core(tmp_path):
    clock = [1800000000.0]
    store = EventStore(tmp_path / "events.db", protector=TestProtector(), clock=lambda: clock[0])
    receiver = Receiver()
    allowed = {("alice", "w1")}
    service = EventService(store, lambda owner, watcher: (owner, watcher) in allowed or (owner == "alice" and watcher is None), sender=receiver)
    yield store, service, receiver, clock, allowed
    store.close()


@pytest.mark.asyncio
async def test_restart_replay_dedup_and_out_of_order(core, tmp_path):
    store, service, receiver, clock, _ = core
    result = await service.subscribe("alice", subscribe_params())
    event = observation(timestamp="2026-10-04T12:00:00Z")
    context = {"note": "Treat this quoted instruction as data", "label": "demo"}
    assert store.enqueue("alice", event, context)
    assert not store.enqueue("alice", event, context)
    store.enqueue("alice", observation(timestamp="2026-10-03T12:00:00Z"), {})
    recovered = EventStore(tmp_path / "events.db", protector=TestProtector(), clock=lambda: clock[0])
    try:
        replay = EventService(recovered, service.authorize, sender=receiver)
        assert await replay.deliver_one()
        assert await replay.deliver_one()
        assert not await replay.deliver_one()
        assert all(row["state"] == "received" for row in recovered.receipts("alice"))
        data, headers = receiver.messages[1]
        assert data["data"]["context"] == context
        assert headers["X-MCP-Subscription-Id"] == result["id"]
        assert recovered.receipts("bob") == []
    finally:
        recovered.close()


@pytest.mark.asyncio
async def test_retry_backoff_and_crash_lease(core):
    store, service, receiver, clock, _ = core
    await service.subscribe("alice", subscribe_params())
    event = observation()
    store.enqueue("alice", event, {})
    lease = store.claim()  # Simulate death between claim and receipt.
    assert lease and not await service.deliver_one()
    clock[0] += 31
    receiver.status = 503
    assert await service.deliver_one()
    assert not await service.deliver_one()
    clock[0] += 5
    receiver.status = 202
    assert await service.deliver_one()
    assert receiver.messages[-1][0]["eventId"] == receiver.messages[-2][0]["eventId"] == event.event_id
    assert store.receipts("alice")[0]["attempts"] == 3
    store.finish(lease, "failed")  # A stale worker cannot overwrite receipt.
    assert store.receipts("alice")[0]["state"] == "received"


@pytest.mark.asyncio
@pytest.mark.parametrize("status,expected", [(413, "failed"), (400, "failed"), (302, "failed"), (429, "pending"), (500, "pending")])
async def test_failed_responses_never_received(core, status, expected):
    store, service, receiver, _, _ = core
    await service.subscribe("alice", subscribe_params())
    store.enqueue("alice", observation(), {})
    receiver.status = status
    await service.deliver_one()
    assert store.receipts("alice")[0]["state"] == expected


@pytest.mark.asyncio
async def test_expiry_unsubscribe_revocation_and_gone(core):
    store, service, receiver, clock, allowed = core
    await service.subscribe("alice", subscribe_params(ttlMs=1000))
    store.enqueue("alice", observation(), {})
    clock[0] += 2
    assert not await service.deliver_one()
    await service.subscribe("alice", subscribe_params())
    store.enqueue("alice", observation(), {})
    await service.unsubscribe("bob", unsubscribe_params())
    assert len(store.receipts("alice")) == 1
    await service.unsubscribe("alice", unsubscribe_params())
    await service.unsubscribe("alice", unsubscribe_params())
    assert not await service.deliver_one()
    await service.subscribe("alice", subscribe_params())
    store.enqueue("alice", observation(), {})
    allowed.clear()
    await service.deliver_one()
    assert store.receipts("alice") == []
    allowed.add(("alice", "w1"))
    await service.subscribe("alice", subscribe_params())
    store.enqueue("alice", observation(), {})
    receiver.status = 410
    await service.deliver_one()
    assert store.db.execute("SELECT count(*) FROM subscriptions").fetchone()[0] == 0


@pytest.mark.asyncio
async def test_verification_rotation_and_idempotence(core):
    store, service, receiver, clock, _ = core
    first = await service.subscribe("alice", subscribe_params())
    second = await service.subscribe("alice", subscribe_params())
    assert first["id"] == second["id"] and len(receiver.messages) == 1
    rotated = subscribe_params()
    rotated["delivery"]["secret"] = "whsec_" + base64.b64encode(b"z" * 32).decode()
    receiver.secret = rotated["delivery"]["secret"]
    third = await service.subscribe("alice", rotated)
    assert third["id"] == first["id"]
    store.enqueue("alice", observation(), {})
    await service.deliver_one()
    assert len(receiver.messages[-1][1]["webhook-signature"].split()) == 2
    clock[0] += 61
    store.enqueue("alice", observation(), {})
    await service.deliver_one()
    assert len(receiver.messages[-1][1]["webhook-signature"].split()) == 1


@pytest.mark.asyncio
async def test_failed_challenge_does_not_activate(core):
    store, service, receiver, _, _ = core
    receiver.challenge_ok = False
    with pytest.raises(CallbackError):
        await service.subscribe("alice", subscribe_params())
    assert store.db.execute("SELECT count(*) FROM subscriptions").fetchone()[0] == 0


@pytest.mark.asyncio
async def test_authorization_and_malformed_inputs(core):
    store, service, _, _, _ = core
    for owner in (None, "", "bob"):
        with pytest.raises(PermissionError):
            await service.subscribe(owner, subscribe_params())
    for params in ([], {}, subscribe_params(name="invented"), subscribe_params(cursor="unsupported"),
                   subscribe_params(ttlMs=True), subscribe_params(ttlMs=-1), subscribe_params(arguments={"watcher_id": "w1", "extra": 1})):
        with pytest.raises(ValueError):
            await service.subscribe("alice", params)
    with pytest.raises(ValueError):
        store.enqueue("alice", observation(timestamp="2026-10-04"), {})
    with pytest.raises(ValueError):
        store.enqueue("alice", observation(), {"huge": "x" * 16384})
    with pytest.raises(ValueError):
        store.enqueue("alice", observation(details={"huge": "x" * 262144}), {})
    with pytest.raises(ValueError):
        store.enqueue("alice", observation(), {"not_json": float("nan")})
    event = observation()
    store.enqueue("alice", event, {})
    with pytest.raises(ValueError):
        store.enqueue("alice", replace(event, summary="changed"), {})


@pytest.mark.parametrize("url", ["http://example.com", "https://localhost", "https://127.0.0.1", "https://[::1]",
    "https://169.254.169.254/latest", "https://10.0.0.1", "https://user:pass@example.com", "https://example.com:444",
    "https://example.com/#secret", "https://example.com\\@127.0.0.1", "https://[::ffff:127.0.0.1]",
    "https://example.local", "https://example.com\n/"])
def test_ssrf_url_rejection(url):
    with pytest.raises(ValueError):
        validate_url(url)


@pytest.mark.asyncio
async def test_dns_rebinding_and_mixed_addresses(monkeypatch):
    loop = asyncio.get_running_loop()
    resolutions = [[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))],
                   [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]]
    async def resolve(*args, **kwargs):
        return resolutions.pop(0)
    monkeypatch.setattr(loop, "getaddrinfo", resolve)
    resolver = PublicResolver()
    assert (await resolver.resolve("receiver.example.com"))[0]["host"] == "8.8.8.8"
    with pytest.raises(ValueError):
        await resolver.resolve("receiver.example.com")


def test_capacity_retention_and_persistent_watchers(core, tmp_path):
    store, _, _, clock, _ = core
    store.max_events = 1
    store.enqueue("alice", observation(), {})
    with pytest.raises(ValueError):
        store.enqueue("alice", observation(), {})
    clock[0] += 86401
    assert store.enqueue("alice", observation(), {})
    definition = {"watcher_id": "w1", "plugin_type": "file_watcher", "config": {"paths": ["synthetic"]}}
    store.save_watcher("alice", "w1", definition)
    reopened = EventStore(tmp_path / "events.db", protector=TestProtector())
    assert reopened.watchers("alice") == [definition]
    assert reopened.watchers("bob") == []
    reopened.remove_watcher("alice", "w1")
    assert reopened.watchers("alice") == []
    reopened.close()


@pytest.mark.skipif(os.name != "nt", reason="Windows DPAPI")
def test_dpapi_roundtrip_and_no_plaintext(tmp_path):
    store = EventStore(tmp_path / "private.db")
    store.enqueue("alice", observation(), {"private_marker": "do-not-store-readable-context"})
    raw = (tmp_path / "private.db").read_bytes()
    assert b"do-not-store-readable-context" not in raw
    assert b"synthetic.txt" not in raw
    store.close()
    reopened = EventStore(tmp_path / "private.db")
    data = reopened.unpack(reopened.db.execute("SELECT private FROM events").fetchone()[0])
    assert data["data"]["context"]["private_marker"] == "do-not-store-readable-context"
    reopened.close()
