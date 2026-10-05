import asyncio
import base64
import contextlib
import hashlib
import hmac
import json
import os
import subprocess
import sys
from unittest.mock import AsyncMock, MagicMock

import pytest

from expergis.dispatcher import Dispatcher
from expergis.event_store import EventStore
from expergis.event_service import EventService
from expergis.events_security import WebhookSender, signed_headers, signing_key, json_bytes, CallbackError
from expergis.runtime_lock import RuntimeLock
from .test_events import Receiver, SECRET, TestProtector, observation, subscribe_params, unsubscribe_params


@pytest.mark.asyncio
@pytest.mark.parametrize("response", [b'{"status":"error"}', b'{"success":false}', b'{"error":"private failure"}',
    b'{"ok":false}', b'not JSON', b'[]', b'x' * 4097])
async def test_legacy_200_errors_are_not_delivery(response, caplog):
    dispatcher = Dispatcher({"velle_endpoint": "http://127.0.0.1:1/unused"})
    session = MagicMock(closed=False)
    reply = AsyncMock(status=200)
    reply.__aenter__.return_value = reply
    reply.content.readexactly.side_effect = asyncio.IncompleteReadError(response, 4097)
    session.post.return_value = reply
    session.close = AsyncMock()
    dispatcher._session = session
    await dispatcher.dispatch(observation(), "{event.summary}")
    assert dispatcher.stats["dispatched"] == 0
    assert dispatcher.stats["dispatch_errors"] == 1
    assert not dispatcher.get_recent_events()[0]["dispatched"]
    assert "private failure" not in caplog.text
    assert session.post.call_args.kwargs["allow_redirects"] is False
    await dispatcher.close()


@pytest.mark.asyncio
async def test_buffer_and_invalid_template_never_send():
    dispatcher = Dispatcher({"velle_endpoint": "http://127.0.0.1:1/unused", "delivery_adapter": "buffer"})
    await dispatcher.dispatch(observation(), "{bad}")
    assert dispatcher.get_recent_events()[0]["delivery_status"] == "buffered"
    dispatcher = Dispatcher({"velle_endpoint": "http://127.0.0.1:1/unused"})
    await dispatcher.dispatch(observation(), "{bad}")
    assert dispatcher.stats["dispatch_errors"] == 1
    assert dispatcher.get_recent_events()[0]["reason_skipped"] == "invalid_template"


def test_process_lock_and_release(tmp_path):
    path = tmp_path / "events.db"
    first = RuntimeLock(path)
    with pytest.raises(RuntimeError):
        RuntimeLock(path)
    first.close()
    second = RuntimeLock(path)
    second.close()


@pytest.mark.skipif(os.name != "nt", reason="Windows DPAPI restart")
def test_real_process_restart_and_dpapi(tmp_path):
    database = tmp_path / "restart.db"
    store = EventStore(database)
    event = observation()
    store.subscribe("sub_test", "alice", "w1", subscribe_params()["delivery"], 9999999999)
    store.enqueue("alice", event, {"note": "synthetic"})
    store.close()
    code = """import sys
from expergis.event_store import EventStore
s=EventStore(sys.argv[1])
item=s.claim()
assert item['payload']['eventId']==sys.argv[2]
assert item['delivery']['secret'].startswith('whsec_')
s.finish(item,'received',status=202)
s.close()
"""
    child = subprocess.run([sys.executable, "-c", code, str(database), event.event_id],
                           capture_output=True, text=True, timeout=15,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    assert child.returncode == 0, child.stderr
    store = EventStore(database)
    assert store.receipts("alice")[0]["state"] == "received"
    store.close()


@pytest.mark.asyncio
async def test_retry_exhaustion_and_unsubscribe_inflight(tmp_path):
    clock = [1800000000.0]
    store = EventStore(tmp_path / "test.db", protector=TestProtector(), clock=lambda: clock[0])
    receiver = Receiver()
    service = EventService(store, lambda owner, watcher: owner == "alice", sender=receiver)
    await service.subscribe("alice", subscribe_params())
    store.enqueue("alice", observation(), {})
    receiver.status = 503
    for _ in range(8):
        assert await service.deliver_one()
        clock[0] += 300
    assert store.receipts("alice")[0]["state"] == "failed"
    assert not await service.deliver_one()

    entered, release = asyncio.Event(), asyncio.Event()
    original = receiver.post
    async def paused(*args):
        entered.set()
        await release.wait()
        return await original(*args)
    receiver.post = paused
    receiver.status = 202
    store.enqueue("alice", observation(), {})
    delivery = asyncio.create_task(service.deliver_one())
    await entered.wait()
    unsubscribe = asyncio.create_task(service.unsubscribe("alice", unsubscribe_params()))
    await asyncio.sleep(0)
    assert not unsubscribe.done()
    release.set()
    await delivery
    await unsubscribe
    assert not await service.deliver_one()
    store.close()


@pytest.mark.asyncio
async def test_filtered_events_and_subscription_cap(tmp_path):
    store = EventStore(tmp_path / "test.db", protector=TestProtector(), max_subscriptions=1, max_jobs=1)
    receiver = Receiver()
    service = EventService(store, lambda owner, watcher: True, sender=receiver)
    await service.subscribe("alice", subscribe_params())
    with pytest.raises(ValueError):
        await service.subscribe("bob", subscribe_params())
    assert len(receiver.messages) == 1  # No outbound challenge after capacity exhausted.
    store.enqueue("bob", observation(), {})
    store.enqueue("alice", observation(watcher_id="different"), {})
    assert not await service.deliver_one()
    store.enqueue("alice", observation(), {})
    with pytest.raises(ValueError):
        store.enqueue("alice", observation(), {})
    assert store.db.execute("SELECT count(*) FROM events").fetchone()[0] == 3
    store.close()


@pytest.mark.asyncio
async def test_webhook_production_transport_settings(monkeypatch):
    import aiohttp
    response = AsyncMock(status=302)
    response.__aenter__.return_value = response
    response.content.readexactly.side_effect = asyncio.IncompleteReadError(b'{}', 4097)
    session = MagicMock()
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=False)
    session.post.return_value = response
    sessions = MagicMock(return_value=session)
    connector = MagicMock()
    monkeypatch.setattr(aiohttp, "ClientSession", sessions)
    monkeypatch.setattr(aiohttp, "TCPConnector", connector)
    status, _ = await WebhookSender().post("https://receiver.example.com/events", b'{}', {})
    assert status == 302
    assert session.post.call_args.kwargs["allow_redirects"] is False
    assert sessions.call_args.kwargs["trust_env"] is False
    assert connector.call_args.kwargs["use_dns_cache"] is False
    assert connector.call_args.kwargs["force_close"] is True
    response.content.readexactly.side_effect = asyncio.IncompleteReadError(b'x' * 4097, 4097)
    with pytest.raises(CallbackError):
        await WebhookSender().post("https://receiver.example.com/events", b'{}', {})


@pytest.mark.asyncio
async def test_signed_loopback_receiver(tmp_path, loopback_client):
    from aiohttp import web
    received = []
    async def receive(request):
        body = await request.read()
        headers = request.headers
        message = f"{headers['webhook-id']}.{headers['webhook-timestamp']}.".encode() + body
        expected = "v1," + base64.b64encode(hmac.new(signing_key(SECRET), message, hashlib.sha256).digest()).decode()
        if not hmac.compare_digest(headers["webhook-signature"], expected):
            return web.Response(status=401)
        data = json.loads(body)
        received.append(data)
        if data.get("type") == "verification":
            return web.json_response({"challenge": data["challenge"]})
        return web.Response(status=202)
    app = web.Application(client_max_size=262144)
    app.router.add_post("/callback", receive)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    class LocalSender(WebhookSender):
        async def post(self, url, body, headers):
            assert url == "https://receiver.example.com/events"
            return await loopback_client(port, body, headers)
    store = EventStore(tmp_path / "loopback.db", protector=TestProtector())
    try:
        service = EventService(store, lambda owner, watcher: owner == "alice", sender=LocalSender())
        await service.subscribe("alice", subscribe_params())
        store.enqueue("alice", observation(), {"label": "loopback only"})
        await service.deliver_one()
        assert received[0]["type"] == "verification"
        assert received[1]["data"]["context"] == {"label": "loopback only"}
        assert store.receipts("alice")[0]["state"] == "received"
        body = json_bytes({"eventId": "evt_bad"})
        headers = signed_headers(SECRET, "sub_bad", "evt_bad", body)
        headers["webhook-signature"] = "v1,invalid"
        status, _ = await loopback_client(port, body, headers)
        assert status == 401
    finally:
        store.close()
        await runner.cleanup()


def test_audit_rotation_and_oversize(tmp_path, monkeypatch):
    from expergis import audit
    path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(audit, "MAX_AUDIT_BYTES", 140)
    for _ in range(5):
        audit.audit_log({"action": "synthetic"}, path)
    assert path.stat().st_size <= 140
    assert path.with_name("audit.jsonl.1").stat().st_size <= 140
    original = path.read_bytes()
    audit.audit_log({"oversize": "x" * 17000}, path)
    assert path.read_bytes() == original


@pytest.mark.asyncio
async def test_callback_timeout_and_mid_verification_revocation(tmp_path):
    store = EventStore(tmp_path / "verify.db", protector=TestProtector())
    receiver = Receiver()
    allowed = [True]
    service = EventService(store, lambda owner, watcher: allowed[0], sender=receiver)
    async def timeout(*args):
        raise asyncio.TimeoutError()
    receiver.post = timeout
    with pytest.raises(CallbackError, match="timeout"):
        await service.subscribe("alice", subscribe_params())
    receiver = Receiver()
    post = receiver.post
    async def revoke(*args):
        result = await post(*args)
        allowed[0] = False
        return result
    receiver.post = revoke
    service.sender = receiver
    with pytest.raises(PermissionError):
        await service.subscribe("alice", subscribe_params())
    assert store.db.execute("SELECT count(*) FROM subscriptions").fetchone()[0] == 0
    store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("args", [[], {}, {"watcher_id": [], "plugin_type": "file_watcher"},
    {"watcher_id": "bad", "plugin_type": "file_watcher", "config": {"paths": "not-a-list"}},
    {"watcher_id": "bad", "plugin_type": "process_watcher", "config": {"process_names": [None]}},
    {"watcher_id": "bad", "plugin_type": "file_watcher", "config": {"context": []}}])
async def test_malformed_watch_registration(args):
    from expergis import server
    result = await server._handle_watch(args)
    assert json.loads(result[0].text)["status"] == "error"
    assert "bad" not in server._watchers
