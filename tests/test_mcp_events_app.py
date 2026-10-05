import asyncio
import time
from importlib.metadata import version

import pytest

pytestmark = pytest.mark.skipif(not version("mcp").startswith("2."), reason="Separate MCP 2.x environment required")


@pytest.mark.asyncio
async def test_authenticated_mcp2_contract(tmp_path, monkeypatch):
    import httpx2 as httpx
    from mcp.server.auth.provider import AccessToken
    from mcp.server.auth.settings import AuthSettings
    from expergis.mcp_events_app import create_app
    from expergis import server as runtime
    from expergis.event_store import EventStore
    from .test_events import TestProtector, Receiver, subscribe_params, unsubscribe_params, observation

    class Verifier:
        async def verify_token(self, token):
            if token not in ("synthetic-alice", "synthetic-bob", "synthetic-expired", "synthetic-wrong-resource", "synthetic-no-scope"):
                return None
            return AccessToken(token=token, subject="bob" if token == "synthetic-bob" else "alice", client_id="test-client",
                scopes=[] if token == "synthetic-no-scope" else ["expergis"],
                expires_at=int(time.time()) + (-60 if token == "synthetic-expired" else 60),
                resource="https://wrong.example.com" if token == "synthetic-wrong-resource" else "https://expergis.example.com/mcp")

    config = {"velle_endpoint": "http://127.0.0.1:1/do-not-call", "delivery_adapter": "mcp_events",
              "mcp_events": {"owner": "alice", "allowed_roots": [str(tmp_path)]}, "watchers": []}
    store = EventStore(tmp_path / "events.db", protector=TestProtector())
    receiver = Receiver()
    revoked = set()
    app = create_app(config, Verifier(), AuthSettings(issuer_url="https://issuer.example.com",
        resource_server_url="https://expergis.example.com/mcp", required_scopes=["expergis"], validate_token_resource=True),
        authorize=lambda owner, watcher: owner == "alice" and watcher not in revoked, store=store, sender=receiver)
    headers = {"Authorization": "Bearer synthetic-alice", "MCP-Protocol-Version": "2026-07-28",
               "Accept": "application/json, text/event-stream"}
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://expergis.example.com") as client:
            async def request(method, params=None, token="synthetic-alice"):
                payload = {"jsonrpc": "2.0", "id": 1, "method": method}
                payload["params"] = {**(params or {}), "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {}}}
                return await client.post("/mcp", headers={**headers, "Authorization": "Bearer " + token, "Mcp-Method": method, **({"Mcp-Name": params["name"]} if method == "tools/call" else {})}, json=payload)

            assert (await request("server/discover", token="invalid")).status_code == 401
            assert "error" in (await request("server/discover", token="synthetic-bob")).json()
            for token in ("synthetic-expired", "synthetic-wrong-resource", "synthetic-no-scope"):
                assert (await request("server/discover", token=token)).status_code in (401, 403)
            discover = (await request("server/discover")).json()
            assert "result" in discover, discover
            assert discover["result"]["supportedVersions"] == ["2026-07-28"]
            assert discover["result"]["capabilities"]["events"] == {}
            listed = (await request("tools/list")).json()
            assert {tool["name"] for tool in listed["result"]["tools"]} == {
                "expergis_watch", "expergis_unwatch", "expergis_list", "expergis_check"}
            assert (await request("events/list")).json()["result"]["events"][0]["name"] == "expergis.observed"
            forbidden = await request("tools/call", {"name": "expergis_watch", "arguments": {
                "watcher_id": "bad", "plugin_type": "file_watcher", "config": {"paths": [str(tmp_path.parent)]}}})
            assert "error" in forbidden.json()
            unc = await request("tools/call", {"name": "expergis_watch", "arguments": {
                "watcher_id": "unc", "plugin_type": "file_watcher", "config": {"paths": ["//forbidden.invalid/share"]}}})
            assert "error" in unc.json()
            registered = await request("tools/call", {"name": "expergis_watch", "arguments": {
                "watcher_id": "w1", "plugin_type": "schedule_watcher", "config": {"cron": "0 0 1 1 *"}}})
            assert "result" in registered.json()
            subscribed = (await request("events/subscribe", subscribe_params())).json()
            assert subscribed["result"]["id"].startswith("sub_")
            assert subscribed["result"]["cursor"] is None
            bad = (await request("events/subscribe", subscribe_params(ttlMs=True))).json()
            assert bad["error"]["code"] == -32602
            await runtime._dispatcher.dispatch(observation(), "NEVER SEND TO VELLE")
            await runtime._dispatcher.event_service.deliver_one()
            assert store.receipts("alice")[0]["state"] == "received"
            removed = (await request("events/unsubscribe", unsubscribe_params())).json()
            assert set(removed["result"]) <= {"resultType", "_meta"}
            assert store.db.execute("SELECT count(*) FROM subscriptions").fetchone()[0] == 0
            receiver.challenge_ok = False
            params = subscribe_params()
            params["delivery"]["url"] += "/unverified"
            bad_callback = (await request("events/subscribe", params)).json()
            assert bad_callback["error"]["code"] == -32015
            assert bad_callback["error"]["data"]["reason"] == "challenge_failed"
            revoked.add("w1")
            listing = (await request("tools/call", {"name": "expergis_list", "arguments": {}})).json()
            import json
            assert json.loads(listing["result"]["content"][0]["text"])["watchers"] == []
            denied = (await request("events/subscribe", subscribe_params())).json()
            assert denied["error"]["code"] == -32001
