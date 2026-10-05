"""Synthetic signatures only. No tenant, credentials or remote receiver needed."""
import asyncio
import copy
from importlib.metadata import version
import json
import time
from unittest.mock import AsyncMock

import pytest

pytestmark = pytest.mark.skipif(not version("mcp").startswith("2."), reason="Auth0 event adapter requires MCP 2.x")

jwt = pytest.importorskip("jwt")
from cryptography.hazmat.primitives.asymmetric import rsa
from expergis.auth0 import Auth0Config, Auth0Verifier, OwnerPolicy, components, fetch_jwks


@pytest.fixture(scope="module")
def signing_keys():
    # Ephemeral test material never written to disk.
    result = []
    for kid in ("first", "second"):
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key()))
        public.update(kid=kid, use="sig", alg="RS256")
        result.append((private, public))
    return result


@pytest.fixture
def setup(tmp_path, signing_keys):
    path = tmp_path / "policy.json"
    policy_data = {"owner": "google-oauth2|synthetic", "enabled": True,
                   "watcher_ids": ["w1"], "tokens_valid_after": 0}
    path.write_text(json.dumps(policy_data))
    config = {"delivery_adapter": "mcp_events", "watchers": [], "velle_endpoint": "http://127.0.0.1:1/do-not-call",
              "mcp_events": {"owner": policy_data["owner"]},
              "auth0": {"issuer": "https://synthetic.auth0.com/", "resource": "https://expergis.example.com/mcp",
                        "client_ids": ["dedicated-client"], "policy_file": str(path)}}
    policy = OwnerPolicy(path, policy_data["owner"])
    clock = [1000.0]
    fetch = AsyncMock(return_value={"keys": [signing_keys[0][1]]})
    verifier = Auth0Verifier(Auth0Config.parse(config), policy, fetch=fetch, clock=lambda: clock[0])
    now = int(time.time())
    claims = {"iss": config["auth0"]["issuer"], "aud": config["auth0"]["resource"],
              "sub": policy_data["owner"], "azp": "dedicated-client", "scope": "openid expergis",
              "iat": now - 1, "exp": now + 600}
    def sign(changes=None, headers=None, key=0):
        return jwt.encode({**claims, **(changes or {})}, signing_keys[key][0], algorithm="RS256",
                          headers={"kid": signing_keys[key][1]["kid"], **(headers or {})})
    return config, policy_data, policy, clock, fetch, verifier, claims, sign


@pytest.mark.asyncio
async def test_valid_resource_bound_token_and_cache(setup):
    config, _, _, _, fetch, verifier, claims, sign = setup
    token = sign({"aud": [claims["aud"], config["auth0"]["issuer"] + "userinfo"]})
    result = await verifier.verify_token(token)
    assert result.subject == claims["sub"] and result.resource == claims["aud"]
    assert result.client_id == "dedicated-client" and "expergis" in result.scopes
    assert (await verifier.verify_token(token)) is not None
    fetch.assert_awaited_once_with(config["auth0"]["issuer"] + ".well-known/jwks.json")


@pytest.mark.parametrize("changes", [
    {"iss": "https://attacker.example.com/"}, {"aud": "another-api"},
    {"sub": "another-owner"}, {"azp": "another-client"}, {"client_id": "conflicting-client"},
    {"scope": "openid profile"}, {"scope": ["expergis"]}, {"exp": 1}, {"exp": None},
    {"iat": 253402300000}, {"iat": True}, {"nbf": 253402300000}, {"nbf": "0"},
])
@pytest.mark.asyncio
async def test_invalid_claims(setup, changes):
    *_, verifier, claims, sign = setup
    assert await verifier.verify_token(sign(changes)) is None


@pytest.mark.parametrize("header", [{"jku": "http://127.0.0.1/keys"}, {"x5u": "https://attacker.example.com"},
    {"jwk": {}}, {"crit": []}, {"typ": "id_token"}, {"kid": ""}])
@pytest.mark.asyncio
async def test_untrusted_headers_do_not_fetch(setup, header):
    _, _, _, _, fetch, verifier, _, sign = setup
    assert await verifier.verify_token(sign(headers=header)) is None
    fetch.assert_not_awaited()


@pytest.mark.asyncio
async def test_signature_algorithm_malformed_limits(setup, signing_keys):
    _, _, _, _, fetch, verifier, claims, sign = setup
    for token in ("", "invalid", "x" * 16385, "\N{SNOWMAN}",
                  jwt.encode(claims, "not-an-rsa-key" * 4, algorithm="HS256", headers={"kid": "first"}),
                  jwt.encode(claims, None, algorithm="none", headers={"kid": "first"})):
        assert await verifier.verify_token(token) is None
    fetch.assert_not_awaited()
    # A valid signature from another key with a known kid must be rejected.
    assert await verifier.verify_token(sign(headers={"kid": "first"}, key=1)) is None
    assert await verifier.verify_token(sign()) is not None


@pytest.mark.asyncio
async def test_rotation_refresh_singleflight_expiry_and_failure(setup, signing_keys):
    _, _, _, clock, fetch, verifier, _, sign = setup
    assert await verifier.verify_token(sign()) is not None
    assert await verifier.verify_token(sign(key=1)) is None  # bounded refresh cooldown
    clock[0] += 31
    fetch.return_value = {"keys": [pair[1] for pair in signing_keys]}
    assert all(await asyncio.gather(*(verifier.verify_token(sign(key=1)) for _ in range(10))))
    assert fetch.await_count == 2
    clock[0] += 301
    fetch.side_effect = OSError("PRIVATE response detail")
    assert await verifier.verify_token(sign()) is None
    assert await verifier.verify_token(sign()) is None
    assert fetch.await_count == 3
    clock[0] += 31
    fetch.side_effect = None
    fetch.return_value = {"keys": [signing_keys[1][1]]}
    assert await verifier.verify_token(sign(key=1)) is not None
    assert await verifier.verify_token(sign()) is None  # removed key is gone


@pytest.mark.parametrize("kind", ["empty", "duplicate", "too_many", "malformed", "private", "bad_ops"])
@pytest.mark.asyncio
async def test_invalid_jwks_fails_closed(setup, signing_keys, kind):
    _, _, _, _, fetch, verifier, _, sign = setup
    key = copy.deepcopy(signing_keys[0][1])
    sets = {"empty": [], "duplicate": [key, key], "too_many": [key] * 17,
            "malformed": [None], "private": [{**key, "d": "do-not-accept"}],
            "bad_ops": [{**key, "key_ops": ["sign"]}]}
    fetch.return_value = {"keys": sets[kind]}
    assert await verifier.verify_token(sign()) is None


@pytest.mark.asyncio
async def test_policy_revocation_and_invalid_file(setup):
    _, data, policy, _, _, verifier, claims, sign = setup
    assert policy(data["owner"], "w1") and not policy(data["owner"], "w2")
    assert not policy("other", None)
    assert await verifier.verify_token(sign()) is not None
    data["tokens_valid_after"] = claims["iat"]
    policy.path.write_text(json.dumps(data))
    assert await verifier.verify_token(sign()) is None
    data["tokens_valid_after"] = 0
    data["watcher_ids"] = []
    policy.path.write_text(json.dumps(data))
    assert policy(data["owner"], None) and not policy(data["owner"], "w1")
    data["enabled"] = False
    policy.path.write_text(json.dumps(data))
    assert not policy(data["owner"], None) and await verifier.verify_token(sign()) is None
    for content in ("{", "null", "{}", "x" * 65537,
                    json.dumps({**data, "enabled": "true"}), '{"enabled":true,"enabled":false}'):
        policy.path.write_text(content)
        assert not policy(data["owner"], None)
    policy.path.unlink()
    assert not policy(data["owner"], None)


@pytest.mark.parametrize("field,value", [
    ("issuer", "http://synthetic.auth0.com/"), ("issuer", "https://127.0.0.1/"),
    ("issuer", "https://synthetic.auth0.com/tenant/"), ("issuer", "https://synthetic.auth0.com/?q=x"),
    ("resource", "https://expergis.example.com/mcp?query=x"), ("client_ids", []),
    ("policy_file", "//server/share/policy.json"), ("policy_file", "relative.json"),
])
def test_configuration_rejects_unsafe_or_ambiguous_values(setup, field, value):
    config = copy.deepcopy(setup[0])
    config["auth0"][field] = value
    with pytest.raises(ValueError):
        Auth0Config.parse(config)


@pytest.mark.asyncio
async def test_jwks_transport_is_bounded_no_redirects_or_credentials(monkeypatch):
    import aiohttp
    import expergis.auth0 as auth
    calls = {}
    class Response:
        status = 200
        content = asyncio.StreamReader()
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
    response = Response()
    response.content.feed_data(b'{"keys":[]}')
    response.content.feed_eof()
    class Session:
        def __init__(self, **kwargs): calls.update(kwargs)
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        def get(self, url, **kwargs):
            calls.update(url=url, **kwargs)
            return response
    monkeypatch.setattr(aiohttp, "TCPConnector", lambda **kwargs: kwargs)
    monkeypatch.setattr(aiohttp, "ClientSession", Session)
    assert await fetch_jwks("https://synthetic.auth0.com/.well-known/jwks.json") == {"keys": []}
    assert calls["allow_redirects"] is False and calls["trust_env"] is False
    assert calls["timeout"].total == 5 and isinstance(calls["connector"]["resolver"], auth.PublicResolver)
    response.status = 302
    with pytest.raises(ValueError):
        await fetch_jwks("https://synthetic.auth0.com/.well-known/jwks.json")
    response.status = 200
    response.content = asyncio.StreamReader()
    response.content.feed_data(b"x" * 65537)
    response.content.feed_eof()
    from expergis.events_security import CallbackError
    with pytest.raises(CallbackError):
        await fetch_jwks("https://synthetic.auth0.com/.well-known/jwks.json")


@pytest.mark.skipif(not version("mcp").startswith("2."), reason="Separate MCP 2.x environment required")
@pytest.mark.asyncio
async def test_auth0_app_metadata_revocation_and_offline_preflight(setup, tmp_path, monkeypatch, capsys):
    import httpx2 as httpx
    from expergis.auth0 import create_auth0_app, main
    from expergis.event_store import EventStore
    from .test_events import TestProtector, Receiver
    config, policy_data, policy, _, _, verifier, _, sign = setup
    monkeypatch.setattr(Auth0Verifier, "key", verifier.key)
    store = EventStore(tmp_path / "events.db", protector=TestProtector())
    app = create_auth0_app(config, store=store, sender=Receiver())
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://expergis.example.com") as client:
            metadata = await client.get("/.well-known/oauth-protected-resource/mcp")
            assert metadata.status_code == 200
            assert metadata.json()["resource"] == config["auth0"]["resource"]
            assert metadata.json()["authorization_servers"] == [config["auth0"]["issuer"]]
            assert metadata.json()["scopes_supported"] == ["expergis"]
            headers = {"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/list",
                       "Accept": "application/json, text/event-stream"}
            payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {}}}}
            denied = await client.post("/mcp", json=payload, headers=headers)
            assert denied.status_code == 401 and "resource_metadata=" in denied.headers["www-authenticate"]
            headers["Authorization"] = "Bearer " + sign()
            listed = await client.post("/mcp", json=payload, headers=headers)
            assert listed.status_code == 200
            assert all(t["securitySchemes"] == [{"type": "oauth2", "scopes": ["expergis"]}]
                       for t in listed.json()["result"]["tools"])
            policy_data["enabled"] = False
            policy.path.write_text(json.dumps(policy_data))
            assert (await client.post("/mcp", json=payload, headers=headers)).status_code == 401
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps(config))
    monkeypatch.setattr("sys.argv", ["preflight", str(config_file)])
    assert main() == 0
    output = capsys.readouterr().out
    assert "access disabled" in output and policy_data["owner"] not in output


@pytest.mark.asyncio
async def test_local_policy_revokes_queued_delivery(setup, tmp_path):
    from expergis.event_service import EventService
    from expergis.event_store import EventStore
    from .test_events import TestProtector, Receiver, subscribe_params, observation
    _, data, policy, *_ = setup
    store = EventStore(tmp_path / "revoked.db", protector=TestProtector())
    try:
        receiver = Receiver()
        service = EventService(store, policy, sender=receiver)
        await service.subscribe(data["owner"], subscribe_params())
        store.enqueue(data["owner"], observation(), {})
        data["enabled"] = False
        policy.path.write_text(json.dumps(data))
        assert await service.deliver_one()
        assert len(receiver.messages) == 1  # Only the earlier signed challenge.
        assert store.db.execute("SELECT count(*) FROM subscriptions").fetchone()[0] == 0
    finally:
        store.close()


@pytest.mark.parametrize("value", [
    None, "", "http://localhost:8000/mcp", "http://127.0.0.2:8000/mcp",
    "http://0.0.0.0:8000/mcp", "http://example.com:8000/mcp",
    "https://127.0.0.1:8000/mcp", "http://127.0.0.1:0/mcp",
    "http://127.0.0.1:65536/mcp", "http://127.0.0.1:08000/mcp",
    "http://127.0.0.1:8000/mcp/", "http://127.0.0.1:8000/mcp?x=1",
    "http://user@127.0.0.1:8000/mcp", "http://127.0.0.1:8000/v1/mcp/test",
])
def test_tunnel_metadata_binding_rejects_nonliteral_or_ambiguous_urls(setup, value):
    config = copy.deepcopy(setup[0])
    config["auth0"]["tunnel_local_resource"] = value
    with pytest.raises(ValueError):
        Auth0Config.parse(config)


@pytest.mark.asyncio
async def test_tunnel_metadata_routing_preserves_exact_audience_and_issuer_fetch(setup, tmp_path, monkeypatch):
    import httpx2 as httpx
    from expergis.auth0 import create_auth0_app
    from expergis.event_store import EventStore
    from .test_events import TestProtector, Receiver
    config, _, _, _, fetch, verifier, _, sign = setup
    config = copy.deepcopy(config)
    # Synthetic identifier with the observed tunnel resource's shape. Never fetched.
    resource = "https://tunnel-service.gateway.unified-0.internal.api.openai.org/v1/mcp/tunnel_synthetic"
    local = "http://127.0.0.1:8123/mcp"
    config["auth0"].update(resource=resource, tunnel_local_resource=local)
    monkeypatch.setattr(Auth0Verifier, "key", verifier.key)
    store = EventStore(tmp_path / "tunnel.db", protector=TestProtector())
    app = create_auth0_app(config, store=store, sender=Receiver())
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8123") as client:
            metadata = await client.get("/.well-known/oauth-protected-resource/mcp")
            assert metadata.status_code == 200
            assert metadata.json()["resource"] == local
            assert metadata.json()["authorization_servers"] == [config["auth0"]["issuer"]]
            assert (await client.get("/.well-known/oauth-protected-resource/v1/mcp/tunnel_synthetic")).status_code == 404
            headers = {"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/list",
                       "Accept": "application/json, text/event-stream"}
            payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {}}}}
            denied = await client.post("/mcp", json=payload, headers=headers)
            assert denied.status_code == 401
            challenge = denied.headers["www-authenticate"]
            assert 'resource_metadata="http://127.0.0.1:8123/.well-known/oauth-protected-resource/mcp"' in challenge
            assert "tunnel_synthetic" not in challenge
            for audience in (local, resource + "/", resource + "-other", "https://expergis.example.com/mcp"):
                response = await client.post("/mcp", json=payload,
                    headers={**headers, "Authorization": "Bearer " + sign({"aud": audience})})
                assert response.status_code == 401
            response = await client.post("/mcp", json=payload,
                headers={**headers, "Authorization": "Bearer " + sign({"aud": resource})})
            assert response.status_code == 200
            assert response.json()["result"]["tools"]
    fetch.assert_awaited_once_with(config["auth0"]["issuer"] + ".well-known/jwks.json")


@pytest.mark.parametrize("resource", ["https://expergis.example.com/other", "https://expergis.example.com/v1/mcp/synthetic"])
def test_resource_identifier_does_not_require_mcp_suffix(setup, resource):
    config = copy.deepcopy(setup[0])
    config["auth0"]["resource"] = resource
    assert Auth0Config.parse(config).resource == resource


@pytest.mark.parametrize("resource", ["https://expergis.example.com/a/../mcp", "https://expergis.example.com/mcp#x"])
def test_resource_identifier_rejects_normalization_or_fragment(setup, resource):
    config = copy.deepcopy(setup[0])
    config["auth0"]["resource"] = resource
    with pytest.raises(ValueError):
        Auth0Config.parse(config)
