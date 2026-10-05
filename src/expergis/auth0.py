"""Opt-in Auth0 resource-server authentication; never handles login credentials.

JWT cryptography is delegated to PyJWT/cryptography. The bounded asynchronous
JWKS cache uses our SSRF-safe transport instead of PyJWT's synchronous fetcher.
Importing this module opens no files, listeners or network connections.
"""
import argparse
import asyncio
from dataclasses import dataclass
import json
from pathlib import Path
import re
import time
from urllib.parse import urlsplit

import aiohttp

from expergis.events_security import PublicResolver, read_bounded, validate_url


def read_json(path):
    with Path(path).open("rb") as source:
        body = source.read(65537)
    if len(body) > 65536:
        raise ValueError("Configuration exceeds limit")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate configuration key")
            result[key] = value
        return result
    return json.loads(body, object_pairs_hook=unique)


def strings(values, limit):
    return (isinstance(values, list) and 0 < len(values) <= limit
            and all(isinstance(v, str) and 0 < len(v) <= 512
                    and not any(ord(c) <= 32 for c in v) for v in values)
            and len(set(values)) == len(values))


@dataclass(frozen=True)
class Auth0Config:
    issuer: str
    resource: str
    client_ids: tuple[str, ...]
    policy_file: Path

    @classmethod
    def parse(cls, config):
        data = config.get("auth0")
        if not isinstance(data, dict) or set(data) != {"issuer", "resource", "client_ids", "policy_file"}:
            raise ValueError("auth0 requires issuer, resource, client_ids and policy_file only")
        issuer, resource = data["issuer"], data["resource"]
        for value in (issuer, resource):
            validate_url(value)
            parsed = urlsplit(value)
            if parsed.query or parsed.netloc != parsed.hostname or not re.fullmatch(r"[a-z0-9.-]+", parsed.hostname):
                raise ValueError("Use canonical HTTPS hostnames without port or query")
        if urlsplit(issuer).path != "/" or urlsplit(resource).path != "/mcp":
            raise ValueError("Issuer must end in /; resource must end in /mcp")
        if not strings(data["client_ids"], 4):
            raise ValueError("Explicit OAuth client allowlist required")
        raw = data["policy_file"]
        if not isinstance(raw, str) or raw.startswith(("\\\\", "//")) or not Path(raw).is_absolute():
            raise ValueError("An absolute local policy path is required")
        return cls(issuer, resource, tuple(data["client_ids"]), Path(raw))


class OwnerPolicy:
    """Re-read on each decision: missing, partial or invalid policy denies access.

    An operator should atomically replace this file in an existing private local
    directory. This is local authorization, not Auth0 tenant revocation polling.
    """
    def __init__(self, path, owner):
        if not isinstance(owner, str) or not 0 < len(owner) <= 512:
            raise ValueError("Explicit owner subject required")
        self.path, self.owner = Path(path), owner

    def snapshot(self):
        try:
            data = read_json(self.path)
            if (not isinstance(data, dict) or set(data) != {"owner", "enabled", "watcher_ids", "tokens_valid_after"}
                    or data["owner"] != self.owner or type(data["enabled"]) is not bool
                    or not isinstance(data["watcher_ids"], list)
                    or (data["watcher_ids"] and not strings(data["watcher_ids"], 32))
                    or any(not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", w) for w in data["watcher_ids"])
                    or type(data["tokens_valid_after"]) is not int
                    or not 0 <= data["tokens_valid_after"] <= 253402300799):
                return None
            return data
        except (OSError, ValueError, TypeError, RecursionError):
            return None

    def __call__(self, owner, watcher):
        policy = self.snapshot()
        return bool(policy and policy["enabled"] and owner == self.owner
                    and (watcher is None or watcher in policy["watcher_ids"]))

    def accepts_token(self, subject, issued_at):
        policy = self.snapshot()
        return bool(policy and policy["enabled"] and subject == self.owner
                    and issued_at > policy["tokens_valid_after"])


async def fetch_jwks(url):
    validate_url(url)
    connector = aiohttp.TCPConnector(resolver=PublicResolver(), use_dns_cache=False,
                                     force_close=True, limit=1)
    async with aiohttp.ClientSession(connector=connector, trust_env=False,
            cookie_jar=aiohttp.DummyCookieJar(), timeout=aiohttp.ClientTimeout(total=5)) as session:
        async with session.get(url, allow_redirects=False, headers={"Accept": "application/json"}) as response:
            if response.status != 200:
                raise ValueError("Key discovery unavailable")
            return json.loads(await read_bounded(response.content, 65536))


class Auth0Verifier:
    """RS256 access tokens for exactly one issuer/resource and selected clients.

    Keys live at a configured URL, never a token-supplied jku/x5u. Cache lifetime
    is 5 minutes; unknown-key/failure fetches are limited to once per 30 seconds.
    Expired keys are never used after a failed refresh. No token/claim logging.
    """
    def __init__(self, config, policy, *, fetch=fetch_jwks, clock=time.monotonic):
        from mcp.server.auth.provider import AccessToken
        if "subject" not in AccessToken.model_fields:
            raise RuntimeError("Auth0 event authentication requires the separate MCP 2.3 environment")
        self.config, self.policy, self.fetch, self.clock = config, policy, fetch, clock
        self.keys, self.valid_until, self.next_fetch = {}, 0.0, 0.0
        self.lock = asyncio.Lock()

    async def key(self, kid):
        import jwt
        async with self.lock:
            now = self.clock()
            if now < self.valid_until and kid in self.keys:
                return self.keys[kid]
            if now < self.next_fetch:
                return None
            self.next_fetch = now + 30
            data = await self.fetch(self.config.issuer + ".well-known/jwks.json")
            if not isinstance(data, dict) or not isinstance(data.get("keys"), list) or not 1 <= len(data["keys"]) <= 16:
                raise ValueError("Invalid key set")
            keys = {}
            for item in data["keys"]:
                if not isinstance(item, dict):
                    raise ValueError("Invalid key")
                # Ignore unrelated signing algorithms, but reject ambiguous IDs.
                if item.get("kty") != "RSA" or item.get("alg", "RS256") != "RS256" or item.get("use", "sig") != "sig":
                    continue
                key_id = item.get("kid")
                if (not isinstance(key_id, str) or not 0 < len(key_id) <= 128 or key_id in keys
                        or "d" in item or item.get("key_ops", ["verify"]) != ["verify"]
                        or not isinstance(item.get("n"), str) or len(item["n"]) > 1400
                        or not isinstance(item.get("e"), str) or len(item["e"]) > 8):
                    raise ValueError("Invalid verification key")
                key = jwt.PyJWK.from_dict(item, algorithm="RS256").key
                if not 2048 <= key.key_size <= 8192:
                    raise ValueError("Invalid RSA key size")
                keys[key_id] = key
            if not keys:
                raise ValueError("No supported verification keys")
            self.keys, self.valid_until = keys, self.clock() + 300
            return keys.get(kid)

    async def verify_token(self, token):
        import jwt
        from mcp.server.auth.provider import AccessToken
        try:
            if not isinstance(token, str) or not 0 < len(token) <= 16384 or not token.isascii():
                return None
            header = jwt.get_unverified_header(token)
            if (header.get("alg") != "RS256" or header.get("typ", "JWT") not in ("JWT", "at+jwt")
                    or any(name in header for name in ("jku", "x5u", "jwk", "crit", "b64"))
                    or not isinstance(header.get("kid"), str) or not 0 < len(header["kid"]) <= 128):
                return None
            key = await self.key(header["kid"])
            if key is None:
                return None
            claims = jwt.decode(token, key, algorithms=["RS256"], issuer=self.config.issuer,
                audience=self.config.resource, options={"require": ["exp", "iat", "iss", "aud", "sub"]})
            if (any(type(claims.get(c)) is not int for c in ("iat", "exp"))
                    or ("nbf" in claims and type(claims["nbf"]) is not int)
                    or claims["exp"] <= claims["iat"]
                    or claims.get("azp", claims.get("client_id")) not in self.config.client_ids
                    or ("azp" in claims and "client_id" in claims and claims["azp"] != claims["client_id"])
                    or not isinstance(claims.get("scope"), str) or len(claims["scope"]) > 4096
                    or "expergis" not in claims["scope"].split()
                    or not self.policy.accepts_token(claims["sub"], claims["iat"])):
                return None
            return AccessToken(token=token, subject=claims["sub"],
                client_id=claims.get("azp", claims.get("client_id")), scopes=claims["scope"].split(),
                expires_at=claims["exp"], resource=self.config.resource)
        except (jwt.PyJWTError, ValueError, TypeError, KeyError, OSError, aiohttp.ClientError, asyncio.TimeoutError):
            return None
        except Exception:
            # Transport/key parsing errors are deliberately not returned or logged:
            # third-party exception messages may contain a token or response body.
            return None


def components(config):
    from mcp.server.auth.settings import AuthSettings
    settings = Auth0Config.parse(config)
    options = config.get("mcp_events", {})
    if config.get("delivery_adapter") != "mcp_events":
        raise ValueError("Explicit event adapter required")
    policy = OwnerPolicy(settings.policy_file, options.get("owner"))
    if policy.snapshot() is None:
        raise ValueError("Missing or invalid owner policy")
    auth = AuthSettings(issuer_url=settings.issuer, resource_server_url=settings.resource,
                        required_scopes=["expergis"], validate_token_resource=True)
    return Auth0Verifier(settings, policy), auth, policy


def create_auth0_app(config, **kwargs):
    """Returns an ASGI app; caller manages approved runtime/listener deployment."""
    from expergis.mcp_events_app import create_app
    verifier, auth, policy = components(config)
    return create_app(config, verifier, auth, authorize=policy, **kwargs)


def main():
    """Offline preflight only: no key fetches, database, watcher or listener."""
    parser = argparse.ArgumentParser(description="Validate Expergis Auth0 configuration offline")
    parser.add_argument("config", type=Path)
    args = parser.parse_args()
    try:
        import jwt
        from mcp.server import Server
        if not hasattr(Server, "add_request_handler"):
            raise ValueError("Separate MCP 2.3 environment required")
        jwt.PyJWK  # Ensure optional verifier dependency is installed.
        _, _, policy = components(read_json(args.config))
        print("Auth configuration and policy valid; access " + ("enabled" if policy(policy.owner, None) else "disabled"))
        print("Offline only: issuer metadata, grants, filesystem permissions and live delivery are not verified.")
    except (ImportError, OSError, ValueError, TypeError, AttributeError):
        print("Preflight failed: check the dedicated environment, auth configuration and owner policy. No values logged.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
