"""Bounded Standard Webhooks delivery with connection-time SSRF protection."""
import asyncio
import base64
import hashlib
import hmac
import ipaddress
import json
import secrets
import socket
import time
from urllib.parse import urlsplit

import aiohttp

MAX_PAYLOAD = 262144


def json_bytes(value, limit=MAX_PAYLOAD):
    try:
        body = json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, RecursionError) as exc:
        raise ValueError("Invalid JSON data") from exc
    if len(body) > limit:
        raise ValueError("Payload exceeds limit")
    return body


def signing_key(secret):
    if not isinstance(secret, str) or not secret.startswith("whsec_") or len(secret) > 100:
        raise ValueError("Invalid signing secret")
    try:
        key = base64.b64decode(secret[6:], validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("Invalid signing secret") from exc
    if not 24 <= len(key) <= 64:
        raise ValueError("Invalid signing secret")
    return key


def signed_headers(secret, subscription_id, message_id, body, now=None):
    timestamp = str(int(time.time() if now is None else now))
    message = message_id.encode() + b"." + timestamp.encode() + b"." + body
    signature = base64.b64encode(hmac.new(signing_key(secret), message, hashlib.sha256).digest()).decode()
    return {"Content-Type": "application/json", "webhook-id": message_id,
            "webhook-timestamp": timestamp, "webhook-signature": "v1," + signature,
            "X-MCP-Subscription-Id": subscription_id}


def validate_url(url):
    if not isinstance(url, str) or len(url) > 2048 or any(ord(c) <= 32 for c in url):
        raise ValueError("Invalid callback URL")
    try:
        parsed = urlsplit(url)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.fragment or parsed.port not in (None, 443)
                or "\\" in url or "%" in parsed.netloc):
            raise ValueError("Invalid callback URL")
        host = parsed.hostname.encode("idna").decode("ascii")
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            if "." not in host or host.endswith((".localhost", ".local", ".internal")):
                raise ValueError("Non-public callback URL")
        else:
            public_address(str(address))
    except (UnicodeError, ValueError) as exc:
        raise ValueError("Invalid callback URL") from exc
    return host


def public_address(value):
    address = ipaddress.ip_address(value)
    if (not address.is_global or address.is_multicast or address.is_unspecified
            or getattr(address, "ipv4_mapped", None) is not None
            or getattr(address, "sixtofour", None) is not None
            or getattr(address, "teredo", None) is not None):
        raise ValueError("Non-public callback address")
    return value


class PublicResolver(aiohttp.abc.AbstractResolver):
    """The connector uses only these validated addresses, retaining TLS hostname."""
    async def resolve(self, host, port=443, family=socket.AF_UNSPEC):
        records = await asyncio.get_running_loop().getaddrinfo(
            host, port, family=family, type=socket.SOCK_STREAM)
        if not records or len(records) > 32:
            raise ValueError("Invalid callback resolution")
        return [{"hostname": host, "host": public_address(record[4][0]), "port": port,
                 "family": record[0], "proto": record[2], "flags": socket.AI_NUMERICHOST}
                for record in records]

    async def close(self):
        pass


class CallbackError(Exception):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


class WebhookSender:
    """One request per fresh connector; no proxy env, redirects, cookies or DNS cache."""
    async def post(self, url, body, headers):
        validate_url(url)
        connector = aiohttp.TCPConnector(resolver=PublicResolver(), use_dns_cache=False,
                                         force_close=True, limit=1)
        async with aiohttp.ClientSession(connector=connector, trust_env=False,
                cookie_jar=aiohttp.DummyCookieJar(),
                timeout=aiohttp.ClientTimeout(total=10)) as session:
            async with session.post(url, data=body, headers=headers, allow_redirects=False) as response:
                # Never read/log an unbounded or attacker-controlled response body.
                content = await response.content.read(4097)
                if len(content) > 4096:
                    raise CallbackError("response_too_large")
                return response.status, content

    async def verify(self, url, secret, subscription_id):
        challenge = secrets.token_urlsafe(32)
        body = json_bytes({"type": "verification", "challenge": challenge})
        headers = signed_headers(secret, subscription_id, "msg_verification_" + secrets.token_hex(16), body)
        try:
            status, content = await self.post(url, body, headers)
            response = json.loads(content)
            echoed = response.get("challenge") if isinstance(response, dict) else None
            if not 200 <= status < 300 or not isinstance(echoed, str) or not hmac.compare_digest(
                    echoed.encode(), challenge.encode()):
                raise CallbackError("challenge_failed")
        except asyncio.TimeoutError as exc:
            raise CallbackError("timeout") from exc
        except (aiohttp.ClientError, ValueError, OSError) as exc:
            raise CallbackError("challenge_failed") from exc
